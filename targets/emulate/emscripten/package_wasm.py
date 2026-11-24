#!/usr/bin/env python3
"""
package_wasm.py -- `emulate/emscripten` WASM64 packaging adapter for `obsd-ports`.

Consumes staged port outputs under `build/openbsd/<ver>/emulate/emscripten/stage/`
and `built-ports.json`, producing:
  1. `applets/<sym>.o` + `applets/<sym>.meta.json` (localized WASM64 relocatable
     applet closures via `wasm_object_tool.py localize-applet`, automatically
     resolving `__main_argc_argv` / `main` / `obsd_tool_main` ->
     `obsd_applet_<sym>_main` while keeping base OpenBSD `libc`/`libssl`/`libz`/
     `libcurses` symbols undefined so they bind cleanly to the single guest
     `libobsdc-wasm-<ver>.a` instance).
  2. `ports-applets.tsv` (`<sym>\t<guest_path>\t<entry_sym>\tapplets/<sym>.o`).
  3. `sysroot/usr/local/...` (complete `/usr/local` overlay excluding raw WASM
     applet binaries at `ports-applets.tsv` paths while preserving shell helper
     scripts, headers, static `.a` libs, `.pc` files, share data, and manpages).
  4. `ports.svfs.gz` (SVFS v1 gzip-compressed bundle of `/usr/local/...` with
     applet stubs).
  5. `ports-owners.db` (binary `struct obsd_fr_disk` fakeroot metadata records)
     and `ports-owners.tsv`.
  6. `packages/<pkgname>.tgz` + `packages/index.tsv` (per-port `.tgz` packages).
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import pathlib
import re
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

SVFS_MAGIC = 0x53564653  # "SVFS" LE
SVFS_HDR_STRUCT = struct.Struct("<IHHI")
SVFS_ENT_STRUCT = struct.Struct("<BBHIIIHHI")
SVFS_TYPE_DIR = 1
SVFS_TYPE_REG = 2
SVFS_TYPE_SYM = 3

FR_RECORD = struct.Struct("<6I")
MASK_ALL = 7  # UID | GID | MODE

STUB_TEXT_FMT = """Sonvori BSD applet stub.

This file stands for an OpenBSD port program linked into the runtime image.
Executing its path inside the machine runs that program; the bytes here are
never interpreted.  table {digest}
"""


def die(msg: str) -> "NoReturn":
    sys.stderr.write(f"package_wasm: {msg}\n")
    raise SystemExit(1)


def is_wasm_object(path: pathlib.Path) -> bool:
    if not path.is_file() or path.is_symlink():
        return False
    try:
        with path.open("rb") as fp:
            return fp.read(8) == b"\x00asm\x01\x00\x00\x00"
    except OSError:
        return False


def _read_uleb(buf: bytes, pos: int) -> Tuple[int, int]:
    res = 0
    shift = 0
    while True:
        b = buf[pos]
        pos += 1
        res |= (b & 0x7F) << shift
        if (b & 0x80) == 0:
            return res, pos
        shift += 7


def _encode_uleb(val: int) -> bytes:
    out = bytearray()
    while True:
        b = val & 0x7F
        val >>= 7
        if val != 0:
            b |= 0x80
        out.append(b)
        if val == 0:
            return bytes(out)


def _encode_wasm_str(s: str) -> bytes:
    raw = s.encode("utf-8")
    return _encode_uleb(len(raw)) + raw


def rewrite_wasm_relro_segments(obj_path: pathlib.Path) -> int:
    """
    Promote ELF/WASM RELRO segment names (`.data.rel.ro` -> `.rodata.rel.ro` and
    `.data.rel.ro.*` -> `.rodata.rel.ro.*`) inside WASM `linking` v2 `WASM_SEGMENT_INFO`
    before `wasm_object_tool.py` runs, ensuring immutable vtables and const pointer
    tables stay in shared read-only `.rodata` instead of mutable `obsd_guest_data`.
    """
    data = obj_path.read_bytes()
    if len(data) < 8 or data[:8] != b"\x00asm\x01\x00\x00\x00":
        return 0

    out = bytearray(data[:8])
    pos = 8
    rewritten = 0

    while pos < len(data):
        sec_id = data[pos]
        sec_len, body_pos = _read_uleb(data, pos + 1)
        sec_end = body_pos + sec_len
        if sec_id == 0:
            nlen, npos = _read_uleb(data, body_pos)
            sec_name = data[npos : npos + nlen].decode("utf-8", "replace")
            if sec_name == "linking":
                ver, p = _read_uleb(data, npos + nlen)
                if ver == 2:
                    new_subsecs: List[Tuple[int, bytes]] = []
                    while p < sec_end:
                        stype = data[p]
                        slen, sp = _read_uleb(data, p + 1)
                        spayload = data[sp : sp + slen]
                        p = sp + slen
                        if stype == 5:  # WASM_SEGMENT_INFO
                            cnt, qp = _read_uleb(spayload, 0)
                            seg_buf = bytearray(_encode_uleb(cnt))
                            for _ in range(cnt):
                                sl2, qp = _read_uleb(spayload, qp)
                                nm = spayload[qp : qp + sl2].decode("utf-8")
                                qp += sl2
                                align, qp = _read_uleb(spayload, qp)
                                flags, qp = _read_uleb(spayload, qp)
                                if nm == ".data.rel.ro":
                                    nm = ".rodata.rel.ro"
                                    rewritten += 1
                                elif nm.startswith(".data.rel.ro."):
                                    nm = ".rodata.rel.ro." + nm[len(".data.rel.ro.") :]
                                    rewritten += 1
                                seg_buf += _encode_wasm_str(nm)
                                seg_buf += _encode_uleb(align)
                                seg_buf += _encode_uleb(flags)
                            spayload = bytes(seg_buf)
                        new_subsecs.append((stype, spayload))

                    if rewritten > 0:
                        linking_body = bytearray(_encode_wasm_str("linking") + _encode_uleb(ver))
                        for stype, spayload in new_subsecs:
                            linking_body.append(stype)
                            linking_body += _encode_uleb(len(spayload))
                            linking_body += spayload
                        out.append(0)
                        out += _encode_uleb(len(linking_body))
                        out += linking_body
                        pos = sec_end
                        continue
        out += data[pos:sec_end]
        pos = sec_end

    if rewritten > 0:
        st_mode = obj_path.stat().st_mode & 0o7777
        tmp_p = obj_path.with_suffix(obj_path.suffix + f".{os.getpid()}.relro.tmp")
        tmp_p.write_bytes(bytes(out))
        tmp_p.chmod(st_mode)
        tmp_p.replace(obj_path)
    return rewritten


def resolve_staged_symlink(stage_dir: pathlib.Path, link_path: pathlib.Path, max_hops: int = 16) -> Optional[pathlib.Path]:
    """Resolve a staged path or symlink (supporting both relative and guest-absolute targets)."""
    cur = link_path
    stage_resolved = stage_dir.resolve()
    for _ in range(max_hops):
        if not cur.is_symlink():
            return cur.resolve() if cur.exists() else None
        raw_target = os.readlink(cur)
        if os.path.isabs(raw_target):
            raw_p = pathlib.Path(raw_target)
            try:
                raw_p.relative_to(stage_resolved)
                cur = raw_p
            except ValueError:
                cur = stage_dir / raw_target.lstrip("/")
        else:
            cur = cur.parent / raw_target
    return cur.resolve() if (cur.exists() and not cur.is_symlink()) else None


def detect_wasm_main_symbol(llvm_nm: pathlib.Path, obj_path: pathlib.Path, explicit_entry: str) -> str:
    if explicit_entry and explicit_entry != "auto":
        return explicit_entry
    out = subprocess.check_output(
        [str(llvm_nm), "--defined-only", "-g", str(obj_path)],
        text=True,
        stderr=subprocess.DEVNULL,
    )
    defs: Set[str] = set()
    for ln in out.splitlines():
        ps = ln.split()
        if len(ps) >= 3 and ps[1] in ("T", "W"):
            defs.add(ps[2])
        elif len(ps) == 2 and ps[0] in ("T", "W"):
            defs.add(ps[1])

    for cand in ("obsd_tool_main", "__main_argc_argv", "main", "__original_main"):
        if cand in defs:
            return cand
    die(f"{obj_path}: no main entrypoint found in WASM global function symbols (found: {sorted(defs)[:15]})")


def localize_port_applets(
    obsd_root: pathlib.Path,
    openbsd_version: str,
    lane_dir: pathlib.Path,
    stage_dir: pathlib.Path,
    records: Sequence[Dict[str, Any]],
) -> Tuple[List[Tuple[str, str, str, str]], Set[str]]:
    emulate_tools = obsd_root / "tools/build/personalities/openbsd/backends/emulate"
    if str(emulate_tools) not in sys.path:
        sys.path.insert(0, str(emulate_tools))
    import build_wasm_guest as bwg  # type: ignore

    wasm_obj_tool = emulate_tools / "wasm_object_tool.py"
    llvm_bin = obsd_root / "deps/emsdk/upstream/bin"
    wasm_ld = llvm_bin / "wasm-ld"
    llvm_nm = llvm_bin / "llvm-nm"

    applets_dir = lane_dir / "applets"
    if applets_dir.exists():
        shutil.rmtree(applets_dir)
    applets_dir.mkdir(parents=True, exist_ok=True)

    tsv_rows: List[Tuple[str, str, str, str]] = []
    applet_guest_paths: Set[str] = set()
    seen_syms: Set[str] = set()

    for rec in records:
        for app in rec.get("applets", []):
            sym = re.sub(r"[^A-Za-z0-9_]", "_", app["sym"])
            if sym in seen_syms:
                die(f"duplicate applet symbol '{sym}' across port recipes")
            seen_syms.add(sym)

            paths = [p if p.startswith("/") else f"/{p}" for p in app.get("paths", [])]
            bin_rel = (app.get("binary") or (paths[0] if paths else "")).lstrip("/")
            if not bin_rel:
                die(f"applet '{sym}' in {rec['port']} specifies no binary or paths")
            if not paths:
                paths = [f"/{bin_rel}"]

            bin_stage_entry = stage_dir / bin_rel
            bin_path = resolve_staged_symlink(stage_dir, bin_stage_entry) if bin_stage_entry.is_symlink() else bin_stage_entry
            if bin_path is None or not bin_path.is_file():
                die(f"applet '{sym}' ({rec['port']}): staged binary missing at {stage_dir / bin_rel}")
            bin_resolved = bin_path.resolve()
            if not is_wasm_object(bin_resolved):
                die(f"applet '{sym}' ({rec['port']}): {bin_resolved} is not a WASM64 relocatable binary")
            bin_path = bin_resolved

            # Optional automatic multi-call symlink alias discovery (e.g. coreutils `--enable-single-binary=symlinks`)
            for alias_dir in app.get("discover_symlink_aliases_in", []):
                scan_dir = stage_dir / str(alias_dir).lstrip("/")
                if not scan_dir.is_dir():
                    continue
                for ent in sorted(scan_dir.iterdir(), key=lambda p: p.name):
                    if not ent.is_symlink():
                        continue
                    target_resolved = resolve_staged_symlink(stage_dir, ent)
                    if target_resolved is not None and target_resolved == bin_resolved:
                        alias_gp = "/" + ent.relative_to(stage_dir).as_posix()
                        if alias_gp not in paths:
                            paths.append(alias_gp)

            paths = list(dict.fromkeys(paths))

            # Normalize through `wasm-ld -m wasm64 -r` if extra objects/archives are requested,
            # or copy directly when `obsd-cc` already emitted a `wasm-ld -m wasm64 -r` object.
            raw_obj = applets_dir / f"{sym}.raw.o"
            extra_inputs = [str(stage_dir / x.lstrip("/")) for x in app.get("extra_libs", [])]
            if extra_inputs:
                subprocess.run(
                    [str(wasm_ld), "-m", "wasm64", "--fatal-warnings", "-r", str(bin_path), *extra_inputs, "-o", str(raw_obj)],
                    check=True,
                )
            else:
                shutil.copy2(bin_path, raw_obj)

            rewrite_wasm_relro_segments(raw_obj)
            src_entry = detect_wasm_main_symbol(llvm_nm, raw_obj, app.get("entry", "auto"))
            loc_obj = applets_dir / f"{sym}.o"
            subprocess.run(
                [
                    sys.executable,
                    "-I",
                    str(wasm_obj_tool),
                    "localize-applet",
                    "--applet-sym",
                    sym,
                    "--entry-symbol",
                    src_entry,
                    "-i",
                    str(raw_obj),
                    "-o",
                    str(loc_obj),
                ],
                check=True,
            )
            raw_obj.unlink(missing_ok=True)

            target_entry = f"obsd_applet_{sym}_main"
            malloc_sym = f"obsd_applet_{sym}_malloc_options"
            arity, ret_void, has_malloc = bwg.inspect_wasm_applet_signature(loc_obj, target_entry, malloc_sym)
            meta = {
                "sym": sym,
                "port": rec["port"],
                "pkgname": rec["pkgname"],
                "entry_symbol": target_entry,
                "source_entry": src_entry,
                "arity": arity,
                "ret_void": ret_void,
                "has_malloc": has_malloc,
                "paths": paths,
            }
            (applets_dir / f"{sym}.meta.json").write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")

            rel_obj = f"applets/{sym}.o"
            for gp in paths:
                applet_guest_paths.add(gp)
                tsv_rows.append((sym, gp, target_entry, rel_obj))

    tsv_rows.sort(key=lambda r: (r[1], r[0]))
    tsv_path = lane_dir / "ports-applets.tsv"
    lines = ["# sym\tguest_path\tentry_sym\tobj_path"] + [
        f"{sym}\t{gp}\t{ent}\t{obj}" for sym, gp, ent, obj in tsv_rows
    ]
    tsv_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return tsv_rows, applet_guest_paths


def build_fr_record(guest_path: str, uid: int, gid: int, full_mode: int, rdev: int = 0) -> bytes:
    path_b = guest_path.encode("utf-8")
    return FR_RECORD.pack(len(path_b), MASK_ALL, uid, gid, full_mode, rdev) + path_b


def stage_sysroot_and_svfs(
    lane_dir: pathlib.Path,
    stage_dir: pathlib.Path,
    tsv_rows: Sequence[Tuple[str, str, str, str]],
    applet_guest_paths: Set[str],
) -> Tuple[int, int]:
    sysroot_dir = lane_dir / "sysroot"
    if sysroot_dir.exists():
        shutil.rmtree(sysroot_dir)
    (sysroot_dir / "usr/local").mkdir(parents=True, exist_ok=True)

    src_usr_local = stage_dir / "usr/local"
    copied_files = 0
    if src_usr_local.is_dir():
        for dirpath, dirnames, filenames in os.walk(src_usr_local, followlinks=False):
            dp = pathlib.Path(dirpath)
            rel_from_stage = dp.relative_to(stage_dir).as_posix()
            guest_dir = "/" + rel_from_stage
            (sysroot_dir / rel_from_stage).mkdir(parents=True, exist_ok=True)

            for nm in sorted(filenames) + sorted(d for d in dirnames if (dp / d).is_symlink()):
                sp = dp / nm
                rel_p = sp.relative_to(stage_dir).as_posix()
                gp = "/" + rel_p
                # Omit raw WASM binaries (or symlinks shadowed by ports-applets.tsv multi-call rows)
                if gp in applet_guest_paths:
                    continue
                # Omit libtool `.la` files and `.so*` shared objects unneeded in static WASM64 sysroot
                if nm.endswith(".la") or nm.endswith(".so") or ".so." in nm:
                    continue
                # Omit any un-registered raw WASM executable in bin/sbin/libexec unless it's a script/data file
                if gp.startswith(("/usr/local/bin/", "/usr/local/sbin/", "/usr/local/libexec/")) and is_wasm_object(sp):
                    continue

                dst_p = sysroot_dir / rel_p
                dst_p.parent.mkdir(parents=True, exist_ok=True)
                if sp.is_symlink():
                    link_target = os.readlink(sp)
                    if dst_p.exists() or dst_p.is_symlink():
                        dst_p.unlink()
                    os.symlink(link_target, dst_p)
                elif sp.is_file():
                    shutil.copy2(sp, dst_p)
                    copied_files += 1

    # Build owners metadata (`ports-owners.db` + `ports-owners.tsv`) and `ports.svfs.gz`
    tsv_digest = hashlib.sha256(
        "\n".join(f"{s}\t{g}\t{e}\t{o}" for s, g, e, o in tsv_rows).encode("utf-8")
    ).hexdigest()
    stub_bytes = STUB_TEXT_FMT.format(digest=tsv_digest).encode("utf-8")

    fr_chunks: List[bytes] = []
    owners_tsv_lines: List[str] = ["# guest_path\tuid\tgid\toctal_mode"]

    svfs_entries: List[Tuple[str, int, int, bytes]] = []  # (rel_no_slash, etype, perms, payload)
    seen_paths: Set[str] = set()

    def record_entry(guest_path: str, etype: int, perms: int, payload: bytes = b"") -> None:
        if guest_path in seen_paths:
            return
        seen_paths.add(guest_path)
        if etype == SVFS_TYPE_DIR:
            full_mode = stat.S_IFDIR | perms
        elif etype == SVFS_TYPE_SYM:
            full_mode = stat.S_IFLNK | 0o777
        else:
            full_mode = stat.S_IFREG | perms
        fr_chunks.append(build_fr_record(guest_path, 0, 0, full_mode, 0))
        owners_tsv_lines.append(f"{guest_path}\t0\t0\t{ oct(full_mode)[2:] }")
        svfs_entries.append((guest_path.lstrip("/"), etype, perms, payload))

    record_entry("/usr", SVFS_TYPE_DIR, 0o755)
    record_entry("/usr/local", SVFS_TYPE_DIR, 0o755)

    for dirpath, dirnames, filenames in os.walk(sysroot_dir / "usr/local", followlinks=False):
        dirnames.sort()
        filenames.sort()
        dp = pathlib.Path(dirpath)
        gp_dir = "/" + dp.relative_to(sysroot_dir).as_posix()
        record_entry(gp_dir, SVFS_TYPE_DIR, 0o755)

        for d in dirnames:
            sub_p = dp / d
            gp = "/" + sub_p.relative_to(sysroot_dir).as_posix()
            if sub_p.is_symlink():
                record_entry(gp, SVFS_TYPE_SYM, 0o777, os.readlink(sub_p).encode("utf-8"))

        for fn in filenames:
            fp = dp / fn
            gp = "/" + fp.relative_to(sysroot_dir).as_posix()
            if fp.is_symlink():
                record_entry(gp, SVFS_TYPE_SYM, 0o777, os.readlink(fp).encode("utf-8"))
            elif fp.is_file():
                st_mode = fp.stat().st_mode & 0o7777
                if gp.startswith(("/usr/local/bin/", "/usr/local/sbin/", "/usr/local/libexec/")):
                    perms = 0o755
                elif st_mode & 0o111:
                    perms = 0o755
                else:
                    perms = 0o644 if not gp.startswith("/usr/local/man/") else 0o444
                record_entry(gp, SVFS_TYPE_REG, perms, fp.read_bytes())

    # Record parent directories & 0555 applet stubs for every applet guest_path
    for _sym, gp, _ent, _obj in tsv_rows:
        parts = gp.strip("/").split("/")
        for i in range(1, len(parts)):
            anc_gp = "/" + "/".join(parts[:i])
            record_entry(anc_gp, SVFS_TYPE_DIR, 0o755)
        record_entry(gp, SVFS_TYPE_REG, 0o555, stub_bytes)

    (lane_dir / "ports-owners.db").write_bytes(b"".join(fr_chunks))
    (lane_dir / "ports-owners.tsv").write_text("\n".join(owners_tsv_lines) + "\n", encoding="utf-8")

    # Serialize SVFS v1 binary bundle -> ports.svfs.gz
    hdr_size = SVFS_HDR_STRUCT.size
    table_size = len(svfs_entries) * SVFS_ENT_STRUCT.size
    cur_off = hdr_size + table_size
    ent_blobs: List[bytes] = []
    data_blobs: List[bytes] = []

    for rel_path, etype, perms, payload in svfs_entries:
        p_bytes = rel_path.encode("utf-8")
        p_off = cur_off
        cur_off += len(p_bytes)
        d_off = cur_off
        cur_off += len(payload)
        ent_blobs.append(
            SVFS_ENT_STRUCT.pack(
                etype,
                0,
                perms,
                p_off,
                len(p_bytes),
                d_off,
                0,
                0,
                len(payload),
            )
        )
        data_blobs.append(p_bytes + payload)

    svfs_raw = SVFS_HDR_STRUCT.pack(SVFS_MAGIC, 1, 0, len(svfs_entries)) + b"".join(ent_blobs) + b"".join(data_blobs)
    svfs_gz_path = lane_dir / "ports.svfs.gz"
    with svfs_gz_path.open("wb") as raw_fp:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw_fp, compresslevel=6, mtime=0) as gz_fp:
            gz_fp.write(svfs_raw)

    return copied_files, len(svfs_entries)


def emit_port_packages(
    lane_dir: pathlib.Path,
    stage_dir: pathlib.Path,
    records: Sequence[Dict[str, Any]],
) -> int:
    pkg_dir = lane_dir / "packages"
    pkg_dir.mkdir(parents=True, exist_ok=True)
    idx_rows = ["# port\tpkgname\tarchive\tsha256\tsize"]
    built_pkgs = 0

    for rec in records:
        pkgname = rec["pkgname"]
        tgz_path = pkg_dir / f"{pkgname}.tgz"
        installed = rec.get("installed_files", [])
        with tgz_path.open("wb") as raw_fp:
            with gzip.GzipFile(filename="", mode="wb", fileobj=raw_fp, compresslevel=6, mtime=0) as gz_fp:
                with tarfile.open(mode="w", fileobj=gz_fp) as tf:
                    # Include +CONTENTS metadata summary
                    contents_txt = (
                        f"@name {pkgname}\n"
                        f"@comment pkgpath={rec['port']} openbsd={rec['openbsd_version']}\n"
                        + "".join(f"{rel}\n" for rel in installed)
                    ).encode("utf-8")
                    ti_meta = tarfile.TarInfo("+CONTENTS")
                    ti_meta.size = len(contents_txt)
                    ti_meta.mode = 0o644
                    ti_meta.mtime = 0
                    import io

                    tf.addfile(ti_meta, io.BytesIO(contents_txt))
                    for rel in installed:
                        fp = stage_dir / rel
                        if not fp.exists() and not fp.is_symlink():
                            continue
                        if fp.is_dir() and not fp.is_symlink():
                            continue
                        tf.add(str(fp), arcname=rel, recursive=False)
        digest = hashlib.sha256(tgz_path.read_bytes()).hexdigest()
        sz = tgz_path.stat().st_size
        idx_rows.append(f"{rec['port']}\t{pkgname}\tpackages/{pkgname}.tgz\t{digest}\t{sz}")
        built_pkgs += 1

    (pkg_dir / "index.tsv").write_text("\n".join(idx_rows) + "\n", encoding="utf-8")
    return built_pkgs


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--openbsd-version", required=True)
    ap.add_argument("--backend", default="emulate")
    ap.add_argument("--pal", default="emscripten")
    ap.add_argument("--libobsdcompat-root", required=True)
    ap.add_argument("--lane-dir", required=True)
    ap.add_argument("--manifest", required=True)
    args = ap.parse_args()

    obsd_root = pathlib.Path(args.libobsdcompat_root).resolve()
    lane_dir = pathlib.Path(args.lane_dir).resolve()
    stage_dir = lane_dir / "stage"
    stage_dir.mkdir(parents=True, exist_ok=True)
    records = json.loads(pathlib.Path(args.manifest).read_text(encoding="utf-8"))

    tsv_rows, applet_guest_paths = localize_port_applets(
        obsd_root=obsd_root,
        openbsd_version=args.openbsd_version,
        lane_dir=lane_dir,
        stage_dir=stage_dir,
        records=records,
    )
    copied_files, svfs_count = stage_sysroot_and_svfs(
        lane_dir=lane_dir,
        stage_dir=stage_dir,
        tsv_rows=tsv_rows,
        applet_guest_paths=applet_guest_paths,
    )
    pkg_count = emit_port_packages(lane_dir=lane_dir, stage_dir=stage_dir, records=records)

    print(
        f"[package/{args.openbsd_version}] packaged {pkg_count} port(s) -> "
        f"{len(tsv_rows)} applet path(s), {copied_files} /usr/local file(s), {svfs_count} SVFS entries in {lane_dir}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
