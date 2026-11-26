#!/usr/bin/env python3
"""
package_wasm.py -- `emulate/emscripten` WASM64 packaging adapter for `obsd-ports`.

Consumes staged port outputs under `build/openbsd/<ver>/emulate/emscripten/stage/`
and `built-ports.json`, producing:
  1. `applets/<sym>.o` + `applets/<sym>.meta.json` (localized WASM64 relocatable
     applet closures via `wasm_object_tool.py localize-applet`).
  2. `ports-applets.tsv` (`<sym>\t<guest_path>\t<entry_sym>\tapplets/<sym>.o`).
  3. `sysroot/usr/local/...` (complete `/usr/local` overlay excluding raw WASM
     applet binaries at `ports-applets.tsv` paths).
  4. `ports.svfs.gz` (SVFS v1 gzip-compressed bundle of `/usr/local/...` with
     applet stubs).
  5. `ports-owners.db` and `ports-owners.tsv`.
  6. `packages/<pkgname>.tgz` + `packages/index.tsv`.
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

TARGETS_ROOT = pathlib.Path(__file__).resolve().parents[2]
REPO_ROOT = TARGETS_ROOT.parent
if str(TARGETS_ROOT / "common") not in sys.path:
    sys.path.insert(0, str(TARGETS_ROOT / "common"))
if str(REPO_ROOT / "sdk/lib") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "sdk/lib"))

import packaging as common_pkg  # noqa: E402
from obsd_toolchain import SHARED_PORT_LIBS  # noqa: E402

is_wasm_object = common_pkg.is_wasm_object
resolve_staged_symlink = common_pkg.resolve_staged_symlink
build_fr_record = common_pkg.build_fr_record
emit_port_packages = common_pkg.emit_port_packages


def die(msg: str) -> "NoReturn":
    sys.stderr.write(f"package_wasm: {msg}\n")
    raise SystemExit(1)


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


def _rewrite_wasm_relro_bytes(data: bytes) -> Tuple[bytes, int]:
    if len(data) < 8 or data[:8] != b"\x00asm\x01\x00\x00\x00":
        return data, 0

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

    return (bytes(out), rewritten) if rewritten > 0 else (data, 0)


def rewrite_wasm_relro_segments(obj_path: pathlib.Path) -> int:
    """
    Promote ELF/WASM RELRO segment names (`.data.rel.ro` -> `.rodata.rel.ro` and
    `.data.rel.ro.*` -> `.rodata.rel.ro.*`) inside WASM `linking` v2 `WASM_SEGMENT_INFO`
    before `wasm_object_tool.py` runs, ensuring immutable vtables and const pointer
    tables stay in shared read-only `.rodata` instead of mutable `obsd_guest_data`.
    """
    out_bytes, rewritten = _rewrite_wasm_relro_bytes(obj_path.read_bytes())
    if rewritten > 0:
        st_mode = obj_path.stat().st_mode & 0o7777
        tmp_p = obj_path.with_suffix(obj_path.suffix + f".{os.getpid()}.relro.tmp")
        tmp_p.write_bytes(out_bytes)
        tmp_p.chmod(st_mode)
        tmp_p.replace(obj_path)
    return rewritten


def _unpack_ar_wasm_objects(ar_path: pathlib.Path) -> List[Tuple[str, bytes]]:
    data = ar_path.read_bytes()
    if not data.startswith(b"!<arch>\n"):
        return []
    pos = 8
    n = len(data)
    out: List[Tuple[str, bytes]] = []
    while pos + 60 <= n:
        if pos % 2 == 1:
            pos += 1
            if pos + 60 > n:
                break
        hdr = data[pos : pos + 60]
        if hdr[58:60] != b"`\n":
            break
        name_raw = hdr[0:16].decode("latin1")
        try:
            size = int(hdr[48:58].decode("ascii").strip())
        except ValueError:
            break
        pstart = pos + 60
        pend = pstart + size
        pos = pend
        if pend > n or name_raw.strip() in ("/", "//", "__.SYMDEF", "__.SYMDEF SORTED"):
            continue
        if name_raw.startswith("#1/"):
            ext_len = int(name_raw[3:].strip())
            mname = data[pstart : pstart + ext_len].rstrip(b"\x00 ").decode("latin1", "replace")
            mbytes = data[pstart + ext_len : pend]
        else:
            mname = name_raw.rstrip(" /")
            mbytes = data[pstart:pend]
        if len(mbytes) >= 8 and mbytes[:8] == b"\x00asm\x01\x00\x00\x00":
            out.append((mname, mbytes))
    return out


def assemble_shared_ports_archive(
    obsd_root: pathlib.Path,
    openbsd_version: str,
    lane_dir: pathlib.Path,
    stage_dir: pathlib.Path,
) -> Optional[pathlib.Path]:
    """
    Pack shared multi-applet static port libraries from `stage/usr/local/lib/` into
    `libobsdports-shared-wasm-<ver>.a` + `ports-shared-libs.json`, promoting RELRO
    segments to `.rodata`, verifying 0 TLS segments/relocations, and wrapping any
    `WASM_INIT_FUNCS` static constructors into idempotent `obsd_ports_shared_run_ctors()`.
    """
    emulate_tools = obsd_root / "tools/build/personalities/openbsd/backends/emulate"
    if str(emulate_tools) not in sys.path:
        sys.path.insert(0, str(emulate_tools))
    import wasm_object_tool as wot  # type: ignore

    out_ar = lane_dir / f"libobsdports-shared-wasm-{openbsd_version}.a"
    libs_json = lane_dir / "ports-shared-libs.json"
    ctors_json = lane_dir / "ports-shared-ctors.json"
    stage_lib_dir = stage_dir / "usr/local/lib"

    archives: List[Tuple[str, pathlib.Path]] = []
    present_names: Set[str] = set()
    seen_inodes: Set[Tuple[int, int]] = set()
    if stage_lib_dir.is_dir():
        for stem in sorted(SHARED_PORT_LIBS):
            cand = stage_lib_dir / f"lib{stem}.a"
            if not cand.is_file():
                continue
            present_names.add(stem)
            rp = cand.resolve()
            st = rp.stat()
            if (st.st_dev, st.st_ino) in seen_inodes:
                continue
            seen_inodes.add((st.st_dev, st.st_ino))
            archives.append((stem, rp))

    if not archives:
        out_ar.unlink(missing_ok=True)
        libs_json.unlink(missing_ok=True)
        ctors_json.unlink(missing_ok=True)
        return None

    emcc = obsd_root / "deps/emsdk/upstream/emscripten/emcc"
    emar = obsd_root / "deps/emsdk/upstream/emscripten/emar"

    with tempfile.TemporaryDirectory(prefix=f"obsd-ports-shared-{openbsd_version}-") as td:
        pack_dir = pathlib.Path(td)
        all_objs: List[pathlib.Path] = []
        ctor_syms: List[str] = []
        idx = 0

        for tag, ar_p in archives:
            safe_tag = re.sub(r"[^A-Za-z0-9_]+", "_", tag)
            for mname, mbytes in _unpack_ar_wasm_objects(ar_p):
                raw_b, _ = _rewrite_wasm_relro_bytes(mbytes)
                # Audit 0 TLS segments/symbols/relocations and check WASM_INIT_FUNCS
                has_inits = False
                q = 8
                while q < len(raw_b):
                    sid = raw_b[q]
                    slen, bp = wot.read_uleb(raw_b, q + 1)
                    se = bp + slen
                    if sid == 0:
                        nl, np = wot.read_uleb(raw_b, bp)
                        cname = raw_b[np : np + nl].decode("utf-8", "replace")
                        pl = raw_b[np + nl : se]
                        if cname == "linking":
                            ver, lp = wot.read_uleb(pl, 0)
                            if ver == 2:
                                while lp < len(pl):
                                    st_id = pl[lp]
                                    sslen, sp = wot.read_uleb(pl, lp + 1)
                                    sub = pl[sp : sp + sslen]
                                    if st_id == wot.WASM_SEGMENT_INFO:
                                        for seg in wot.parse_segments(sub):
                                            if seg["name"].startswith((".tdata", ".tbss")) or (seg["flags"] & 0x2):
                                                die(f"TLS segment {seg['name']} in {ar_p.name}({mname})")
                                    elif st_id == wot.WASM_SYMBOL_TABLE:
                                        for sym in wot.parse_symbols(sub):
                                            if sym["flags"] & wot.WASM_SYM_TLS:
                                                die(f"TLS symbol {sym.get('name')} in {ar_p.name}({mname})")
                                    elif st_id == wot.WASM_INIT_FUNCS and sslen > 0:
                                        ic, _ = wot.read_uleb(sub, 0)
                                        if ic > 0:
                                            has_inits = True
                                    lp = sp + sslen
                        elif cname in ("reloc.CODE", "reloc.DATA"):
                            _, rels = wot.parse_relocs(pl)
                            for rt, _, _, _ in rels:
                                if rt in (wot.R_WASM_MEMORY_ADDR_TLS_SLEB, wot.R_WASM_MEMORY_ADDR_TLS_SLEB64):
                                    die(f"TLS relocation {rt} in {ar_p.name}({mname})")
                    q = se

                if has_inits:
                    local_ctors: List[str] = []

                    def _strip_inits(subsecs: List[Tuple[int, bytes]]) -> List[Tuple[int, bytes]]:
                        syms = None
                        inits: List[Tuple[int, int]] = []
                        for stype, payload in subsecs:
                            if stype == wot.WASM_SYMBOL_TABLE:
                                syms = wot.parse_symbols(payload)
                            elif stype == wot.WASM_INIT_FUNCS:
                                cnt, ip = wot.read_uleb(payload, 0)
                                for _ in range(cnt):
                                    prio, ip = wot.read_uleb(payload, ip)
                                    sidx, ip = wot.read_uleb(payload, ip)
                                    inits.append((prio, sidx))
                        if not syms or not inits:
                            return subsecs
                        for _, (_prio, sidx) in sorted(enumerate(inits), key=lambda x: (x[1][0], x[0])):
                            cname = f"__obsd_ports_lib_ctor_{len(ctor_syms) + len(local_ctors)}"
                            wot.make_exported_default(syms[sidx], cname)
                            local_ctors.append(cname)
                        out_s: List[Tuple[int, bytes]] = []
                        for stype, payload in subsecs:
                            if stype == wot.WASM_INIT_FUNCS:
                                continue
                            if stype == wot.WASM_SYMBOL_TABLE:
                                out_s.append((stype, wot.serialize_symbols(syms)))
                            else:
                                out_s.append((stype, payload))
                        return out_s

                    raw_b = wot.rewrite_wasm_object(raw_b, _strip_inits)
                    ctor_syms.extend(local_ctors)

                safe_m = re.sub(r"[^A-Za-z0-9_.-]+", "_", os.path.basename(mname) or "obj.o")
                if not safe_m.endswith(".o"):
                    safe_m += ".o"
                dst = pack_dir / f"{safe_tag}_{idx:05d}_{safe_m}"
                dst.write_bytes(raw_b)
                all_objs.append(dst)
                idx += 1

        init_c = pack_dir / "obsd_ports_shared_init.c"
        init_o = pack_dir / "obsd_ports_shared_init.o"
        init_lines = ["/* Auto-generated idempotent constructor runner for libobsdports-shared-wasm */"]
        for cs in ctor_syms:
            init_lines.append(f"extern void {cs}(void);")
        init_lines.extend(
            [
                "static int __obsd_ports_shared_ctors_ran = 0;",
                "void obsd_ports_shared_run_ctors(void) {",
                "\tif (__obsd_ports_shared_ctors_ran) return;",
                "\t__obsd_ports_shared_ctors_ran = 1;",
            ]
        )
        for cs in ctor_syms:
            init_lines.append(f"\t{cs}();")
        init_lines.append("}")
        init_c.write_text("\n".join(init_lines) + "\n", encoding="utf-8")
        subprocess.run(
            [
                str(emcc),
                "-c",
                "-m64",
                "-pthread",
                "-O2",
                "-fno-common",
                "-fno-builtin",
                "-femulated-tls",
                "-fno-stack-protector",
                "-sSUPPORT_LONGJMP=0",
                "-fsanitize-coverage=trace-pc,no-prune",
                "-nostdinc",
                str(init_c),
                "-o",
                str(init_o),
            ],
            check=True,
        )
        all_objs.append(init_o)

        tmp_ar = out_ar.with_suffix(f".{os.getpid()}.a.tmp")
        tmp_ar.unlink(missing_ok=True)
        for start in range(0, len(all_objs), 250):
            batch = [str(p) for p in all_objs[start : start + 250]]
            subprocess.run([str(emar), "rcs", str(tmp_ar), *batch], check=True)
        tmp_ar.replace(out_ar)

    libs_json.write_text(json.dumps(sorted(present_names), indent=2) + "\n", encoding="utf-8")
    ctors_json.write_text(json.dumps(ctor_syms, indent=2) + "\n", encoding="utf-8")
    sz_mb = out_ar.stat().st_size / (1024 * 1024)
    print(
        f"[package/{openbsd_version}] assembled {out_ar.name}: {sz_mb:.2f} MiB "
        f"({len(archives)} shared archives, {len(all_objs)} objects, {len(ctor_syms)} wrapped ctors)"
    )
    return out_ar


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
            sym, bin_path, paths = common_pkg.resolve_applet_spec(stage_dir, rec, app, seen_syms, die)
            if not is_wasm_object(bin_path):
                die(f"applet '{sym}' ({rec['port']}): {bin_path} is not a WASM64 relocatable binary")

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


def stage_sysroot_and_svfs(
    lane_dir: pathlib.Path,
    stage_dir: pathlib.Path,
    tsv_rows: Sequence[Tuple[str, str, str, str]],
    applet_guest_paths: Set[str],
) -> Tuple[int, int]:
    return common_pkg.stage_usr_local_sysroot(
        lane_dir=lane_dir,
        stage_dir=stage_dir,
        tsv_rows=tsv_rows,
        applet_guest_paths=applet_guest_paths,
        is_binary_object=is_wasm_object,
        emit_svfs=True,
        record_applet_stubs_in_owners=True,
    )


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--openbsd-version", required=True)
    ap.add_argument("--backend", default="emulate")
    ap.add_argument("--pal", default="emscripten")
    ap.add_argument("--sdk", default="")
    ap.add_argument("--libobsdcompat-root", required=True)
    ap.add_argument("--lane-dir", required=True)
    ap.add_argument("--manifest", required=True)
    args = ap.parse_args()

    obsd_root = pathlib.Path(args.libobsdcompat_root).resolve()
    lane_dir = pathlib.Path(args.lane_dir).resolve()
    stage_dir = lane_dir / "stage"
    stage_dir.mkdir(parents=True, exist_ok=True)
    records = json.loads(pathlib.Path(args.manifest).read_text(encoding="utf-8"))

    assemble_shared_ports_archive(
        obsd_root=obsd_root,
        openbsd_version=args.openbsd_version,
        lane_dir=lane_dir,
        stage_dir=stage_dir,
    )
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
