#!/usr/bin/env python3
"""
targets/common/packaging.py -- Shared packaging helpers across `obsd-ports`
target adapters (`emulate/emscripten`, `emulate/darwin`, `translate/darwin`).

Provides:
  - `resolve_staged_symlink`: symlink target resolution inside `stage/`
  - `discover_applet_paths`: `port.toml` `[[applets]]` + `discover_symlink_aliases_in`
  - `stage_usr_local_sysroot`: copies non-applet `/usr/local/**` files & symlinks,
    records `struct obsd_fr_disk` fakeroot metadata (`ports-owners.db` +
    `ports-owners.tsv`), and optionally emits `ports.svfs.gz`
  - `emit_port_packages`: builds deterministic `.tgz` packages (`+CONTENTS` +
    staged files) and `packages/index.tsv`
"""
from __future__ import annotations

import gzip
import hashlib
import io
import os
import pathlib
import re
import shutil
import stat
import struct
import tarfile
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple

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

MACHO_MAGICS = {
    b"\xfe\xed\xfa\xcf",
    b"\xcf\xfa\xed\xfe",
    b"\xfe\xed\xfa\xce",
    b"\xce\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe",
    b"\xbe\xba\xfe\xca",
}


def is_wasm_object(path: pathlib.Path) -> bool:
    if not path.is_file() or path.is_symlink():
        return False
    try:
        with path.open("rb") as fp:
            return fp.read(8) == b"\x00asm\x01\x00\x00\x00"
    except OSError:
        return False


def is_macho_file(path: pathlib.Path) -> bool:
    if not path.is_file() or path.is_symlink():
        return False
    try:
        with path.open("rb") as fp:
            hdr = fp.read(4)
        return len(hdr) == 4 and hdr in MACHO_MAGICS
    except OSError:
        return False


def resolve_staged_symlink(
    stage_dir: pathlib.Path,
    link_path: pathlib.Path,
    max_hops: int = 16,
) -> Optional[pathlib.Path]:
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


def resolve_applet_spec(
    stage_dir: pathlib.Path,
    rec: Dict[str, Any],
    app: Dict[str, Any],
    seen_syms: Set[str],
    die_fn: Callable[[str], Any],
) -> Tuple[str, pathlib.Path, List[str]]:
    sym = re.sub(r"[^A-Za-z0-9_]", "_", app["sym"])
    if sym in seen_syms:
        die_fn(f"duplicate applet symbol '{sym}' across port recipes")
    seen_syms.add(sym)

    paths = [p if p.startswith("/") else f"/{p}" for p in app.get("paths", [])]
    bin_rel = (app.get("binary") or (paths[0] if paths else "")).lstrip("/")
    if not bin_rel:
        die_fn(f"applet '{sym}' in {rec['port']} specifies no binary or paths")
    if not paths:
        paths = [f"/{bin_rel}"]

    bin_stage_entry = stage_dir / bin_rel
    bin_path = (
        resolve_staged_symlink(stage_dir, bin_stage_entry)
        if bin_stage_entry.is_symlink()
        else bin_stage_entry
    )
    if bin_path is None or not bin_path.is_file():
        die_fn(f"applet '{sym}' ({rec['port']}): staged binary missing at {stage_dir / bin_rel}")
    bin_resolved = bin_path.resolve()

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
    return sym, bin_resolved, paths


def build_fr_record(guest_path: str, uid: int, gid: int, full_mode: int, rdev: int = 0) -> bytes:
    path_b = guest_path.encode("utf-8")
    return FR_RECORD.pack(len(path_b), MASK_ALL, uid, gid, full_mode, rdev) + path_b


def stage_usr_local_sysroot(
    lane_dir: pathlib.Path,
    stage_dir: pathlib.Path,
    tsv_rows: Sequence[Tuple[str, str, str, str]],
    applet_guest_paths: Set[str],
    is_binary_object: Callable[[pathlib.Path], bool],
    emit_svfs: bool = False,
    record_applet_stubs_in_owners: bool = True,
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
            (sysroot_dir / rel_from_stage).mkdir(parents=True, exist_ok=True)

            for nm in sorted(filenames) + sorted(d for d in dirnames if (dp / d).is_symlink()):
                sp = dp / nm
                rel_p = sp.relative_to(stage_dir).as_posix()
                gp = "/" + rel_p
                if gp in applet_guest_paths:
                    continue
                if nm.endswith((".la", ".dylib")) or nm.endswith(".so") or ".so." in nm:
                    continue
                if gp.startswith(("/usr/local/bin/", "/usr/local/sbin/", "/usr/local/libexec/")) and is_binary_object(sp):
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

    tsv_digest = hashlib.sha256(
        "\n".join(f"{s}\t{g}\t{e}\t{o}" for s, g, e, o in tsv_rows).encode("utf-8")
    ).hexdigest()
    stub_bytes = STUB_TEXT_FMT.format(digest=tsv_digest).encode("utf-8")

    fr_chunks: List[bytes] = []
    owners_tsv_lines: List[str] = ["# guest_path\tuid\tgid\toctal_mode"]
    svfs_entries: List[Tuple[str, int, int, bytes]] = []
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
        owners_tsv_lines.append(f"{guest_path}\t0\t0\t{oct(full_mode)[2:]}")
        if emit_svfs:
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
                record_entry(gp, SVFS_TYPE_SYM, 0o777, os.readlink(sub_p).encode("utf-8") if emit_svfs else b"")

        for fn in filenames:
            fp = dp / fn
            gp = "/" + fp.relative_to(sysroot_dir).as_posix()
            if fp.is_symlink():
                record_entry(gp, SVFS_TYPE_SYM, 0o777, os.readlink(fp).encode("utf-8") if emit_svfs else b"")
            elif fp.is_file():
                st_mode = fp.stat().st_mode & 0o7777
                if gp.startswith(("/usr/local/bin/", "/usr/local/sbin/", "/usr/local/libexec/")):
                    perms = 0o755
                elif st_mode & 0o111:
                    perms = 0o755
                else:
                    perms = 0o644 if not gp.startswith("/usr/local/man/") else 0o444
                record_entry(gp, SVFS_TYPE_REG, perms, fp.read_bytes() if emit_svfs else b"")

    if record_applet_stubs_in_owners:
        for _sym, gp, _ent, _obj in tsv_rows:
            parts = gp.strip("/").split("/")
            for i in range(1, len(parts)):
                anc_gp = "/" + "/".join(parts[:i])
                record_entry(anc_gp, SVFS_TYPE_DIR, 0o755)
            record_entry(gp, SVFS_TYPE_REG, 0o555, stub_bytes if emit_svfs else b"")

    (lane_dir / "ports-owners.db").write_bytes(b"".join(fr_chunks))
    (lane_dir / "ports-owners.tsv").write_text("\n".join(owners_tsv_lines) + "\n", encoding="utf-8")

    if emit_svfs:
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

    return copied_files, len(seen_paths)


def emit_port_packages(
    lane_dir: pathlib.Path,
    stage_dir: pathlib.Path,
    records: Sequence[Dict[str, Any]],
) -> int:
    pkg_dir = lane_dir / "packages"
    if pkg_dir.exists():
        shutil.rmtree(pkg_dir)
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
                    contents_txt = (
                        f"@name {pkgname}\n"
                        f"@comment pkgpath={rec['port']} openbsd={rec['openbsd_version']}\n"
                        + "".join(f"{rel}\n" for rel in installed)
                    ).encode("utf-8")
                    ti_meta = tarfile.TarInfo("+CONTENTS")
                    ti_meta.size = len(contents_txt)
                    ti_meta.mode = 0o644
                    ti_meta.mtime = 0
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
