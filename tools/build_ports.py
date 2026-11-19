#!/usr/bin/env python3
"""
build_ports.py -- Multi-axis OpenBSD Port Builder & Catalog Driver for `obsd-ports`.

Commands:
  - `list-catalog`: Search the full ~10,500+ OpenBSD release ports catalog
    (`config/versions/<ver>-catalog.tsv`).
  - `list`: List active port recipes under `ports/**`, topological build order,
    vendor distinfo status, and build/applet status for the selected
    `(OPENBSD_VERSION, COMPAT_BACKEND, COMPAT_PAL)` lane.
  - `fetch`: Parse `vendor/openbsd/versions/<ver>/ports/<port>/distinfo`
    (supporting OpenBSD's base64 SHA256 and hex SHA256 + SIZE), resolve upstream
    `SITES` / `GH_*` / `network.conf` + OpenBSD distfiles mirrors, download into
    `.cache/distfiles/`, and verify exact SHA256 & byte size.
  - `build`: Extract distfiles into `build/openbsd/<ver>/<backend>/<pal>/work/<port>/`,
    apply unmodified `vendor/.../patches/patch-*` (plus optional recipe
    `ports/<port>/patches/patch-*`), cross-compile in topological dependency
    order using `sdk/bin/obsd-*`, and stage into `stage/usr/local/...`.
  - `package`: Invoke the target adapter (`targets/<backend>/<pal>/package_*.py`)
    to produce localized WASM64 applet closures (`applets/<sym>.o`),
    `ports-applets.tsv`, `sysroot/usr/local/...`, `ports.svfs.gz`,
    `ports-owners.db`, and per-port `packages/<pkgname>.tgz`.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import lzma
import os
import pathlib
import platform
import re
import shlex
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import urllib.request
import zipfile
import zlib
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]

DISTINFO_SHA256_RE = re.compile(r"^SHA256\s*\((.+)\)\s*=\s*(\S+)\s*$")
DISTINFO_SIZE_RE = re.compile(r"^SIZE\s*\((.+)\)\s*=\s*(\d+)\s*$")
VAR_ASSIGN_RE = re.compile(r"^([A-Za-z0-9_.+-]+?)\s*([+?:!]?=)\s*(.*)$")
SIMPLE_VAR_RE = re.compile(
    r"\$\{([A-Za-z0-9_.+-]+)(?::=([^}]*))?(?::([RL]))?\}|\$\(([A-Za-z0-9_.+-]+)\)|\$([A-Za-z0-9_])"
)


def die(msg: str, code: int = 1) -> "NoReturn":
    sys.stderr.write(f"build_ports: {msg}\n")
    raise SystemExit(code)


def sha256_file(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fp:
        while True:
            chunk = fp.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def decode_openbsd_sha256(digest_str: str) -> str:
    """Decode OpenBSD base64 SHA256 (or 64-char hex SHA256) to lowercase 64-char hex."""
    s = digest_str.strip()
    if len(s) == 64 and all(c in "0123456789abcdefABCDEF" for c in s):
        return s.lower()
    try:
        raw = base64.b64decode(s, validate=True)
    except binascii.Error as exc:
        raise ValueError(f"invalid SHA256 digest '{s}': {exc}") from exc
    if len(raw) != 32:
        raise ValueError(f"decoded SHA256 digest '{s}' has {len(raw)} bytes (expected 32)")
    return raw.hex()


def parse_distinfo(distinfo_path: pathlib.Path) -> List[Dict[str, Any]]:
    if not distinfo_path.is_file():
        die(f"missing vendor distinfo: {distinfo_path}")
    digests: Dict[str, str] = {}
    sizes: Dict[str, int] = {}
    order: List[str] = []
    for raw in distinfo_path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m_sha = DISTINFO_SHA256_RE.match(line)
        if m_sha:
            fname, raw_hash = m_sha.group(1).strip(), m_sha.group(2).strip()
            digests[fname] = decode_openbsd_sha256(raw_hash)
            if fname not in order:
                order.append(fname)
            continue
        m_sz = DISTINFO_SIZE_RE.match(line)
        if m_sz:
            fname, sz_s = m_sz.group(1).strip(), m_sz.group(2).strip()
            sizes[fname] = int(sz_s)
    entries = []
    for fn in order:
        entries.append(
            {
                "filename": fn,
                "sha256": digests[fn],
                "size": sizes.get(fn),
            }
        )
    return entries


def parse_openbsd_makefile_vars(paths: Sequence[pathlib.Path]) -> Dict[str, str]:
    env: Dict[str, str] = {
        "LOCALBASE": "/usr/local",
        "PREFIX": "/usr/local",
        "TRUEPREFIX": "/usr/local",
        "SYSCONFDIR": "/etc",
    }
    for p in paths:
        if not p.is_file():
            continue
        logical: List[str] = []
        cur = ""
        for raw in p.read_text(encoding="utf-8", errors="replace").splitlines():
            s = raw.rstrip()
            if "#" in s:
                idx = s.find("#")
                if idx == 0 or s[idx - 1] != "\\":
                    s = s[:idx].rstrip()
            if s.endswith("\\"):
                cur += (" " if cur else "") + s[:-1].strip()
            else:
                cur += (" " if cur else "") + s.strip()
                if cur:
                    logical.append(cur)
                cur = ""
        if cur:
            logical.append(cur)

        for ln in logical:
            if ln.startswith("."):
                continue
            m = VAR_ASSIGN_RE.match(ln)
            if not m:
                continue
            k, op, val = m.group(1), m.group(2), m.group(3).strip()
            if len(val) >= 2 and val[0] == val[-1] and val[0] in ('"', "'"):
                val = val[1:-1]
            if op == "+=" and k in env:
                env[k] = (env[k] + " " + val).strip()
            elif op == "?=" and k in env:
                continue
            else:
                env[k] = val

            # Populate LIB<name>_VERSION from SHARED_LIBS += name ver
            if k == "SHARED_LIBS":
                toks = env[k].split()
                for idx in range(0, len(toks) - 1, 2):
                    if not toks[idx].startswith("#"):
                        env[f"LIB{toks[idx]}_VERSION"] = toks[idx + 1]

    # Synthesize default DISTNAME from GH_* or DIST_TUPLE when omitted (matching bsd.port.mk / dist-tuple.port.mk)
    if "DISTNAME" not in env:
        if "GH_PROJECT" in env and ("GH_TAGNAME" in env or "GH_COMMIT" in env):
            proj = expand_openbsd_expr(env.get("GH_PROJECT", ""), env).strip()
            tag = expand_openbsd_expr(env.get("GH_TAGNAME", ""), env).strip()
            if proj and tag:
                ver_part = tag[1:] if (len(tag) > 1 and tag[0] in ("v", "V") and tag[1].isdigit()) else tag
                env["DISTNAME"] = f"{proj}-{ver_part}"
        elif "DIST_TUPLE" in env:
            dt = expand_openbsd_expr(env["DIST_TUPLE"], env).split()
            if len(dt) >= 5:
                _tmpl, _acct, proj, ref, _sub = dt[0], dt[1], dt[2], dt[3], dt[4]
                ver_part = ref[1:] if (len(ref) > 1 and ref[0] in ("v", "V") and ref[1].isdigit()) else ref
                env["DISTNAME"] = f"{proj}-{ver_part}"
    return env


def expand_openbsd_expr(expr: str, env: Dict[str, str], depth: int = 0) -> str:
    if depth > 8 or "$" not in expr:
        return expr

    def repl(m: re.Match) -> str:
        name = m.group(1) or m.group(4) or m.group(5) or ""
        suffix_append = m.group(2)
        mod = m.group(3)
        base_val = expand_openbsd_expr(env.get(name, ""), env, depth + 1)
        if mod == "R":
            return base_val.rsplit(".", 1)[0] if "." in base_val else base_val
        if mod == "L":
            return base_val.lower()
        if suffix_append is not None:
            sub = expand_openbsd_expr(suffix_append, env, depth + 1)
            toks = base_val.split()
            return " ".join(t + sub for t in toks)
        return base_val

    return SIMPLE_VAR_RE.sub(repl, expr)


def resolve_distfile_urls(
    vendor_ports_dir: pathlib.Path,
    vendor_port: str,
    distfile_name: str,
    extra_sites: Sequence[str],
) -> List[str]:
    mk_paths: List[pathlib.Path] = [vendor_ports_dir / "infrastructure/db/network.conf"]
    parts = vendor_port.split("/")
    for i in range(1, len(parts)):
        anc = "/".join(parts[:i])
        mk_paths.append(vendor_ports_dir / anc / "Makefile.inc")
    mk_paths.append(vendor_ports_dir / vendor_port / "Makefile")

    env = parse_openbsd_makefile_vars(mk_paths)
    sites_raw = list(extra_sites)

    if "SITES" in env:
        expanded = expand_openbsd_expr(env["SITES"], env)
        sites_raw.extend(expanded.split())

    gh_acct = expand_openbsd_expr(env.get("GH_ACCOUNT", ""), env).strip()
    gh_proj = expand_openbsd_expr(env.get("GH_PROJECT", ""), env).strip()
    gh_tag = expand_openbsd_expr(env.get("GH_TAGNAME", ""), env).strip()
    gh_commit = expand_openbsd_expr(env.get("GH_COMMIT", ""), env).strip()
    if gh_acct and gh_proj and (gh_tag or gh_commit):
        ref = gh_commit or gh_tag
        sites_raw.append(f"https://github.com/{gh_acct}/{gh_proj}/archive/{ref}/")
        if gh_tag:
            sites_raw.append(f"https://github.com/{gh_acct}/{gh_proj}/releases/download/{gh_tag}/")

    if "DIST_TUPLE" in env:
        dt_toks = expand_openbsd_expr(env["DIST_TUPLE"], env).split()
        for idx in range(0, len(dt_toks) - 4, 5):
            tmpl, acct, proj, ref, _sub = dt_toks[idx : idx + 5]
            if tmpl == "github":
                sites_raw.append(f"https://github.com/{acct}/{proj}/archive/{ref}/")
                sites_raw.append(f"https://github.com/{acct}/{proj}/releases/download/{ref}/")

    # Always include official OpenBSD distfile mirrors as reliable fallback
    sites_raw.extend(
        [
            "https://cdn.openbsd.org/pub/OpenBSD/distfiles/",
            "https://ftp.openbsd.org/pub/OpenBSD/distfiles/",
            f"https://cdn.openbsd.org/pub/OpenBSD/distfiles/{distfile_name.split('/', 1)[0]}/"
            if "/" in distfile_name
            else "",
        ]
    )

    leaf = distfile_name.rsplit("/", 1)[-1]
    urls: List[str] = []
    seen: Set[str] = set()
    for s in sites_raw:
        s = s.strip()
        if not s or not s.startswith(("https://", "http://")):
            continue
        if not s.endswith("/"):
            s += "/"
        for candidate in ([s + distfile_name, s + leaf] if "/" in distfile_name else [s + leaf]):
            if candidate not in seen:
                seen.add(candidate)
                urls.append(candidate)
    return urls


def load_recipe(port_dir: pathlib.Path, openbsd_version: str) -> Dict[str, Any]:
    toml_path = port_dir / "port.toml"
    json_path = port_dir / "port.json"
    if toml_path.is_file():
        raw = tomllib.loads(toml_path.read_text(encoding="utf-8"))
    elif json_path.is_file():
        raw = json.loads(json_path.read_text(encoding="utf-8"))
    else:
        die(f"missing port.toml or port.json in {port_dir}")

    rel_port = port_dir.relative_to(REPO_ROOT / "ports").as_posix()
    recipe = dict(raw)
    ver_overrides = recipe.pop("versions", {}).get(openbsd_version, {})
    if isinstance(ver_overrides, dict):
        for k, v in ver_overrides.items():
            recipe[k] = v

    recipe["port"] = recipe.get("port", rel_port)
    recipe["vendor_port"] = recipe.get("vendor_port", recipe["port"])
    recipe["port_dir"] = port_dir
    recipe.setdefault("depends", [])
    recipe.setdefault("build_style", "gnu")
    recipe.setdefault("separate_build", False)
    recipe.setdefault("use_gmake", True)
    recipe.setdefault("apply_vendor_patches", True)
    recipe.setdefault("skip_vendor_patches", [])
    recipe.setdefault("patch_strip", 0)
    recipe.setdefault("applets", [])
    return recipe


def discover_recipes(openbsd_version: str, target_ports: Optional[Sequence[str]] = None) -> List[Dict[str, Any]]:
    ports_root = REPO_ROOT / "ports"
    if not ports_root.is_dir():
        return []

    all_map: Dict[str, Dict[str, Any]] = {}
    for p in sorted(ports_root.rglob("port.toml")) + sorted(ports_root.rglob("port.json")):
        port_dir = p.parent
        rel = port_dir.relative_to(ports_root).as_posix()
        if rel not in all_map:
            all_map[rel] = load_recipe(port_dir, openbsd_version)

    if target_ports:
        wanted: Set[str] = set()

        def add_with_deps(name: str) -> None:
            norm = name.strip().strip("/")
            if norm.startswith("ports/"):
                norm = norm[len("ports/") :]
            if norm not in all_map:
                die(f"port recipe '{norm}' not found under ports/ (available: {', '.join(sorted(all_map)) or 'none'})")
            if norm in wanted:
                return
            wanted.add(norm)
            for dep in all_map[norm].get("depends", []):
                add_with_deps(dep)

        for tp in target_ports:
            for item in tp.split(","):
                if item.strip():
                    add_with_deps(item)
    else:
        wanted = set(all_map.keys())

    # Topological sort
    ordered: List[Dict[str, Any]] = []
    visiting: Set[str] = set()
    visited: Set[str] = set()

    def visit(name: str) -> None:
        if name in visited:
            return
        if name in visiting:
            die(f"cyclic port dependency involving '{name}'")
        visiting.add(name)
        rec = all_map.get(name)
        if rec is None:
            die(f"missing dependency port recipe 'ports/{name}/port.toml'")
        for dep in rec.get("depends", []):
            visit(dep)
        visiting.remove(name)
        visited.add(name)
        ordered.append(rec)

    for name in sorted(wanted):
        visit(name)
    return ordered


def fetch_port_distfiles(recipe: Dict[str, Any], openbsd_version: str) -> List[Tuple[pathlib.Path, Dict[str, Any]]]:
    vendor_ports_dir = REPO_ROOT / "vendor/openbsd/versions" / openbsd_version / "ports"
    vport = recipe["vendor_port"]
    vdir = vendor_ports_dir / vport
    if not vdir.is_dir():
        die(
            f"port '{recipe['port']}' has no vendored OpenBSD {openbsd_version} subtree at {vdir}; "
            f"run `make import PORT={vport}` first"
        )

    entries = parse_distinfo(vdir / "distinfo")
    cache_dist = REPO_ROOT / ".cache/distfiles"
    extra_sites = recipe.get("sites", [])
    fetched: List[Tuple[pathlib.Path, Dict[str, Any]]] = []

    for ent in entries:
        fn = ent["filename"]
        expected_sha = ent["sha256"]
        expected_sz = ent["size"]
        dest = cache_dist / fn
        dest.parent.mkdir(parents=True, exist_ok=True)

        if dest.is_file():
            actual_sz = dest.stat().st_size
            actual_sha = sha256_file(dest)
            if actual_sha == expected_sha and (expected_sz is None or actual_sz == expected_sz):
                fetched.append((dest, ent))
                continue
            dest.unlink()

        urls = resolve_distfile_urls(vendor_ports_dir, vport, fn, extra_sites)
        part = dest.with_suffix(dest.suffix + ".part")
        last_err = "no candidate URLs"
        ok = False
        for url in urls:
            print(f"[fetch/{openbsd_version}] {recipe['port']}: {url}")
            part.unlink(missing_ok=True)
            proc = subprocess.run(
                ["curl", "-fL", "--connect-timeout", "15", "--retry", "2", "-sS", "-o", str(part), url],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            if proc.returncode != 0 or not part.is_file():
                last_err = proc.stderr.strip() or f"curl exit {proc.returncode}"
                continue
            actual_sz = part.stat().st_size
            actual_sha = sha256_file(part)
            if expected_sz is not None and actual_sz != expected_sz:
                last_err = f"size mismatch from {url}: got {actual_sz}, expected {expected_sz}"
                part.unlink(missing_ok=True)
                continue
            if actual_sha != expected_sha:
                last_err = f"SHA256 mismatch from {url}: got {actual_sha}, expected {expected_sha}"
                part.unlink(missing_ok=True)
                continue
            part.replace(dest)
            print(f"[fetch/{openbsd_version}] verified {fn} (sha256={actual_sha[:16]}..., {actual_sz} bytes)")
            ok = True
            break

        if not ok:
            die(f"failed to fetch & verify distfile '{fn}' for {recipe['port']}: {last_err}")
        fetched.append((dest, ent))

    return fetched


def decompress_lzip_stream(src_path: pathlib.Path, dst_fp: Any) -> None:
    """Pure-Python LZIP v1 (.lz) multi-member decompressor with CRC32 & size verification."""
    buf = b""
    members_decoded = 0
    with src_path.open("rb") as src_fp:
        while True:
            while len(buf) < 6:
                chunk = src_fp.read(262144)
                if not chunk:
                    break
                buf += chunk

            if not buf:
                if members_decoded == 0:
                    die(f"cannot extract {src_path.name}: empty LZIP archive")
                break

            if not buf.startswith(b"LZIP"):
                if members_decoded > 0:
                    rest = src_fp.read()
                    if all(b == 0 for b in buf) and all(b == 0 for b in rest):
                        break
                die(f"cannot extract {src_path.name}: invalid LZIP header magic")

            if len(buf) < 6:
                die(f"cannot extract {src_path.name}: truncated 6-byte LZIP header")

            ver = buf[4]
            if ver != 1:
                die(f"cannot extract {src_path.name}: unsupported LZIP version {ver}")

            ds = buf[5]
            base = 1 << (ds & 0x1F)
            dict_size = base - (base >> 4) * ((ds >> 5) & 0x07)
            if dict_size < 4096 or dict_size > (512 << 20):
                die(f"cannot extract {src_path.name}: invalid LZIP dictionary size {dict_size}")

            buf = buf[6:]
            member_bytes = 6
            crc = 0
            data_size = 0
            dec = lzma.LZMADecompressor(
                format=lzma.FORMAT_RAW,
                filters=[{"id": lzma.FILTER_LZMA1, "dict_size": dict_size, "lc": 3, "lp": 0, "pb": 2}],
            )

            while not dec.eof:
                if not buf:
                    chunk = src_fp.read(262144)
                    if not chunk:
                        die(f"cannot extract {src_path.name}: unexpected EOF in LZIP compressed stream")
                    buf = chunk
                in_len = len(buf)
                out = dec.decompress(buf)
                unused = dec.unused_data
                member_bytes += in_len - len(unused)
                buf = unused
                if out:
                    crc = zlib.crc32(out, crc)
                    data_size += len(out)
                    dst_fp.write(out)

            while len(buf) < 20:
                chunk = src_fp.read(262144)
                if not chunk:
                    break
                buf += chunk
            if len(buf) < 20:
                die(f"cannot extract {src_path.name}: truncated 20-byte LZIP member trailer")

            exp_crc, exp_data_size, exp_member_size = struct.unpack("<IQQ", buf[:20])
            buf = buf[20:]
            member_bytes += 20

            actual_crc = crc & 0xFFFFFFFF
            if actual_crc != exp_crc:
                die(f"cannot extract {src_path.name}: LZIP CRC32 mismatch (0x{actual_crc:08x} != 0x{exp_crc:08x})")
            if data_size != exp_data_size:
                die(f"cannot extract {src_path.name}: LZIP data size mismatch ({data_size} != {exp_data_size})")
            if member_bytes != exp_member_size:
                die(f"cannot extract {src_path.name}: LZIP member size mismatch ({member_bytes} != {exp_member_size})")
            members_decoded += 1


def extract_archive(archive_path: pathlib.Path, extract_root: pathlib.Path) -> None:
    name = archive_path.name.lower()
    if name.endswith(".zip"):
        with zipfile.ZipFile(archive_path, "r") as zf:
            for info in zf.infolist():
                out_p = extract_root / info.filename
                if info.is_dir():
                    out_p.mkdir(parents=True, exist_ok=True)
                    continue
                out_p.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(info, "r") as src, out_p.open("wb") as dst:
                    shutil.copyfileobj(src, dst)
                unix_mode = (info.external_attr >> 16) & 0o7777
                if unix_mode:
                    out_p.chmod(unix_mode)
        return

    if name.endswith((".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz", ".tar")):
        with tarfile.open(archive_path, "r:*") as tf:
            tf.extractall(path=extract_root, filter="data")
        return

    if name.endswith(".tar.zst"):
        subprocess.run(["tar", "--zstd", "-xf", str(archive_path), "-C", str(extract_root)], check=True)
        return

    if name.endswith(".tar.lz"):
        with tempfile.TemporaryFile(dir=str(extract_root.parent)) as tmp_tar:
            decompress_lzip_stream(archive_path, tmp_tar)
            tmp_tar.seek(0)
            with tarfile.open(fileobj=tmp_tar, mode="r:") as tf:
                tf.extractall(path=extract_root, filter="data")
        return

    die(f"unsupported archive format: {archive_path.name}")


def detect_wrksrc(extract_root: pathlib.Path, wrksrc_subdir: str) -> pathlib.Path:
    if wrksrc_subdir:
        cand = extract_root / wrksrc_subdir
        if not cand.is_dir():
            die(f"configured wrksrc_subdir '{wrksrc_subdir}' does not exist under {extract_root}")
        return cand
    children = [p for p in extract_root.iterdir() if not p.name.startswith(".")]
    dirs = [p for p in children if p.is_dir()]
    files = [p for p in children if p.is_file()]
    if len(dirs) == 1 and not files:
        return dirs[0]
    return extract_root


def apply_patch_dir(patch_dir: pathlib.Path, wrksrc: pathlib.Path, strip_level: int, skip_set: Set[str], label: str) -> None:
    if not patch_dir.is_dir():
        return
    patch_files = sorted(p for p in patch_dir.iterdir() if p.is_file() and p.name.startswith("patch-"))
    for pf in patch_files:
        if pf.name in skip_set:
            print(f"  [patch] skipping {label}/{pf.name} (per recipe)")
            continue
        print(f"  [patch] applying {label}/{pf.name}")
        with pf.open("rb") as stdin_fp:
            proc = subprocess.run(
                [
                    "patch",
                    f"-p{strip_level}",
                    "-f",
                    "-N",
                    "-s",
                    "--no-backup-if-mismatch",
                    "-d",
                    str(wrksrc),
                ],
                stdin=stdin_fp,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        if proc.returncode != 0:
            die(
                f"patch failed ({label}/{pf.name}) in {wrksrc}:\n"
                f"{proc.stdout.decode('utf-8', 'replace')}\n{proc.stderr.decode('utf-8', 'replace')}"
            )


def get_port_pkgname(vendor_ports_dir: pathlib.Path, vendor_port: str) -> str:
    mk_paths: List[pathlib.Path] = []
    parts = vendor_port.split("/")
    for i in range(1, len(parts)):
        mk_paths.append(vendor_ports_dir / "/".join(parts[:i]) / "Makefile.inc")
    mk_paths.append(vendor_ports_dir / vendor_port / "Makefile")
    env = parse_openbsd_makefile_vars(mk_paths)
    distname = expand_openbsd_expr(env.get("DISTNAME", ""), env).strip()
    pkgname = expand_openbsd_expr(env.get("PKGNAME", distname or parts[-1]), env).strip()
    if not pkgname:
        pkgname = parts[-1]
    return pkgname


def make_sdk_env(
    openbsd_version: str,
    backend: str,
    pal: str,
    obsd_root: pathlib.Path,
    stage_dir: pathlib.Path,
    wrksrc: pathlib.Path,
    wrkbuild: pathlib.Path,
    port_dir: pathlib.Path,
    vendor_port_dir: pathlib.Path,
    vendor_env: Dict[str, str],
    recipe: Dict[str, Any],
    jobs: int,
) -> Dict[str, str]:
    sdk_bin = REPO_ROOT / "sdk/bin"
    env = dict(os.environ)
    env["OBSD_PORTS_ROOT"] = str(REPO_ROOT)
    env["LIBOBSDCOMPAT_ROOT"] = str(obsd_root)
    env["OPENBSD_VERSION"] = openbsd_version
    env["COMPAT_BACKEND"] = backend
    env["COMPAT_PAL"] = pal
    env["OBSD_STAGE_DIR"] = str(stage_dir)

    cc = str(sdk_bin / "obsd-cc")
    cxx = str(sdk_bin / "obsd-c++")
    ar = str(sdk_bin / "obsd-ar")
    ranlib = str(sdk_bin / "obsd-ranlib")
    ld = str(sdk_bin / "obsd-ld")
    nm = str(sdk_bin / "obsd-nm")
    strip_bin = str(sdk_bin / "obsd-strip")
    pkg_cfg = str(sdk_bin / "obsd-pkg-config")
    install_bin = str(sdk_bin / "obsd-install")
    config_site = str(REPO_ROOT / "sdk/autoconf/config.site")
    cmake_tc = str(REPO_ROOT / "sdk/cmake/openbsd-wasm64.cmake")

    env["PATH"] = f"{sdk_bin}:{env.get('PATH', '/usr/bin:/bin')}"
    env["CC"] = cc
    env["CXX"] = cxx
    env["CPP"] = f"{cc} -E"
    env["AR"] = ar
    env["RANLIB"] = ranlib
    env["LD"] = ld
    env["NM"] = nm
    env["STRIP"] = strip_bin
    env["PKG_CONFIG"] = pkg_cfg
    env["INSTALL"] = install_bin
    env["INSTALL_PROGRAM"] = f"{install_bin} -c -m 0755"
    env["INSTALL_SCRIPT"] = f"{install_bin} -c -m 0755"
    env["INSTALL_DATA"] = f"{install_bin} -c -m 0644"
    env["INSTALL_MAN"] = f"{install_bin} -c -m 0444"
    env["INSTALL_DATA_DIR"] = f"{install_bin} -d -m 0755"
    env["CONFIG_SITE"] = config_site
    env["CMAKE_TOOLCHAIN_FILE"] = cmake_tc

    # Host C compiler for ports whose Makefile compiles build-time code generators (CC_FOR_BUILD / HOSTCC)
    host_cc = shutil.which("clang") or shutil.which("gcc") or shutil.which("cc") or "cc"
    env["CC_FOR_BUILD"] = host_cc
    env["BUILD_CC"] = host_cc
    env["HOSTCC"] = host_cc

    base_cf = ["-O2", *recipe.get("cflags", [])]
    base_cxxf = ["-O2", *recipe.get("cxxflags", [])]
    base_cppf = [f"-I{stage_dir}/usr/local/include", *recipe.get("cppflags", [])]
    base_ldf = [f"-L{stage_dir}/usr/local/lib", *recipe.get("ldflags", [])]
    base_libs = list(recipe.get("libs", []))

    env["CFLAGS"] = " ".join(base_cf).strip()
    env["CXXFLAGS"] = " ".join(base_cxxf).strip()
    env["CPPFLAGS"] = " ".join(base_cppf).strip()
    env["LDFLAGS"] = " ".join(base_ldf).strip()
    if base_libs:
        env["LIBS"] = " ".join(base_libs)

    env["PREFIX"] = "/usr/local"
    env["LOCALBASE"] = "/usr/local"
    env["SYSCONFDIR"] = "/etc"
    env["DESTDIR"] = str(stage_dir)
    env["STAGE_DIR"] = str(stage_dir)
    env["WRKSRC"] = str(wrksrc)
    env["WRKBUILD"] = str(wrkbuild)
    env["PORT_DIR"] = str(port_dir)
    env["VENDOR_PORT_DIR"] = str(vendor_port_dir)
    env["JOBS"] = str(jobs)

    # Export OpenBSD SHARED_LIBS versions (`LIBbz2_VERSION`, `LIBlua5.4_VERSION`, etc.)
    for k, v in vendor_env.items():
        if k.startswith("LIB") and k.endswith("_VERSION"):
            env.setdefault(k, v)

    for k, v in recipe.get("env", {}).items():
        env[str(k)] = str(v)

    return env


def run_step(cmd: Sequence[str] | str, cwd: pathlib.Path, env: Dict[str, str], desc: str) -> None:
    if isinstance(cmd, str):
        print(f"  [{desc}] sh -c {cmd}")
        proc = subprocess.run(["bash", "-euo", "pipefail", "-c", cmd], cwd=str(cwd), env=env)
    else:
        print(f"  [{desc}] {' '.join(shlex.quote(str(x)) for x in cmd)}")
        proc = subprocess.run([str(x) for x in cmd], cwd=str(cwd), env=env)
    if proc.returncode != 0:
        die(f"{desc} failed with exit code {proc.returncode} in {cwd}")


def snapshot_tree(root: pathlib.Path) -> Dict[str, Tuple[int, int]]:
    snap: Dict[str, Tuple[int, int]] = {}
    if not root.exists():
        return snap
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dp = pathlib.Path(dirpath)
        for nm in list(dirnames) + list(filenames):
            fp = dp / nm
            rel = fp.relative_to(root).as_posix()
            st = fp.lstat()
            snap[rel] = (st.st_mtime_ns, st.st_size)
    return snap


def build_single_port(
    recipe: Dict[str, Any],
    openbsd_version: str,
    backend: str,
    pal: str,
    obsd_root: pathlib.Path,
    lane_dir: pathlib.Path,
    jobs: int,
    force: bool = False,
) -> Dict[str, Any]:
    port_name = recipe["port"]
    vport = recipe["vendor_port"]
    vendor_ports_dir = REPO_ROOT / "vendor/openbsd/versions" / openbsd_version / "ports"
    vendor_port_dir = vendor_ports_dir / vport
    pkgname = recipe.get("pkgname") or get_port_pkgname(vendor_ports_dir, vport)

    stage_dir = lane_dir / "stage"
    stage_dir.mkdir(parents=True, exist_ok=True)
    for sub in ("bin", "sbin", "lib", "lib/pkgconfig", "include", "share", "man", "man/man1"):
        (stage_dir / "usr/local" / sub).mkdir(parents=True, exist_ok=True)

    stamps_dir = lane_dir / ".stamps"
    stamps_dir.mkdir(parents=True, exist_ok=True)
    stamp_slug = port_name.replace("/", "__")
    stamp_file = stamps_dir / f"{stamp_slug}.json"

    fetched = fetch_port_distfiles(recipe, openbsd_version)

    # Compute deterministic recipe + vendor + distfile build signature
    sig_h = hashlib.sha256()
    sig_h.update(json.dumps(recipe, default=str, sort_keys=True).encode("utf-8"))
    for vf in sorted(vendor_port_dir.rglob("*")):
        if vf.is_file():
            sig_h.update(vf.relative_to(vendor_port_dir).as_posix().encode())
            sig_h.update(sha256_file(vf).encode())
    port_dir: pathlib.Path = recipe["port_dir"]
    for pf in sorted(port_dir.rglob("*")):
        if pf.is_file():
            sig_h.update(pf.relative_to(port_dir).as_posix().encode())
            sig_h.update(sha256_file(pf).encode())
    for df_path, df_ent in fetched:
        sig_h.update(df_ent["sha256"].encode())
    build_sig = sig_h.hexdigest()

    if not force and stamp_file.is_file():
        old = json.loads(stamp_file.read_text(encoding="utf-8"))
        if old.get("signature") == build_sig:
            all_present = all((stage_dir / rel).exists() or (stage_dir / rel).is_symlink() for rel in old.get("installed_files", []))
            if all_present:
                print(f"[build/{openbsd_version}] {port_name} ({pkgname}): up-to-date")
                return old

    print(f"==> [build/{openbsd_version}] building {port_name} ({pkgname}) [{backend}/{pal}]...")
    work_port_dir = lane_dir / "work" / port_name
    if work_port_dir.exists():
        shutil.rmtree(work_port_dir)
    src_extract_dir = work_port_dir / "src"
    src_extract_dir.mkdir(parents=True, exist_ok=True)

    for df_path, _ent in fetched:
        extract_archive(df_path, src_extract_dir)

    wrksrc = detect_wrksrc(src_extract_dir, recipe.get("wrksrc_subdir", ""))
    if recipe.get("separate_build", False):
        wrkbuild = work_port_dir / "build"
        wrkbuild.mkdir(parents=True, exist_ok=True)
    else:
        wrkbuild = wrksrc

    skip_patches = set(recipe.get("skip_vendor_patches", []))
    pstrip = int(recipe.get("patch_strip", 0))
    if recipe.get("apply_vendor_patches", True):
        apply_patch_dir(vendor_port_dir / "patches", wrksrc, pstrip, skip_patches, f"vendor/{vport}/patches")
    apply_patch_dir(port_dir / "patches", wrksrc, pstrip, set(), f"ports/{port_name}/patches")

    mk_paths = [vendor_ports_dir / "/".join(vport.split("/")[:i]) / "Makefile.inc" for i in range(1, len(vport.split("/")))]
    mk_paths.append(vendor_port_dir / "Makefile")
    vendor_env = parse_openbsd_makefile_vars(mk_paths)

    env = make_sdk_env(
        openbsd_version=openbsd_version,
        backend=backend,
        pal=pal,
        obsd_root=obsd_root,
        stage_dir=stage_dir,
        wrksrc=wrksrc,
        wrkbuild=wrkbuild,
        port_dir=port_dir,
        vendor_port_dir=vendor_port_dir,
        vendor_env=vendor_env,
        recipe=recipe,
        jobs=jobs,
    )

    make_prog = (shutil.which("gmake") or "make") if recipe.get("use_gmake", True) else "make"
    before_snap = snapshot_tree(stage_dir)

    for hook in recipe.get("pre_configure", []):
        run_step(hook, wrksrc, env, f"{port_name}:pre-configure")

    style = recipe["build_style"]
    custom_script = port_dir / "build.sh"

    if style == "script" or (custom_script.is_file() and style == "custom"):
        if custom_script.is_file():
            run_step(["bash", "-euo", "pipefail", str(custom_script)], wrkbuild, env, f"{port_name}:build.sh")
        else:
            for cmd in recipe.get("build_cmd", []):
                run_step(cmd, wrkbuild, env, f"{port_name}:build")
    else:
        if style in ("gnu", "simple"):
            cfg_rel = recipe.get("configure_script", "./configure")
            cfg_bin = (wrksrc / cfg_rel).resolve() if not os.path.isabs(cfg_rel) else pathlib.Path(cfg_rel)
            host_arch = platform.machine() or "x86_64"
            cfg_cmd: List[str] = ["sh", str(cfg_bin)]
            if recipe.get("configure_host", style == "gnu"):
                cfg_cmd.extend(
                    [
                        f"--host=aarch64-unknown-openbsd{openbsd_version}",
                        f"--build={host_arch}-unknown-linux-gnu",
                    ]
                )
            if recipe.get("configure_default_args", style == "gnu"):
                cfg_cmd.extend(
                    [
                        "--prefix=/usr/local",
                        "--sysconfdir=/etc",
                        "--mandir=/usr/local/man",
                        "--disable-shared",
                        "--enable-static",
                    ]
                )
            cfg_cmd.extend(recipe.get("configure_args", []))
            run_step(cfg_cmd, wrkbuild, env, f"{port_name}:configure")

        elif style == "cmake":
            cmake_cmd = [
                "cmake",
                "-S",
                str(wrksrc),
                "-B",
                str(wrkbuild),
                f"-DCMAKE_TOOLCHAIN_FILE={REPO_ROOT / 'sdk/cmake/openbsd-wasm64.cmake'}",
                "-DCMAKE_BUILD_TYPE=Release",
                "-DCMAKE_INSTALL_PREFIX=/usr/local",
                "-DCMAKE_INSTALL_MANDIR=/usr/local/man",
                "-DBUILD_SHARED_LIBS=OFF",
                *recipe.get("cmake_args", []),
            ]
            run_step(cmake_cmd, wrkbuild, env, f"{port_name}:cmake-configure")

        elif style == "make":
            pass
        else:
            die(f"{port_name}: unsupported build_style '{style}'")

        for hook in recipe.get("post_configure", []):
            run_step(hook, wrkbuild, env, f"{port_name}:post-configure")

        for hook in recipe.get("pre_build", []):
            run_step(hook, wrkbuild, env, f"{port_name}:pre-build")

        if recipe.get("build_cmd"):
            for bcmd in recipe["build_cmd"]:
                run_step(bcmd, wrkbuild, env, f"{port_name}:build")
        elif style == "cmake":
            run_step(["cmake", "--build", str(wrkbuild), "-j", str(jobs), *recipe.get("make_args", [])], wrkbuild, env, f"{port_name}:cmake-build")
        else:
            m_cmd = [make_prog, f"-j{jobs}", *recipe.get("make_args", []), *recipe.get("make_targets", [])]
            run_step(m_cmd, wrkbuild, env, f"{port_name}:make")

        if recipe.get("install_cmd"):
            for icmd in recipe["install_cmd"]:
                run_step(icmd, wrkbuild, env, f"{port_name}:install")
        elif style == "cmake":
            inst_env = dict(env)
            inst_env["DESTDIR"] = str(stage_dir)
            run_step(["cmake", "--install", str(wrkbuild)], wrkbuild, inst_env, f"{port_name}:cmake-install")
        else:
            inst_target = recipe.get("install_target", "install")
            if inst_target:
                use_destdir = recipe.get("install_use_destdir", True)
                dest_args = [f"DESTDIR={stage_dir}"] if use_destdir else [f"PREFIX={stage_dir}/usr/local"]
                i_cmd = [make_prog, inst_target, *dest_args, *recipe.get("install_args", [])]
                run_step(i_cmd, wrkbuild, env, f"{port_name}:install")

    for hook in recipe.get("post_install", []):
        run_step(hook, wrkbuild, env, f"{port_name}:post-install")

    after_snap = snapshot_tree(stage_dir)
    installed_files = sorted(
        rel for rel, meta in after_snap.items() if before_snap.get(rel) != meta
    )

    record = {
        "port": port_name,
        "vendor_port": vport,
        "pkgname": pkgname,
        "openbsd_version": openbsd_version,
        "backend": backend,
        "pal": pal,
        "signature": build_sig,
        "installed_files": installed_files,
        "applets": recipe.get("applets", []),
    }
    stamp_file.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(f"[build/{openbsd_version}] finished {port_name} ({pkgname}): {len(installed_files)} staged entries")
    return record


def resolve_obsd_root_arg(arg_val: Optional[str]) -> pathlib.Path:
    if arg_val:
        p = pathlib.Path(arg_val).resolve()
        if not (p / "vendor/openbsd/versions").is_dir():
            die(f"invalid --libobsdcompat-root: {p}")
        return p
    proc = subprocess.run(
        ["sh", str(REPO_ROOT / "tools/config/locate-libobsdcompat.sh")],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr)
        raise SystemExit(proc.returncode)
    return pathlib.Path(proc.stdout.strip()).resolve()


def cmd_list_catalog(args: argparse.Namespace) -> int:
    cat_path = REPO_ROOT / "config/versions" / f"{args.openbsd_version}-catalog.tsv"
    if not cat_path.is_file():
        die(f"missing catalog {cat_path}; run `make sync-vendor` first")
    flt = (args.filter or "").strip().lower()
    shown = 0
    for idx, raw in enumerate(cat_path.read_text(encoding="utf-8").splitlines()):
        if idx == 0 or not raw.strip() or raw.startswith("#"):
            continue
        if raw.startswith("portpath\t"):
            continue
        if flt and flt not in raw.lower():
            continue
        cols = raw.split("\t")
        portpath = cols[0]
        pkgname = cols[1] if len(cols) > 1 else ""
        comment = cols[3] if len(cols) > 3 else ""
        print(f"{portpath:<32} {pkgname:<28} {comment}")
        shown += 1
    print(f"# OpenBSD {args.openbsd_version} catalog: {shown} matching port(s)")
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    recipes = discover_recipes(args.openbsd_version, [args.port] if args.port else None)
    lane_dir = REPO_ROOT / "build/openbsd" / args.openbsd_version / args.backend / args.pal
    vendor_ports_dir = REPO_ROOT / "vendor/openbsd/versions" / args.openbsd_version / "ports"

    if not recipes:
        print(f"# No port recipes under ports/ yet (lane: OpenBSD {args.openbsd_version} {args.backend}/{args.pal})")
        return 0

    print(f"{'PORT':<24} {'PKGNAME':<24} {'VENDOR':<10} {'STATUS':<10} {'APPLETS'}")
    for rec in recipes:
        pname = rec["port"]
        vdir = vendor_ports_dir / rec["vendor_port"]
        has_vendor = "imported" if (vdir / "distinfo").is_file() else "missing"
        pkgname = rec.get("pkgname") or (get_port_pkgname(vendor_ports_dir, rec["vendor_port"]) if has_vendor == "imported" else "-")
        stamp = lane_dir / ".stamps" / (pname.replace("/", "__") + ".json")
        status = "built" if stamp.is_file() else "pending"
        app_names = ",".join(a.get("sym", "") for a in rec.get("applets", [])) or "(lib)"
        print(f"{pname:<24} {pkgname:<24} {has_vendor:<10} {status:<10} {app_names}")
    return 0


def cmd_fetch(args: argparse.Namespace) -> int:
    recipes = discover_recipes(args.openbsd_version, [args.port] if args.port else None)
    if not recipes:
        print(f"[fetch/{args.openbsd_version}] 0 port recipes in ports/ (nothing to fetch)")
        return 0
    for rec in recipes:
        fetch_port_distfiles(rec, args.openbsd_version)
    return 0


def cmd_build(args: argparse.Namespace) -> int:
    obsd_root = resolve_obsd_root_arg(args.libobsdcompat_root)
    recipes = discover_recipes(args.openbsd_version, [args.port] if args.port else None)
    lane_dir = REPO_ROOT / "build/openbsd" / args.openbsd_version / args.backend / args.pal
    lane_dir.mkdir(parents=True, exist_ok=True)
    if not recipes:
        print(f"[build/{args.openbsd_version}] 0 port recipes in ports/ (nothing to build)")
        return 0
    for rec in recipes:
        build_single_port(
            recipe=rec,
            openbsd_version=args.openbsd_version,
            backend=args.backend,
            pal=args.pal,
            obsd_root=obsd_root,
            lane_dir=lane_dir,
            jobs=args.jobs,
            force=args.force,
        )
    return 0


def cmd_package(args: argparse.Namespace) -> int:
    obsd_root = resolve_obsd_root_arg(args.libobsdcompat_root)
    lane_dir = REPO_ROOT / "build/openbsd" / args.openbsd_version / args.backend / args.pal
    lane_dir.mkdir(parents=True, exist_ok=True)

    adapter_script = REPO_ROOT / "targets" / args.backend / args.pal / f"package_{'wasm' if args.pal in ('emscripten', 'wasi') else args.pal}.py"
    if not adapter_script.is_file():
        adapter_script = REPO_ROOT / "targets" / args.backend / args.pal / "package.py"
    if not adapter_script.is_file():
        die(f"target packaging adapter not implemented for {args.backend}/{args.pal}: expected {adapter_script}")

    # Collect all declared recipes (so ports-applets.tsv reflects the complete built lane!)
    all_recipes = discover_recipes(args.openbsd_version, None)
    manifest_file = lane_dir / "built-ports.json"
    stamps_dir = lane_dir / ".stamps"
    records = []
    for rec in all_recipes:
        st_path = stamps_dir / (rec["port"].replace("/", "__") + ".json")
        if st_path.is_file():
            data = json.loads(st_path.read_text(encoding="utf-8"))
            # Always use latest applet definitions from port.toml in case aliases were updated
            data["applets"] = rec.get("applets", [])
            records.append(data)
    manifest_file.write_text(json.dumps(records, indent=2) + "\n", encoding="utf-8")

    cmd = [
        sys.executable,
        "-I",
        str(adapter_script),
        "--openbsd-version",
        args.openbsd_version,
        "--backend",
        args.backend,
        "--pal",
        args.pal,
        "--libobsdcompat-root",
        str(obsd_root),
        "--lane-dir",
        str(lane_dir),
        "--manifest",
        str(manifest_file),
    ]
    return subprocess.run(cmd).returncode


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="subcmd", required=True)

    p_cat = sub.add_parser("list-catalog")
    p_cat.add_argument("--openbsd-version", default="7.9")
    p_cat.add_argument("--filter", default="")

    for name in ("list", "fetch", "build", "package"):
        sp = sub.add_parser(name)
        sp.add_argument("--openbsd-version", default="7.9")
        sp.add_argument("--backend", default="emulate")
        sp.add_argument("--pal", default="emscripten")
        sp.add_argument("--libobsdcompat-root", default="")
        sp.add_argument("--port", default="")
        sp.add_argument("--jobs", type=int, default=os.cpu_count() or 8)
        if name == "build":
            sp.add_argument("--force", action="store_true")

    args = ap.parse_args()
    if args.subcmd == "list-catalog":
        return cmd_list_catalog(args)
    if args.subcmd == "list":
        return cmd_list(args)
    if args.subcmd == "fetch":
        return cmd_fetch(args)
    if args.subcmd == "build":
        return cmd_build(args)
    if args.subcmd == "package":
        return cmd_package(args)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
