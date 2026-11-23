#!/usr/bin/env python3
"""
gen_cargo_distinfo.py -- Generate authentic OpenBSD `crates.inc` & `distinfo`
for `extra/<category>/<name>/` Rust (`MODULES = devel/cargo`) ports.

Features:
  - Reads an `extra/<cat>/<name>/Makefile` (`--port-dir`) or explicit `--tarball` /
    `--cargo-lock`, downloads & caches upstream source tarballs (and any `DIST_TUPLE`
    archives) into `.cache/distfiles/`, extracts `Cargo.lock` in memory if needed,
    and downloads all crates.io `.crate` archives in parallel into
    `.cache/distfiles/cargo/<crate>-<ver>.tar.gz`.
  - Verifies every crate's SHA256 against `Cargo.lock` `checksum`, inspects each
    crate's `Cargo.toml` for SPDX `license` metadata, and writes exact OpenBSD:
      1. `crates.inc`: `MODCARGO_CRATES +=\t<crate>\t<ver>\t# <license>`
      2. `distinfo`: paired `SHA256 (<file>) = <44-char base64>` and `SIZE (<file>) = <bytes>`
  - Reports any `git+...` dependencies in `Cargo.lock` so port authors can add
    corresponding `DIST_TUPLE` lines cleanly.
"""
from __future__ import annotations

import argparse
import base64
import concurrent.futures
import fcntl
import hashlib
import pathlib
import sys
import tarfile
import threading
import time
import tomllib
import subprocess
from typing import Any, Dict, List, Optional, Sequence, Tuple

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
if str(REPO_ROOT / "tools") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "tools"))

import build_ports as bp  # type: ignore


def die(msg: str) -> "NoReturn":
    sys.stderr.write(f"gen_cargo_distinfo: {msg}\n")
    raise SystemExit(1)


def sha256_base64_and_hex(path: pathlib.Path) -> Tuple[str, str, int]:
    h = hashlib.sha256()
    sz = 0
    with path.open("rb") as fp:
        while True:
            chunk = fp.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
            sz += len(chunk)
    raw = h.digest()
    return base64.b64encode(raw).decode("ascii"), raw.hex(), sz


def download_to_cache(dest: pathlib.Path, urls: Sequence[str], expected_hex: Optional[str] = None) -> Tuple[str, str, int]:
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.is_file():
        b64, hx, sz = sha256_base64_and_hex(dest)
        if expected_hex is None or hx == expected_hex.lower():
            return b64, hx, sz

    lock_path = dest.parent / f".{dest.name}.lock"
    with lock_path.open("w") as lock_fp:
        fcntl.flock(lock_fp.fileno(), fcntl.LOCK_EX)
        if dest.is_file():
            b64, hx, sz = sha256_base64_and_hex(dest)
            if expected_hex is None or hx == expected_hex.lower():
                return b64, hx, sz
            dest.unlink(missing_ok=True)

        part = dest.parent / f".{dest.name}.{threading.get_ident()}.part"
        last_err = "no URLs"
        try:
            for url in urls:
                for attempt in range(3):
                    if attempt > 0:
                        time.sleep(0.5 * (2 ** (attempt - 1)))
                    part.unlink(missing_ok=True)
                    proc = subprocess.run(
                        [
                            "curl",
                            "-fL",
                            "--connect-timeout",
                            "15",
                            "--max-time",
                            "600",
                            "--retry",
                            "2",
                            "-sS",
                            "-o",
                            str(part),
                            url,
                        ],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                    )
                    if proc.returncode != 0 or not part.is_file():
                        last_err = proc.stderr.strip() or f"curl exit {proc.returncode}"
                        if "404" in last_err:
                            break
                        continue
                    b64, hx, sz = sha256_base64_and_hex(part)
                    if expected_hex is not None and hx != expected_hex.lower():
                        last_err = f"SHA256 mismatch from {url}: got {hx}, expected {expected_hex}"
                        part.unlink(missing_ok=True)
                        break
                    part.replace(dest)
                    return b64, hx, sz
        finally:
            part.unlink(missing_ok=True)

    die(f"failed downloading {dest.name}: {last_err}")


def read_crate_license(crate_tar: pathlib.Path, cname: str, cver: str) -> str:
    prefix = f"{cname}-{cver}/Cargo.toml"
    try:
        with tarfile.open(crate_tar, "r:*") as tf:
            member = None
            for m in tf.getmembers():
                if m.name == prefix or m.name.endswith("/Cargo.toml") and m.name.count("/") == 1:
                    member = m
                    break
            if member is None:
                return "unknown"
            fp = tf.extractfile(member)
            if fp is None:
                return "unknown"
            data = tomllib.loads(fp.read().decode("utf-8", errors="replace"))
            pkg = data.get("package", {})
            lic = pkg.get("license")
            if isinstance(lic, str) and lic.strip():
                return " ".join(lic.strip().split())
            lic_file = pkg.get("license-file")
            if isinstance(lic_file, str) and lic_file.strip():
                return f"custom ({lic_file.strip()})"
    except Exception:
        pass
    return "unknown"


def extract_cargo_lock_from_tarball(tar_path: pathlib.Path, lock_rel: str = "Cargo.lock") -> str:
    with tarfile.open(tar_path, "r:*") as tf:
        candidates: List[tarfile.TarInfo] = []
        for m in tf.getmembers():
            if not m.isfile():
                continue
            parts = m.name.split("/", 1)
            rel = parts[1] if len(parts) == 2 else parts[0]
            if rel == lock_rel or m.name == lock_rel:
                candidates.append(m)
        if not candidates:
            die(f"could not find '{lock_rel}' inside {tar_path}")
        candidates.sort(key=lambda x: len(x.name))
        fp = tf.extractfile(candidates[0])
        if fp is None:
            die(f"unable to read '{candidates[0].name}' from {tar_path}")
        return fp.read().decode("utf-8")


def infer_makefile_distfiles(port_dir: pathlib.Path, openbsd_version: str) -> List[Tuple[str, List[str]]]:
    mk_path = port_dir / "Makefile"
    if not mk_path.is_file():
        die(f"missing Makefile at {mk_path}")
    vendor_ports_dir = REPO_ROOT / "vendor/openbsd/versions" / openbsd_version / "ports"
    net_conf = vendor_ports_dir / "infrastructure/db/network.conf"
    paths = ([net_conf] if net_conf.is_file() else []) + [mk_path]
    env = bp.parse_openbsd_makefile_vars(paths)

    filenames: List[str] = []
    distname = bp.expand_openbsd_expr(env.get("DISTNAME", ""), env).strip()
    sufx = bp.expand_openbsd_expr(env.get("EXTRACT_SUFX", ".tar.gz"), env).strip() or ".tar.gz"

    if "GH_ACCOUNT" in env and "GH_PROJECT" in env and ("GH_TAGNAME" in env or "GH_COMMIT" in env):
        if distname:
            filenames.append(f"{distname}{sufx}")

    for dt in bp.parse_dist_tuples(env):
        proj_tail = dt["project"].rsplit("/", 1)[-1]
        if dt["targetdir"] == "." and distname == f"{proj_tail}-{dt['ver_part']}" and f"{distname}{sufx}" in filenames:
            continue
        filenames.append(f"{dt['account']}-{proj_tail}-{dt['ref']}.tar.gz")

    if not filenames and distname:
        filenames.append(f"{distname}{sufx}")

    rel_port = port_dir.name
    out: List[Tuple[str, List[str]]] = []
    seen: Set[str] = set()
    for fn in filenames:
        if fn in seen:
            continue
        seen.add(fn)
        urls = bp.resolve_distfile_urls(
            vendor_ports_dir=vendor_ports_dir,
            vendor_port=rel_port,
            distfile_name=fn,
            extra_sites=[],
            port_dir=port_dir,
            section="extra",
        )
        out.append((fn, urls))
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--port-dir", default="", help="Path to extra/<category>/<name> containing Makefile")
    ap.add_argument(
        "--distfile",
        action="append",
        default=[],
        help="Explicit primary/extra distfile `<filename>=<url_or_local_path>` (repeatable)",
    )
    ap.add_argument("--cargo-lock", default="", help="Path to Cargo.lock (otherwise extracted from main tarball)")
    ap.add_argument("--cargo-lock-subpath", default="Cargo.lock", help="Relative path to Cargo.lock inside tarball")
    ap.add_argument("--out-crates-inc", default="", help="Output path for crates.inc (default: <port-dir>/crates.inc)")
    ap.add_argument("--out-distinfo", default="", help="Output path for distinfo (default: <port-dir>/distinfo)")
    ap.add_argument("--openbsd-version", default="8.0")
    ap.add_argument("--jobs", type=int, default=24)
    args = ap.parse_args()

    cache_dist = REPO_ROOT / ".cache/distfiles"
    cache_dist.mkdir(parents=True, exist_ok=True)

    port_dir = pathlib.Path(args.port_dir).resolve() if args.port_dir else None
    out_crates = pathlib.Path(args.out_crates_inc).resolve() if args.out_crates_inc else (port_dir / "crates.inc" if port_dir else None)
    out_distinfo = pathlib.Path(args.out_distinfo).resolve() if args.out_distinfo else (port_dir / "distinfo" if port_dir else None)

    if out_crates is None or out_distinfo is None:
        die("specify --port-dir or both --out-crates-inc and --out-distinfo")

    dist_entries: List[Tuple[str, str, int]] = []  # (filename, b64_sha256, size)
    primary_tarball: Optional[pathlib.Path] = None

    if args.distfile:
        for spec in args.distfile:
            if "=" not in spec:
                die(f"invalid --distfile '{spec}' (expected <filename>=<url-or-path>)")
            fn, src = spec.split("=", 1)
            fn = fn.strip()
            src = src.strip()
            dest = cache_dist / fn
            if src.startswith(("https://", "http://")):
                b64, _hx, sz = download_to_cache(dest, [src])
            else:
                sp = pathlib.Path(src).resolve()
                if not sp.is_file():
                    die(f"local distfile not found: {sp}")
                dest.parent.mkdir(parents=True, exist_ok=True)
                if sp != dest.resolve():
                    import shutil

                    shutil.copy2(sp, dest)
                b64, _hx, sz = sha256_base64_and_hex(dest)
            dist_entries.append((fn, b64, sz))
            if primary_tarball is None:
                primary_tarball = dest
    elif port_dir is not None:
        inferred = infer_makefile_distfiles(port_dir, args.openbsd_version)
        for fn, urls in inferred:
            dest = cache_dist / fn
            print(f"[gen-cargo] fetching/verifying {fn}...")
            b64, _hx, sz = download_to_cache(dest, urls)
            dist_entries.append((fn, b64, sz))
            if primary_tarball is None:
                primary_tarball = dest

    if args.cargo_lock:
        lock_txt = pathlib.Path(args.cargo_lock).read_text(encoding="utf-8")
    elif primary_tarball is not None:
        lock_txt = extract_cargo_lock_from_tarball(primary_tarball, args.cargo_lock_subpath)
    else:
        die("provide --cargo-lock, --port-dir, or --distfile so Cargo.lock can be read")

    lock_data = tomllib.loads(lock_txt)
    crates_io_pkgs: List[Tuple[str, str, Optional[str]]] = []
    git_pkgs: List[Tuple[str, str, str]] = []
    seen_pairs: set[Tuple[str, str]] = set()

    for pkg in lock_data.get("package", []):
        cname = str(pkg.get("name", "")).strip()
        cver = str(pkg.get("version", "")).strip()
        src = str(pkg.get("source", "")).strip()
        if not cname or not cver or not src:
            continue
        if src == "registry+https://github.com/rust-lang/crates.io-index":
            if (cname, cver) not in seen_pairs:
                seen_pairs.add((cname, cver))
                cksum = pkg.get("checksum")
                crates_io_pkgs.append((cname, cver, str(cksum) if cksum else None))
        elif src.startswith("git+"):
            git_pkgs.append((cname, cver, src))

    crates_io_pkgs.sort(key=lambda r: (r[0], r[1]))
    if git_pkgs:
        for gname, gver, gsrc in git_pkgs:
            print(
                f"[gen-cargo] NOTE: git dependency {gname} {gver} ({gsrc}) -> "
                f"ensure DIST_TUPLE extracts to modcargo-crates/{gname}-{gver}",
                file=sys.stderr,
            )

    print(f"[gen-cargo] downloading & indexing {len(crates_io_pkgs)} crates.io archive(s) (jobs={args.jobs})...")

    def _process_crate(item: Tuple[str, str, Optional[str]]) -> Tuple[str, str, str, str, int]:
        cname, cver, exp_hex = item
        rel = f"cargo/{cname}-{cver}.tar.gz"
        dest = cache_dist / rel
        urls = [
            f"https://static.crates.io/crates/{cname}/{cname}-{cver}.crate",
            f"https://crates.io/api/v1/crates/{cname}/{cver}/download",
            f"https://cdn.openbsd.org/pub/OpenBSD/distfiles/{rel}",
        ]
        b64, _hx, sz = download_to_cache(dest, urls, expected_hex=exp_hex)
        lic = read_crate_license(dest, cname, cver)
        return cname, cver, lic, b64, sz

    crate_results: List[Tuple[str, str, str, str, int]] = []
    workers = max(1, min(args.jobs, 32, max(1, len(crates_io_pkgs))))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        for res in pool.map(_process_crate, crates_io_pkgs):
            crate_results.append(res)

    crates_lines = [
        f"MODCARGO_CRATES +=\t{cname}\t{cver}\t# {lic}"
        for cname, cver, lic, _b64, _sz in crate_results
    ]
    out_crates.parent.mkdir(parents=True, exist_ok=True)
    out_crates.write_text("\n".join(crates_lines) + ("\n" if crates_lines else ""), encoding="utf-8")

    all_dist: List[Tuple[str, str, int]] = list(dist_entries)
    for cname, cver, _lic, b64, sz in crate_results:
        all_dist.append((f"cargo/{cname}-{cver}.tar.gz", b64, sz))
    all_dist.sort(key=lambda x: x[0])

    sha_lines = [f"SHA256 ({fn}) = {b64}" for fn, b64, _sz in all_dist]
    sz_lines = [f"SIZE ({fn}) = {sz}" for fn, _b64, sz in all_dist]
    out_distinfo.parent.mkdir(parents=True, exist_ok=True)
    out_distinfo.write_text("\n".join(sha_lines + sz_lines) + "\n", encoding="utf-8")

    print(
        f"[gen-cargo] wrote {out_crates} ({len(crates_lines)} crates) and "
        f"{out_distinfo} ({len(all_dist)} distfiles)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
