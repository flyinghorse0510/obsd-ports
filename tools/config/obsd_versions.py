#!/usr/bin/env python3
"""
obsd_versions.py -- Single source of truth for the OpenBSD release axis.

Every builder, adapter, test and audit in obsd-ports resolves the set of
releases from `config/versions/index.tsv` through this module instead of
hardcoding a release list. The default release is the newest `verified` row.

When a libobsdcompat checkout is declared, `check_against_libobsdcompat()`
additionally cross-checks each release against libobsdcompat's
`config/personalities/openbsd/versions/index.tsv` (must be `verified` there
too) and against the vendor `sys/sys/param.h` `#define OpenBSD <osrev>`.

Deliberately stdlib-only and Python 3.9 compatible so metadata targets
(`make audit`, `make list-catalog`) keep working on the stock macOS python3.

CLI:
  obsd_versions.py list            # verified releases, ascending, one per line
  obsd_versions.py default         # default release (newest verified)
  obsd_versions.py resolve SPEC    # SPEC = "" | all | "7.9,8.0" | "7.9 8.0"
  obsd_versions.py osrev VERSION   # osrev_int column
  obsd_versions.py check [--libobsdcompat-root DIR]
"""
from __future__ import annotations

import argparse
import os
import pathlib
import re
import sys
from typing import Dict, List, Optional, Tuple

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
VERSIONS_INDEX = REPO_ROOT / "config/versions/index.tsv"
LIBOBSDCOMPAT_VERSIONS_INDEX = pathlib.PurePosixPath("config/personalities/openbsd/versions/index.tsv")
PARAM_H_OSREV_RE = re.compile(r"^#define\s+OpenBSD\s+(\d{6})\b", re.MULTILINE)
VERSION_RE = re.compile(r"^\d+\.\d+$")


class ReleaseConfigError(Exception):
    pass


def version_key(version: str) -> Tuple[int, ...]:
    if not VERSION_RE.match(version):
        raise ReleaseConfigError(f"malformed OpenBSD release '{version}' (expected <major>.<minor>)")
    return tuple(int(p) for p in version.split("."))


def _read_tsv(path: pathlib.Path) -> List[Dict[str, str]]:
    if not path.is_file():
        raise ReleaseConfigError(f"missing release manifest {path}")
    header: Optional[List[str]] = None
    rows: List[Dict[str, str]] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.rstrip("\r\n")
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        cols = line.split("\t")
        if header is None:
            header = cols
            if header[0] != "version":
                raise ReleaseConfigError(f"{path}: first non-comment row must be the 'version' header")
            continue
        rows.append({k: (cols[i] if i < len(cols) else "") for i, k in enumerate(header)})
    return rows


def load_releases(index: pathlib.Path = VERSIONS_INDEX) -> List[Dict[str, str]]:
    rows = _read_tsv(index)
    seen = set()
    for r in rows:
        version_key(r["version"])
        if r["version"] in seen:
            raise ReleaseConfigError(f"{index}: duplicate release row {r['version']}")
        seen.add(r["version"])
    return sorted(rows, key=lambda r: version_key(r["version"]))


def verified_versions(index: pathlib.Path = VERSIONS_INDEX) -> List[str]:
    out = [r["version"] for r in load_releases(index) if r.get("status", "") == "verified"]
    if not out:
        raise ReleaseConfigError(f"{index}: no verified releases declared")
    return out


def default_version(index: pathlib.Path = VERSIONS_INDEX) -> str:
    return verified_versions(index)[-1]


def env_or_default_version() -> str:
    v = os.environ.get("OPENBSD_VERSION", "").strip()
    return v or default_version()


def release_row(version: str, index: pathlib.Path = VERSIONS_INDEX) -> Dict[str, str]:
    for r in load_releases(index):
        if r["version"] == version:
            return r
    raise ReleaseConfigError(
        f"OpenBSD release '{version}' is not declared in {index} "
        f"(declared: {', '.join(r['version'] for r in load_releases(index))})"
    )


def osrev_int(version: str) -> int:
    return int(release_row(version)["osrev_int"])


def require_verified(version: str) -> str:
    vers = verified_versions()
    if version not in vers:
        raise ReleaseConfigError(
            f"OpenBSD release '{version}' is not a verified release in {VERSIONS_INDEX.relative_to(REPO_ROOT)} "
            f"(verified: {', '.join(vers)})"
        )
    return version


def resolve_versions(spec: Optional[str]) -> List[str]:
    """`""`/`all` -> every verified release; otherwise comma/space separated list."""
    s = (spec or "").strip()
    if s in ("", "all"):
        return verified_versions()
    out: List[str] = []
    for tok in re.split(r"[,\s]+", s):
        if tok and tok not in out:
            out.append(require_verified(tok))
    return out


def add_version_argument(ap: argparse.ArgumentParser, *, allow_all: bool, env_default: bool = True) -> None:
    """Uniform `--openbsd-version` flag for tools/tests (no hardcoded choices)."""
    default = os.environ.get("OPENBSD_VERSION", "").strip() if env_default else ""
    if not default:
        default = "all" if allow_all else default_version()
    vers = ", ".join(verified_versions())
    ap.add_argument(
        "--openbsd-version",
        default=default,
        help=(f"OpenBSD release(s) from config/versions/index.tsv ({vers}"
              + (", comma/space separated, or all" if allow_all else "")
              + f"; default: {default})"),
    )


# --------------------------------------------------------------------------
# libobsdcompat cross-checks
# --------------------------------------------------------------------------

def libobsdcompat_verified_versions(obsd_root: pathlib.Path) -> List[str]:
    idx = obsd_root / LIBOBSDCOMPAT_VERSIONS_INDEX
    return [r["version"] for r in load_releases(idx) if r.get("status", "") == "verified"]


def vendor_param_osrev(obsd_root: pathlib.Path, version: str) -> Optional[int]:
    p = obsd_root / "vendor/openbsd/versions" / version / "src/sys/sys/param.h"
    if not p.is_file():
        return None
    m = PARAM_H_OSREV_RE.search(p.read_text(encoding="utf-8", errors="replace"))
    return int(m.group(1)) if m else None


def check_repo_consistency() -> List[str]:
    """index.tsv <-> config/versions/<v>.mk agreement (no libobsdcompat needed)."""
    errors: List[str] = []
    for r in load_releases():
        v = r["version"]
        mk = REPO_ROOT / "config/versions" / f"{v}.mk"
        if not mk.is_file():
            errors.append(f"missing config/versions/{v}.mk")
            continue
        mk_vars = {}
        for line in mk.read_text(encoding="utf-8").splitlines():
            m = re.match(r"^\s*([A-Z0-9_]+)\s*:?=\s*(.*?)\s*$", line)
            if m:
                mk_vars[m.group(1)] = m.group(2)
        for col, var in (("osrev_int", "OPENBSD_OSREV_INT"), ("api_hex", "OPENBSD_API_HEX"),
                         ("ports_sha256", "OPENBSD_PORTS_SHA256"), ("ports_url", "OPENBSD_PORTS_URL")):
            if mk_vars.get(var, "") != r.get(col, ""):
                errors.append(f"{v}: index.tsv {col}={r.get(col, '')!r} != {v}.mk {var}={mk_vars.get(var, '')!r}")
        if mk_vars.get("OPENBSD_RELEASE", "") != v:
            errors.append(f"{v}: {v}.mk OPENBSD_RELEASE={mk_vars.get('OPENBSD_RELEASE', '')!r}")
        osrev = r.get("osrev_int", "")
        if not re.match(r"^\d{6}$", osrev):
            errors.append(f"{v}: osrev_int {osrev!r} is not YYYYMM")
    return errors


def check_against_libobsdcompat(obsd_root: pathlib.Path) -> List[str]:
    errors: List[str] = []
    try:
        lib_vers = libobsdcompat_verified_versions(obsd_root)
    except ReleaseConfigError as exc:
        return [str(exc)]
    for v in verified_versions():
        if v not in lib_vers:
            errors.append(f"{v}: verified in obsd-ports but not verified in {obsd_root / LIBOBSDCOMPAT_VERSIONS_INDEX}")
        vendor = vendor_param_osrev(obsd_root, v)
        if vendor is None:
            errors.append(f"{v}: cannot read '#define OpenBSD' from libobsdcompat vendor sys/sys/param.h")
        elif vendor != osrev_int(v):
            errors.append(f"{v}: index.tsv osrev_int={osrev_int(v)} but vendor sys/sys/param.h says {vendor}")
    return errors


def _locate_libobsdcompat_quiet() -> Optional[pathlib.Path]:
    env = os.environ.get("LIBOBSDCOMPAT_ROOT", "").strip()
    cand: Optional[str] = env or None
    marker = REPO_ROOT / ".libobsdcompat-root"
    if cand is None and marker.is_file():
        for line in marker.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                cand = line if line.startswith("/") else str(REPO_ROOT / line)
                break
    if cand and (pathlib.Path(cand) / "vendor/openbsd/versions").is_dir():
        return pathlib.Path(cand).resolve()
    return None


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="OpenBSD release axis (config/versions/index.tsv)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list")
    sub.add_parser("default")
    p_res = sub.add_parser("resolve")
    p_res.add_argument("spec", nargs="?", default="")
    p_os = sub.add_parser("osrev")
    p_os.add_argument("version")
    p_chk = sub.add_parser("check")
    p_chk.add_argument("--libobsdcompat-root", default="")
    p_chk.add_argument("--require-libobsdcompat", action="store_true")
    args = ap.parse_args(argv)
    try:
        if args.cmd == "list":
            print("\n".join(verified_versions()))
        elif args.cmd == "default":
            print(default_version())
        elif args.cmd == "resolve":
            print("\n".join(resolve_versions(args.spec)))
        elif args.cmd == "osrev":
            print(osrev_int(args.version))
        elif args.cmd == "check":
            errors = check_repo_consistency()
            root = pathlib.Path(args.libobsdcompat_root).resolve() if args.libobsdcompat_root else _locate_libobsdcompat_quiet()
            if root is None:
                if args.require_libobsdcompat:
                    errors.append("no libobsdcompat checkout declared (LIBOBSDCOMPAT_ROOT / .libobsdcompat-root)")
                else:
                    print("release axis: libobsdcompat not declared; skipping vendor param.h / index.tsv cross-check")
            else:
                errors += check_against_libobsdcompat(root)
            if errors:
                for e in errors:
                    sys.stderr.write(f"release axis check failed: {e}\n")
                return 1
            print(f"release axis: ok ({', '.join(f'{v}={osrev_int(v)}' for v in verified_versions())}; default {default_version()}"
                  + (f"; cross-checked {root}" if root else "") + ")")
    except ReleaseConfigError as exc:
        sys.stderr.write(f"obsd_versions: {exc}\n")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
