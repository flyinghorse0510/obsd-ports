#!/usr/bin/env python3
"""
audit_extra_ports.py -- Audit `extra/` OpenBSD-style ports, `config/extra/index.tsv`,
and 3D matrix `port.toml` coordinates across both `ports/**` and `extra/**`.

Enforces:
  1. `config/extra/index.tsv` header & row schema (`port`, `category`, `pkgname_base`,
     `upstream_url`, `jit_free`, `versions`, `backends`, `pals`, `notes`).
  2. Official OpenBSD category membership (derived from `config/versions/8.0-catalog.tsv`)
     and zero `<category>/<name>` collisions between `ports/` and `extra/`.
  3. Complete OpenBSD port anatomy in every `extra/<port>/` directory:
       - `Makefile` (`COMMENT`, `CATEGORIES`, `HOMEPAGE`, `PERMIT_PACKAGE`, `.include <bsd.port.mk>`,
         plus `.include "crates.inc"` when `crates.inc` is present)
       - `distinfo` (paired valid 32-byte base64/hex `SHA256` + positive `SIZE` for every entry)
       - `crates.inc` <-> `distinfo` `cargo/*.tar.gz` exact bijection when `crates.inc` exists
       - Non-empty `pkg/DESCR` and `pkg/PLIST`
       - Unified diff headers (`--- ` and `+++ `) on any `patches/patch-*`, with zero `.orig`/`.rej`
  4. Valid 3D matrix keys & values in `port.toml` across BOTH `ports/**` and `extra/**`
     (`[versions.*]`, `[backends.*]`, `[pals.*]`, `[targets.*]`, `[matrix.*]`, and
     `only_for_*` / `not_for_*` / `only_versions`).
  5. Zero tracked build/vendor artifacts under `extra/`.
"""
from __future__ import annotations

import pathlib
import re
import subprocess
import sys
import tomllib
from typing import Any, Dict, List, Set, Tuple

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
if str(REPO_ROOT / "tools") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "tools"))

import build_ports as bp  # type: ignore

FORBIDDEN_EXTRA_NAMES = {
    "target",
    "work",
    "modcargo-crates",
    ".cargo-home",
    "__pycache__",
}


def fail(msg: str) -> "NoReturn":
    sys.stderr.write(f"extra ports audit failed: {msg}\n")
    raise SystemExit(1)


def load_valid_coordinates(root: pathlib.Path) -> Tuple[Set[str], Set[str], Set[str], Set[str], Set[str]]:
    versions: Set[str] = set()
    for raw in (root / "config/versions/index.tsv").read_text(encoding="utf-8").splitlines():
        s = raw.strip()
        if not s or s.startswith("#") or s.startswith("version\t"):
            continue
        versions.add(raw.split("\t")[0].strip())

    backends: Set[str] = set()
    pals: Set[str] = set()
    targets: Set[str] = set()
    for raw in (root / "config/matrix/index.tsv").read_text(encoding="utf-8").splitlines():
        s = raw.strip()
        if not s or s.startswith("#") or s.startswith("backend\t"):
            continue
        cols = raw.split("\t")
        b, p = cols[0].strip(), cols[1].strip()
        backends.add(b)
        pals.add(p)
        targets.add(f"{b}/{p}")

    matrix_3d = {f"{v}/{t}" for v in versions for t in targets}
    return versions, backends, pals, targets, matrix_3d


def load_official_categories(root: pathlib.Path) -> Set[str]:
    cat_tsv = root / "config/versions/8.0-catalog.tsv"
    if not cat_tsv.is_file():
        fail(f"missing {cat_tsv}")
    cats: Set[str] = set()
    for raw in cat_tsv.read_text(encoding="utf-8").splitlines():
        if not raw or raw.startswith("#") or raw.startswith("portpath\t"):
            continue
        portpath = raw.split("\t", 1)[0].strip()
        if "/" in portpath:
            cats.add(portpath.split("/", 1)[0])
    return cats


def validate_gate_fields(
    table: Dict[str, Any],
    ctx_label: str,
    valid_versions: Set[str],
    valid_backends: Set[str],
    valid_pals: Set[str],
    valid_targets: Set[str],
) -> None:
    checks = (
        ("only_versions", valid_versions),
        ("only_for_versions", valid_versions),
        ("not_for_versions", valid_versions),
        ("only_for_backends", valid_backends),
        ("not_for_backends", valid_backends),
        ("only_for_pals", valid_pals),
        ("not_for_pals", valid_pals),
        ("only_for_targets", valid_targets),
        ("not_for_targets", valid_targets),
    )
    for field, allowed in checks:
        if field not in table or table[field] is None:
            continue
        val = table[field]
        if not isinstance(val, list) or not all(isinstance(x, str) for x in val):
            fail(f"{ctx_label}: `{field}` must be a list of strings")
        bad = [x for x in val if x.strip() not in allowed]
        if bad:
            fail(f"{ctx_label}: `{field}` contains invalid coordinate(s) {bad} (allowed: {sorted(allowed)})")


def audit_port_toml_matrix(
    toml_path: pathlib.Path,
    valid_versions: Set[str],
    valid_backends: Set[str],
    valid_pals: Set[str],
    valid_targets: Set[str],
    valid_matrix_3d: Set[str],
) -> Dict[str, Any]:
    try:
        raw = tomllib.loads(toml_path.read_text(encoding="utf-8"))
    except Exception as exc:
        fail(f"{toml_path}: invalid TOML: {exc}")

    label = toml_path.relative_to(REPO_ROOT).as_posix()
    validate_gate_fields(raw, label, valid_versions, valid_backends, valid_pals, valid_targets)

    table_specs = (
        ("versions", valid_versions),
        ("backends", valid_backends),
        ("pals", valid_pals),
        ("targets", valid_targets),
        ("matrix", valid_matrix_3d),
    )
    for tbl_name, allowed_keys in table_specs:
        if tbl_name not in raw:
            continue
        tbl = raw[tbl_name]
        if not isinstance(tbl, dict):
            fail(f"{label}: `[{tbl_name}]` must be a TOML table")
        for k, sub in tbl.items():
            if k not in allowed_keys:
                fail(f"{label}: invalid `[{tbl_name}.{k!r}]` key (allowed: {sorted(allowed_keys)})")
            if not isinstance(sub, dict):
                fail(f"{label}: `[{tbl_name}.{k!r}]` must be a table")
            validate_gate_fields(
                sub,
                f"{label}[{tbl_name}.{k}]",
                valid_versions,
                valid_backends,
                valid_pals,
                valid_targets,
            )
    return raw


def audit_single_extra_port(
    port_dir: pathlib.Path,
    rel_port: str,
    official_cats: Set[str],
    declared_ports: Set[str],
    valid_versions: Set[str],
    valid_backends: Set[str],
    valid_pals: Set[str],
    valid_targets: Set[str],
    valid_matrix_3d: Set[str],
) -> None:
    parts = rel_port.split("/")
    if len(parts) not in (2, 3):
        fail(f"extra/{rel_port}: expected 2- or 3-level <category>/<name> path")
    cat = parts[0]
    if cat not in official_cats:
        fail(f"extra/{rel_port}: category '{cat}' is not in official OpenBSD categories")
    if rel_port in declared_ports:
        fail(f"extra/{rel_port}: collides with existing ports/{rel_port}")

    # 1. port.toml
    toml_path = port_dir / "port.toml"
    if not toml_path.is_file():
        fail(f"extra/{rel_port}: missing port.toml")
    audit_port_toml_matrix(toml_path, valid_versions, valid_backends, valid_pals, valid_targets, valid_matrix_3d)

    # 2. Makefile
    mk_path = port_dir / "Makefile"
    if not mk_path.is_file():
        fail(f"extra/{rel_port}: missing OpenBSD Makefile")
    mk_raw = mk_path.read_text(encoding="utf-8")
    if ".include <bsd.port.mk>" not in mk_raw:
        fail(f"extra/{rel_port}/Makefile: missing `.include <bsd.port.mk>`")

    crates_inc = port_dir / "crates.inc"
    if crates_inc.is_file() and '.include "crates.inc"' not in mk_raw:
        fail(f"extra/{rel_port}/Makefile: crates.inc exists without `.include \"crates.inc\"`")

    mk_env = bp.parse_openbsd_makefile_vars([mk_path])
    for req_var in ("COMMENT", "CATEGORIES", "HOMEPAGE", "PERMIT_PACKAGE"):
        val = bp.expand_openbsd_expr(mk_env.get(req_var, mk_env.get(f"{req_var}-main", "")), mk_env).strip()
        if not val:
            fail(f"extra/{rel_port}/Makefile: missing required OpenBSD variable `{req_var}`")
    if cat not in bp.expand_openbsd_expr(mk_env.get("CATEGORIES", ""), mk_env).split():
        fail(f"extra/{rel_port}/Makefile: CATEGORIES does not include '{cat}'")

    # 3. distinfo (+ crates.inc bijection)
    distinfo_path = port_dir / "distinfo"
    if not distinfo_path.is_file():
        fail(f"extra/{rel_port}: missing distinfo")
    sha_map: Dict[str, str] = {}
    sz_map: Dict[str, int] = {}
    for idx, ln in enumerate(distinfo_path.read_text(encoding="utf-8").splitlines(), start=1):
        s = ln.strip()
        if not s or s.startswith("#"):
            continue
        m_sha = bp.DISTINFO_SHA256_RE.match(s)
        if m_sha:
            fn, d_str = m_sha.group(1).strip(), m_sha.group(2).strip()
            try:
                sha_map[fn] = bp.decode_openbsd_sha256(d_str)
            except ValueError as exc:
                fail(f"extra/{rel_port}/distinfo:{idx}: {exc}")
            continue
        m_sz = bp.DISTINFO_SIZE_RE.match(s)
        if m_sz:
            fn, sz_s = m_sz.group(1).strip(), m_sz.group(2).strip()
            sz_val = int(sz_s)
            if sz_val <= 0:
                fail(f"extra/{rel_port}/distinfo:{idx}: non-positive SIZE for {fn}")
            sz_map[fn] = sz_val
            continue
        fail(f"extra/{rel_port}/distinfo:{idx}: malformed line: {s}")

    if not sha_map:
        fail(f"extra/{rel_port}/distinfo: contains 0 distfiles")
    if set(sha_map.keys()) != set(sz_map.keys()):
        diff = sorted(set(sha_map.keys()) ^ set(sz_map.keys()))
        fail(f"extra/{rel_port}/distinfo: mismatched SHA256 vs SIZE entries: {diff[:10]}")

    if crates_inc.is_file():
        cargo_map = bp.parse_modcargo_crates_map(mk_env)
        dist_cargo = {fn for fn in sha_map if fn.startswith("cargo/")}
        expected_cargo = set(cargo_map.keys())
        if dist_cargo != expected_cargo:
            missing_in_dist = sorted(expected_cargo - dist_cargo)[:5]
            extra_in_dist = sorted(dist_cargo - expected_cargo)[:5]
            fail(
                f"extra/{rel_port}: crates.inc <-> distinfo mismatch "
                f"(missing_in_distinfo={missing_in_dist}, extra_in_distinfo={extra_in_dist})"
            )

    # 4. pkg/DESCR & pkg/PLIST
    descr_p = port_dir / "pkg/DESCR"
    plist_p = port_dir / "pkg/PLIST"
    if not descr_p.is_file() or not descr_p.read_text(encoding="utf-8").strip():
        fail(f"extra/{rel_port}: missing or empty pkg/DESCR")
    if not plist_p.is_file() or not plist_p.read_text(encoding="utf-8").strip():
        fail(f"extra/{rel_port}: missing or empty pkg/PLIST")

    # 5. patches/patch-*
    patches_dir = port_dir / "patches"
    if patches_dir.is_dir():
        for pf in sorted(patches_dir.iterdir()):
            if pf.name.endswith((".orig", ".rej", "~")) or not pf.name.startswith("patch-"):
                fail(f"extra/{rel_port}/patches/{pf.name}: invalid file in patches/ (expected patch-*)")
            ptxt = pf.read_text(encoding="utf-8", errors="replace")
            if "--- " not in ptxt or "+++ " not in ptxt:
                fail(f"extra/{rel_port}/patches/{pf.name}: missing unified diff `--- `/`+++ ` headers")


def audit_extra_manifest(
    root: pathlib.Path,
    official_cats: Set[str],
    extra_ports_on_disk: Set[str],
    valid_versions: Set[str],
    valid_backends: Set[str],
    valid_pals: Set[str],
) -> int:
    idx_path = root / "config/extra/index.tsv"
    if not idx_path.is_file():
        fail("missing config/extra/index.tsv")

    expected_hdr = "port\tcategory\tpkgname_base\tupstream_url\tjit_free\tversions\tbackends\tpals\tnotes"
    saw_hdr = False
    manifest_ports: Set[str] = set()

    def _check_axis_spec(val: str, allowed: Set[str], col_name: str, port_id: str) -> None:
        s = val.strip()
        if s == "*":
            return
        items = [x.strip() for x in s.split(",") if x.strip()]
        if not items or any(x not in allowed for x in items):
            fail(f"config/extra/index.tsv ({port_id}): invalid {col_name}={val!r} (allowed: '*' or {sorted(allowed)})")

    for line_no, raw in enumerate(idx_path.read_text(encoding="utf-8").splitlines(), start=1):
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        if raw == expected_hdr:
            saw_hdr = True
            continue
        cols = raw.split("\t")
        if len(cols) < 9:
            fail(f"config/extra/index.tsv:{line_no}: expected 9 TSV columns, got {len(cols)}")
        port_id, cat, pkg_base, url, jit_free, vers, bcks, pals, _notes = cols[:9]
        if port_id in manifest_ports:
            fail(f"config/extra/index.tsv:{line_no}: duplicate port '{port_id}'")
        manifest_ports.add(port_id)
        if port_id not in extra_ports_on_disk:
            fail(f"config/extra/index.tsv:{line_no}: '{port_id}' does not exist under extra/{port_id}")
        if cat not in official_cats or not port_id.startswith(f"{cat}/"):
            fail(f"config/extra/index.tsv:{line_no}: invalid category '{cat}' for '{port_id}'")
        if not pkg_base.strip() or not url.startswith(("https://", "http://")):
            fail(f"config/extra/index.tsv:{line_no}: invalid pkgname_base or upstream_url for '{port_id}'")
        if jit_free.strip().lower() not in ("yes", "true", "1"):
            fail(f"config/extra/index.tsv:{line_no}: '{port_id}' must declare jit_free=yes")
        _check_axis_spec(vers, valid_versions, "versions", port_id)
        _check_axis_spec(bcks, valid_backends, "backends", port_id)
        _check_axis_spec(pals, valid_pals, "pals", port_id)

    if not saw_hdr:
        fail(f"config/extra/index.tsv: missing canonical header `{expected_hdr}`")
    return len(manifest_ports)


def main() -> int:
    valid_versions, valid_backends, valid_pals, valid_targets, valid_matrix_3d = load_valid_coordinates(REPO_ROOT)
    official_cats = load_official_categories(REPO_ROOT)

    ports_root = REPO_ROOT / "ports"
    extra_root = REPO_ROOT / "extra"
    if not extra_root.is_dir():
        fail("missing extra/ directory")

    # Audit 3D matrix keys across all `ports/**/port.toml`
    declared_ports: Set[str] = set()
    if ports_root.is_dir():
        for pt in sorted(ports_root.rglob("port.toml")):
            rel = pt.parent.relative_to(ports_root).as_posix()
            declared_ports.add(rel)
            audit_port_toml_matrix(pt, valid_versions, valid_backends, valid_pals, valid_targets, valid_matrix_3d)

    # Reject forbidden build artifacts under `extra/` (both untracked working tree and git-tracked)
    for dirpath, dirnames, filenames in bp.os.walk(extra_root):
        dp = pathlib.Path(dirpath)
        for d in list(dirnames):
            if d in FORBIDDEN_EXTRA_NAMES:
                fail(f"forbidden build directory inside extra/: {(dp / d).relative_to(REPO_ROOT)}")
        for fn in filenames:
            if fn.endswith((".o", ".a", ".wasm", ".pyc", ".orig", ".rej")):
                fail(f"forbidden build/temp artifact inside extra/: {(dp / fn).relative_to(REPO_ROOT)}")

    tracked = subprocess.check_output(["git", "-C", str(REPO_ROOT), "ls-files", "--", "extra"], text=True).splitlines()
    for tr in tracked:
        if any(seg in FORBIDDEN_EXTRA_NAMES for seg in tr.split("/")) or tr.endswith((".o", ".a", ".wasm", ".pyc")):
            fail(f"forbidden artifact tracked in Git: {tr}")

    # Discover & audit every port under `extra/`
    extra_ports: Dict[str, pathlib.Path] = {}
    for pt in sorted(extra_root.rglob("port.toml")):
        pdir = pt.parent
        rel = pdir.relative_to(extra_root).as_posix()
        extra_ports[rel] = pdir

    # Also ensure no orphan subdirectory in `extra/` exists without a `port.toml`
    for top in sorted(extra_root.iterdir()):
        if top.name == "README.md" and top.is_file():
            continue
        if top.is_file():
            fail(f"unexpected top-level file in extra/: extra/{top.name}")
        if top.is_dir():
            if top.name not in official_cats:
                fail(f"extra/{top.name}: not an official OpenBSD ports category")
            sub_tomls = list(top.rglob("port.toml"))
            if not sub_tomls:
                fail(f"extra/{top.name}: empty or missing port.toml under category directory")

    for rel, pdir in sorted(extra_ports.items()):
        audit_single_extra_port(
            port_dir=pdir,
            rel_port=rel,
            official_cats=official_cats,
            declared_ports=declared_ports,
            valid_versions=valid_versions,
            valid_backends=valid_backends,
            valid_pals=valid_pals,
            valid_targets=valid_targets,
            valid_matrix_3d=valid_matrix_3d,
        )

    manifest_count = audit_extra_manifest(
        REPO_ROOT,
        official_cats,
        set(extra_ports.keys()),
        valid_versions,
        valid_backends,
        valid_pals,
    )

    print(
        f"extra ports audit: ok ({len(declared_ports)} ports/ recipes, "
        f"{len(extra_ports)} extra/ recipes, {manifest_count} indexed, {len(official_cats)} categories)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
