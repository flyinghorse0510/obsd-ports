#!/usr/bin/env bash
# audit_matrix_seams.sh -- Verify release axis (`7.8`, `7.9`, `8.0`) and 7-cell
# Backend x PAL matrix (`emulate/{emscripten,wasi,darwin,ios}`,
# `translate/{darwin,ios,linux}` -> 3 x 7 = 21 lanes) across manifests, Make
# fragments, target adapter scripts, and `sdk/rust/` target mappings.
set -euo pipefail

repo_root=${REPO_ROOT:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}
cd "$repo_root"

python3 -I - <<'PY_EOF'
import json
import pathlib
import subprocess
import sys

root = pathlib.Path(".")

# 1. Verify config/versions/index.tsv
ver_rows = []
for raw in (root / "config/versions/index.tsv").read_text(encoding="utf-8").splitlines():
    s = raw.strip()
    if not s or s.startswith("#") or s.startswith("version\t"):
        continue
    cols = raw.split("\t")
    ver_rows.append(cols)
    ver, _st, _hex, _osrev, _url, sha, vdir, cat = cols[:8]
    if not (root / f"config/versions/{ver}.mk").is_file():
        raise SystemExit(f"matrix audit failed: missing config/versions/{ver}.mk")
    if not (root / vdir).is_dir():
        raise SystemExit(f"matrix audit failed: missing vendor dir {vdir}")
    if not (root / cat).is_file():
        raise SystemExit(f"matrix audit failed: missing release catalog {cat}")
    if len(sha) != 64:
        raise SystemExit(f"matrix audit failed: invalid SHA256 for {ver}")

if len(ver_rows) < 3:
    raise SystemExit("matrix audit failed: expected at least OpenBSD 7.8, 7.9, and 8.0 in config/versions/index.tsv")

# 2. Verify config/matrix/index.tsv (all 7 cells)
expected_cells = {
    ("emulate", "emscripten"),
    ("emulate", "wasi"),
    ("emulate", "darwin"),
    ("emulate", "ios"),
    ("translate", "darwin"),
    ("translate", "ios"),
    ("translate", "linux"),
}
mat_rows = []
seen_cells = set()
for raw in (root / "config/matrix/index.tsv").read_text(encoding="utf-8").splitlines():
    s = raw.strip()
    if not s or s.startswith("#") or s.startswith("backend\t"):
        continue
    cols = raw.split("\t")
    mat_rows.append(cols)
    backend, pal, _status, _arch, _fmt, adapter_dir = cols[:6]
    seen_cells.add((backend, pal))
    if not (root / f"config/matrix/backends/{backend}.mk").is_file():
        raise SystemExit(f"matrix audit failed: missing backend fragment for {backend}")
    if not (root / f"config/matrix/pals/{pal}.mk").is_file():
        raise SystemExit(f"matrix audit failed: missing PAL fragment for {pal}")
    if not (root / adapter_dir).is_dir():
        raise SystemExit(f"matrix audit failed: missing adapter dir {adapter_dir}")
    if not (root / adapter_dir / "README.md").is_file():
        raise SystemExit(f"matrix audit failed: missing {adapter_dir}/README.md")
    pkg_script = root / adapter_dir / f"package_{'wasm' if pal in ('emscripten', 'wasi') else pal}.py"
    if not pkg_script.is_file():
        raise SystemExit(f"matrix audit failed: missing adapter script {pkg_script}")

if seen_cells != expected_cells:
    raise SystemExit(f"matrix audit failed: expected 7 cells {sorted(expected_cells)}, got {sorted(seen_cells)}")

# 3. Verify all 3 x 7 = 21 lanes resolve cleanly in `sdk/rust/obsd_rust.py`
obsd_rust = root / "sdk/rust/obsd_rust.py"
lane_count = 0
for ver_cols in ver_rows:
    ver = ver_cols[0]
    for mat_cols in mat_rows:
        backend, pal = mat_cols[0], mat_cols[1]
        out = subprocess.check_output(
            [
                sys.executable,
                "-I",
                str(obsd_rust),
                "target-info",
                "--openbsd-version",
                ver,
                "--backend",
                backend,
                "--pal",
                pal,
            ],
            text=True,
        )
        info = json.loads(out)
        if not info.get("target_name") or not info.get("jit_free"):
            raise SystemExit(f"matrix audit failed: invalid Rust target info for {ver}/{backend}/{pal}: {info}")
        lane_count += 1

print(
    f"matrix seams audit: ok ({len(ver_rows)} releases x {len(mat_rows)} backend/PAL cells = {lane_count} lanes verified)"
)
PY_EOF
