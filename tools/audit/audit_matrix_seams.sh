#!/usr/bin/env bash
# audit_matrix_seams.sh -- Verify the release axis (config/versions/index.tsv) and
# canonical 5-cell Backend x PAL matrix (config/matrix/index.tsv:
# emulate/{emscripten,wasi,darwin} + translate/{darwin,linux}) across manifests,
# Make fragments, target adapter scripts, and sdk/rust/ target mappings.
# tools/config/obsd_versions.py also checks index.tsv <-> <ver>.mk agreement and,
# when libobsdcompat is declared, the vendor sys/sys/param.h osrev and that every
# release is verified in libobsdcompat's own versions/index.tsv.
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

if not ver_rows:
    raise SystemExit("matrix audit failed: no releases declared in config/versions/index.tsv")

# 2. Verify config/matrix/index.tsv (canonical 5 cells)
expected_cells = {
    ("emulate", "emscripten"),
    ("emulate", "wasi"),
    ("emulate", "darwin"),
    ("translate", "darwin"),
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
    raise SystemExit(f"matrix audit failed: expected 5 cells {sorted(expected_cells)}, got {sorted(seen_cells)}")

# 3. Verify all releases x 5 cells (= 15 matrix cells, including Darwin COMPAT_SDK variants) in `sdk/rust/obsd_rust.py`
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
        if (backend, pal) == ("emulate", "darwin"):
            if info["target_name"] != "aarch64-apple-ios-sim":
                raise SystemExit(f"matrix audit failed: expected aarch64-apple-ios-sim default for emulate/darwin, got {info['target_name']}")
            out_ios = subprocess.check_output(
                [
                    sys.executable,
                    "-I",
                    str(obsd_rust),
                    "target-info",
                    "--openbsd-version",
                    ver,
                    "--backend",
                    "emulate",
                    "--pal",
                    "darwin",
                    "--sdk",
                    "iphoneos",
                ],
                text=True,
            )
            if json.loads(out_ios)["target_name"] != "aarch64-apple-ios":
                raise SystemExit("matrix audit failed: expected aarch64-apple-ios for emulate/darwin --sdk iphoneos")
        elif (backend, pal) == ("translate", "darwin"):
            if info["target_name"] != "aarch64-apple-darwin":
                raise SystemExit(f"matrix audit failed: expected aarch64-apple-darwin for translate/darwin, got {info['target_name']}")
        lane_count += 1

print(
    f"matrix seams audit: ok ({len(ver_rows)} releases x {len(mat_rows)} backend/PAL cells = {lane_count} lanes verified)"
)
PY_EOF

python3 -I "$repo_root/tools/config/obsd_versions.py" check
