#!/usr/bin/env bash
# audit_matrix_seams.sh -- Verify release axis (`7.8`, `7.9`) and Backend x PAL
# matrix (`emulate`, `translate` x `emscripten`, `wasi`, `darwin`, `linux`)
# consistency across manifests, Make fragments, and target adapter directories.
set -euo pipefail

repo_root=${REPO_ROOT:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}
cd "$repo_root"

python3 -I - <<'PY_EOF'
import pathlib
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

if len(ver_rows) < 2:
    raise SystemExit("matrix audit failed: expected at least OpenBSD 7.8 and 7.9 in config/versions/index.tsv")

# 2. Verify config/matrix/index.tsv
mat_rows = []
for raw in (root / "config/matrix/index.tsv").read_text(encoding="utf-8").splitlines():
    s = raw.strip()
    if not s or s.startswith("#") or s.startswith("backend\t"):
        continue
    cols = raw.split("\t")
    mat_rows.append(cols)
    backend, pal, status, _arch, _fmt, adapter_dir = cols[:6]
    if not (root / f"config/matrix/backends/{backend}.mk").is_file():
        raise SystemExit(f"matrix audit failed: missing backend fragment for {backend}")
    if not (root / f"config/matrix/pals/{pal}.mk").is_file():
        raise SystemExit(f"matrix audit failed: missing PAL fragment for {pal}")
    if not (root / adapter_dir).is_dir():
        raise SystemExit(f"matrix audit failed: missing adapter dir {adapter_dir}")
    if not (root / adapter_dir / "README.md").is_file():
        raise SystemExit(f"matrix audit failed: missing {adapter_dir}/README.md")

print(f"matrix seams audit: ok ({len(ver_rows)} releases x {len(mat_rows)} backend/PAL cells verified)")
PY_EOF
