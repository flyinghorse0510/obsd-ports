#!/usr/bin/env bash
# audit_vendor_clean.sh -- Verify 100% immutability of `vendor/openbsd/versions/`
# against Git status AND `tools/audit/vendor-baseline.tsv`.
set -euo pipefail

repo_root=${REPO_ROOT:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}
cd "$repo_root"

vendor_path=${1:-vendor/openbsd/versions}
baseline=${VENDOR_BASELINE:-tools/audit/vendor-baseline.tsv}

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
	printf 'vendor clean audit failed: %s is not a Git repository\n' "$repo_root" >&2
	exit 1
fi

if [ ! -d "$vendor_path" ]; then
	printf 'vendor clean audit failed: missing vendor directory %s\n' "$vendor_path" >&2
	exit 1
fi

if [ ! -f "$baseline" ]; then
	printf 'vendor clean audit failed: missing baseline %s\n' "$baseline" >&2
	exit 1
fi

# 1. If HEAD exists, verify zero uncommitted or untracked changes under vendor/.
if git rev-parse --verify --quiet HEAD >/dev/null 2>&1; then
	status=$(git status --porcelain -- "$vendor_path")
	if [ -n "$status" ]; then
		printf 'vendor clean audit failed: local changes under %s:\n%s\n' "$vendor_path" "$status" >&2
		exit 1
	fi
fi

# 2. Verify exact 1-to-1 SHA256 and byte-size match between vendor/ and vendor-baseline.tsv.
python3 -I - "$vendor_path" "$baseline" <<'PY_EOF'
import hashlib
import pathlib
import sys

vendor_dir = pathlib.Path(sys.argv[1])
baseline_path = pathlib.Path(sys.argv[2])

expected = {}
for raw in baseline_path.read_text(encoding="utf-8").splitlines():
    line = raw.strip()
    if not line or line.startswith("#") or line.startswith("version\t"):
        continue
    ver, rel, sha, sz = raw.split("\t")
    expected[rel] = (ver, sha, int(sz))

if not expected:
    sys.stderr.write("vendor clean audit failed: vendor-baseline.tsv is empty\n")
    raise SystemExit(1)

actual_files = sorted(p for p in vendor_dir.rglob("*") if p.is_file())
seen = set()
errors = []

for fp in actual_files:
    rel = fp.as_posix()
    seen.add(rel)
    if rel not in expected:
        errors.append(f"unrecorded file in vendor/: {rel}")
        continue
    _ver, exp_sha, exp_sz = expected[rel]
    st_sz = fp.stat().st_size
    act_sha = hashlib.sha256(fp.read_bytes()).hexdigest()
    if st_sz != exp_sz or act_sha != exp_sha:
        errors.append(
            f"modified vendor file {rel}: actual=({act_sha}, {st_sz}B) != baseline=({exp_sha}, {exp_sz}B)"
        )

for rel in sorted(set(expected.keys()) - seen):
    errors.append(f"missing baseline vendor file: {rel}")

if errors:
    sys.stderr.write("vendor clean audit failed:\n  " + "\n  ".join(errors) + "\n")
    raise SystemExit(1)

print(f"vendor clean audit: ok ({len(seen)} immutable files verified)")
PY_EOF
