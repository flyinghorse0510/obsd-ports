#!/usr/bin/env bash
# audit_tree_layout.sh -- Verify clean multi-axis directory layout & gitignore hygiene.
set -euo pipefail

repo_root=${REPO_ROOT:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}
cd "$repo_root"

required_dirs=(
	config/versions
	config/matrix/backends
	config/matrix/pals
	config/extra
	extra
	mk/root
	mk/config
	mk/catalog
	mk/rules
	sdk/bin
	sdk/lib
	sdk/rust
	sdk/autoconf
	sdk/cmake
	targets/common
	targets/emulate/emscripten
	targets/emulate/darwin
	targets/emulate/wasi
	targets/translate/darwin
	targets/translate/linux
	tools/vendor
	tools/extra
	tools/audit
	tools/config
	tools/testing
	docs
)

# Per-release dirs/files come from config/versions/index.tsv (never hardcoded).
while IFS= read -r rel; do
	[ -n "$rel" ] || continue
	required_dirs+=("vendor/openbsd/versions/$rel/ports")
done < <(python3 -I tools/config/obsd_versions.py list)

for d in "${required_dirs[@]}"; do
	if [ ! -d "$d" ]; then
		printf 'tree layout audit failed: missing required directory %s\n' "$d" >&2
		exit 1
	fi
done

required_files=(
	Makefile
	.gitignore
	README.md
	config/versions/index.tsv
	config/matrix/index.tsv
	config/matrix/pals/darwin.mk
	config/extra/index.tsv
	sdk/bin/obsd-cc
	sdk/bin/obsd-c++
	sdk/bin/obsd-ar
	sdk/bin/obsd-ranlib
	sdk/bin/obsd-ld
	sdk/bin/obsd-nm
	sdk/bin/obsd-strip
	sdk/bin/obsd-pkg-config
	sdk/bin/obsd-cargo
	sdk/bin/obsd-rust-ld
	sdk/lib/obsd-python.sh
	sdk/rust/wasm64-unknown-openbsd.json
	sdk/rust/obsd_rust.py
	sdk/rust/unwind_stub.c
	sdk/autoconf/config.site
	sdk/autoconf/config.site.darwin
	sdk/cmake/openbsd-wasm64.cmake
	sdk/cmake/openbsd-darwin.cmake
	tools/build_ports.py
	tools/config/obsd_versions.py
	tools/config/obsd_env.py
	tools/extra/gen_cargo_distinfo.py
	tools/audit/audit_extra_ports.py
	tools/vendor/sync_openbsd_ports.py
	tools/vendor/import_port.py
	tools/audit/vendor-baseline.tsv
	targets/common/packaging.py
	targets/emulate/emscripten/package_wasm.py
	targets/emulate/darwin/package_darwin.py
	targets/translate/darwin/package_darwin.py
)

while IFS= read -r rel; do
	[ -n "$rel" ] || continue
	required_files+=("config/versions/$rel.mk" "config/versions/$rel-catalog.tsv")
done < <(python3 -I tools/config/obsd_versions.py list)

for f in "${required_files[@]}"; do
	if [ ! -f "$f" ]; then
		printf 'tree layout audit failed: missing required file %s\n' "$f" >&2
		exit 1
	fi
done

# Ensure .libobsdcompat-root, build/, and .cache/ are never tracked in Git
tracked_forbidden=$(git ls-files -- .libobsdcompat-root build .cache)
if [ -n "$tracked_forbidden" ]; then
	printf 'tree layout audit failed: local/ephemeral paths tracked in Git:\n%s\n' "$tracked_forbidden" >&2
	exit 1
fi

printf 'tree layout audit: ok\n'
