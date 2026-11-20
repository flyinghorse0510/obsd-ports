#!/usr/bin/env bash
# audit_tree_layout.sh -- Verify clean multi-axis directory layout & gitignore hygiene.
set -euo pipefail

repo_root=${REPO_ROOT:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}
cd "$repo_root"

required_dirs=(
	config/versions
	config/matrix/backends
	config/matrix/pals
	mk/root
	mk/config
	mk/catalog
	mk/rules
	sdk/bin
	sdk/lib
	sdk/autoconf
	sdk/cmake
	vendor/openbsd/versions/7.8/ports
	vendor/openbsd/versions/7.9/ports
	vendor/openbsd/versions/8.0/ports
	targets/emulate/emscripten
	targets/emulate/darwin
	targets/emulate/wasi
	targets/translate/darwin
	targets/translate/linux
	tools/vendor
	tools/audit
	tools/config
	tools/testing
	docs
)

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
	config/versions/7.8.mk
	config/versions/7.9.mk
	config/versions/8.0.mk
	config/versions/7.8-catalog.tsv
	config/versions/7.9-catalog.tsv
	config/versions/8.0-catalog.tsv
	config/matrix/index.tsv
	sdk/bin/obsd-cc
	sdk/bin/obsd-c++
	sdk/bin/obsd-ar
	sdk/bin/obsd-ranlib
	sdk/bin/obsd-ld
	sdk/bin/obsd-nm
	sdk/bin/obsd-strip
	sdk/bin/obsd-pkg-config
	sdk/autoconf/config.site
	sdk/cmake/openbsd-wasm64.cmake
	tools/build_ports.py
	tools/vendor/sync_openbsd_ports.py
	tools/vendor/import_port.py
	tools/audit/vendor-baseline.tsv
	targets/emulate/emscripten/package_wasm.py
)

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
