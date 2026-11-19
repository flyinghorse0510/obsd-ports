#!/usr/bin/env bash
# audit_make_hierarchy.sh -- Verify 4-layer Make hierarchy & standalone clean.
set -euo pipefail

repo_root=${REPO_ROOT:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}
cd "$repo_root"

required_mk=(
	Makefile
	mk/root/main.mk
	mk/root/fragments.mk
	mk/root/clean.mk
	mk/config/main.mk
	mk/config/fragments.mk
	mk/config/layout.mk
	mk/config/versions.mk
	mk/config/matrix.mk
	mk/config/dependencies.mk
	mk/catalog/main.mk
	mk/catalog/fragments.mk
	mk/rules/main.mk
	mk/rules/fragments.mk
	mk/rules/vendor.mk
	mk/rules/ports.mk
	mk/rules/check.mk
	mk/rules/audit.mk
)

for m in "${required_mk[@]}"; do
	if [ ! -f "$m" ]; then
		printf 'make hierarchy audit failed: missing %s\n' "$m" >&2
		exit 1
	fi
done

# Verify `make -n clean` works standalone even when LIBOBSDCOMPAT_ROOT is unset/nonexistent
tmp_build=$(mktemp -d)
trap 'rm -rf "$tmp_build"' EXIT
env -i PATH="/usr/bin:/bin" make -C "$repo_root" clean BUILD_ROOT="$tmp_build/out" >/dev/null

# Verify command-line `$` expansion guard rejects forged Make expressions
if make -C "$repo_root" list OPENBSD_VERSION='$(shell echo 7.9)' >/dev/null 2>&1; then
	printf 'make hierarchy audit failed: top-level Make parser boundary accepted $ expansion\n' >&2
	exit 1
fi

printf 'make hierarchy audit: ok\n'
