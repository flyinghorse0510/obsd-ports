#!/bin/sh
# Declared, never searched: resolve the libobsdcompat checkout this tree builds
# against strictly from:
#   1. $LIBOBSDCOMPAT_ROOT, if non-empty.
#   2. ./.libobsdcompat-root (single path line), if present.
#   3. Otherwise fail explicitly with instructions.
set -eu

quiet=0
if [ "${1:-}" = "--quiet" ]; then
	quiet=1
	shift
fi

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd -P)
marker="$repo/.libobsdcompat-root"

err() {
	if [ "$quiet" -eq 0 ]; then
		printf '%s\n' "$*" >&2
	fi
}

is_checkout() {
	[ -n "$1" ] && [ -d "$1/vendor/openbsd/versions" ]
}

resolve_candidate() {
	candidate=$1
	origin=$2
	resolved=$(CDPATH= cd -- "$candidate" 2>/dev/null && pwd -P) || {
		err "locate-libobsdcompat: $origin names a path that does not exist: $candidate"
		exit 1
	}
	is_checkout "$resolved" || {
		err "locate-libobsdcompat: $origin names $resolved, which has no vendor/openbsd/versions"
		exit 1
	}
	printf '%s\n' "$resolved"
	exit 0
}

if [ -n "${LIBOBSDCOMPAT_ROOT:-}" ]; then
	resolve_candidate "$LIBOBSDCOMPAT_ROOT" "LIBOBSDCOMPAT_ROOT"
fi

if [ -f "$marker" ]; then
	declared=$(sed -e 's/[[:space:]]*$//' -e '/^[[:space:]]*#/d' -e '/^$/d' "$marker" | head -n 1)
	if [ -z "$declared" ]; then
		err "locate-libobsdcompat: $marker is empty"
		exit 1
	fi
	case "$declared" in
		/*) ;;
		*) declared="$repo/$declared" ;;
	esac
	resolve_candidate "$declared" "$marker"
fi

err "locate-libobsdcompat: no libobsdcompat checkout declared."
err "locate-libobsdcompat: set LIBOBSDCOMPAT_ROOT=/path/to/libobsdcompat or write it into:"
err "  $marker"
exit 1
