# Declared, never searched: LIBOBSDCOMPAT_ROOT comes ONLY from explicit
# command-line/environment LIBOBSDCOMPAT_ROOT or ./.libobsdcompat-root.
# Targets that only inspect repository metadata (audit, list, list-catalog,
# import, sync-vendor) defer hard failure until a target requires libobsdcompat.
ifeq ($(origin LIBOBSDCOMPAT_ROOT),undefined)
LIBOBSDCOMPAT_ROOT := $(shell sh $(TOOLS_ROOT)/config/locate-libobsdcompat.sh --quiet 2>/dev/null)
endif

REQUIRE_LIBOBSDCOMPAT = sh "$(TOOLS_ROOT)/config/locate-libobsdcompat.sh" >/dev/null
