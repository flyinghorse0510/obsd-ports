# Declared, never searched: LIBOBSDCOMPAT_ROOT comes ONLY from explicit
# command-line/environment LIBOBSDCOMPAT_ROOT or ./.libobsdcompat-root.
# Targets that only inspect repository metadata (audit, list, list-catalog,
# import, sync-vendor) defer hard failure until a target requires libobsdcompat.
ifeq ($(origin LIBOBSDCOMPAT_ROOT),undefined)
LIBOBSDCOMPAT_ROOT := $(shell sh $(TOOLS_ROOT)/config/locate-libobsdcompat.sh --quiet 2>/dev/null)
endif

ifeq ($(origin XENOCARA_BUILD_DIR),undefined)
ifeq ($(COMPAT_BACKEND)/$(COMPAT_PAL),emulate/emscripten)
ifneq ($(wildcard /var/tmp/sonvori-xenocara/build/$(OPENBSD_VERSION)/libobsdx11-libs.json),)
XENOCARA_BUILD_DIR := /var/tmp/sonvori-xenocara/build/$(OPENBSD_VERSION)
endif
endif
endif
XENOCARA_BUILD_DIR ?=

REQUIRE_LIBOBSDCOMPAT = sh "$(TOOLS_ROOT)/config/locate-libobsdcompat.sh" >/dev/null
