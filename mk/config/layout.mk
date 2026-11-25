OBSD_PORTS_ROOT := $(CURDIR)
BUILD_ROOT ?= build
CACHE_ROOT ?= .cache
CONFIG_ROOT := config
VENDOR_ROOT := vendor
PORTS_ROOT := ports
EXTRA_ROOT := extra
SDK_ROOT := sdk
TARGETS_ROOT := targets
TOOLS_ROOT := tools
TESTS_ROOT := tests

# build/package/check need Python >= 3.11 (tomllib). Prefer the newest
# python3.1x on PATH; override with PYTHON=/path/to/python3.11+.
ifeq ($(origin PYTHON),undefined)
PYTHON := $(or $(firstword $(foreach _py,python3.14 python3.13 python3.12 python3.11,$(shell command -v $(_py) 2>/dev/null))),python3)
endif
export OBSD_PYTHON := $(PYTHON)
REQUIRE_PYTHON = "$(PYTHON)" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else "obsd-ports: PYTHON=$(PYTHON) is Python %d.%d; build/fetch/package/check need Python >= 3.11 (tomllib). Install one and pass PYTHON=/path/to/python3.11+ (e.g. PYTHON=/opt/homebrew/bin/python3.13)." % sys.version_info[:2])'
JOBS ?= $(shell getconf _NPROCESSORS_ONLN 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 8)
