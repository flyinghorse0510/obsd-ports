OBSD_PORTS_ROOT := $(CURDIR)
BUILD_ROOT ?= build
CACHE_ROOT ?= .cache
CONFIG_ROOT := config
VENDOR_ROOT := vendor
PORTS_ROOT := ports
SDK_ROOT := sdk
TARGETS_ROOT := targets
TOOLS_ROOT := tools
TESTS_ROOT := tests

PYTHON ?= python3
JOBS ?= $(shell getconf _NPROCESSORS_ONLN 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 8)
