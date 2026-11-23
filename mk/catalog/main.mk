include $(MAKEFILE_ROOT)/catalog/fragments.mk

SECTION ?= all
PORT ?=
FILTER ?=

ifeq ($(filter $(SECTION),all ports extra),)
$(error Unsupported SECTION='$(SECTION)'. Expected one of: all ports extra)
endif

# Discover declarative port recipes (ports/<cat>/<name>/port.toml or port.json)
PORT_TOMLS := $(sort $(shell [ -d "$(PORTS_ROOT)" ] && find "$(PORTS_ROOT)" -mindepth 3 -maxdepth 4 -type f \( -name 'port.toml' -o -name 'port.json' \) 2>/dev/null || true))
DECLARED_PORTS := $(sort $(patsubst $(PORTS_ROOT)/%,%,$(patsubst %/,%,$(dir $(PORT_TOMLS)))))

# Discover declarative extra port recipes (extra/<cat>/<name>/port.toml or port.json)
EXTRA_TOMLS := $(sort $(shell [ -d "$(EXTRA_ROOT)" ] && find "$(EXTRA_ROOT)" -mindepth 3 -maxdepth 4 -type f \( -name 'port.toml' -o -name 'port.json' \) 2>/dev/null || true))
DECLARED_EXTRA_PORTS := $(sort $(patsubst $(EXTRA_ROOT)/%,%,$(patsubst %/,%,$(dir $(EXTRA_TOMLS)))))

MAKEFILE_FRAGMENTS += $(MAKEFILE_CATALOG_FRAGMENTS)
