include $(MAKEFILE_ROOT)/catalog/fragments.mk

PORT ?=
FILTER ?=

# Discover declarative port recipes (ports/<cat>/<name>/port.toml or port.json)
PORT_TOMLS := $(sort $(shell [ -d "$(PORTS_ROOT)" ] && find "$(PORTS_ROOT)" -mindepth 3 -maxdepth 4 -type f \( -name 'port.toml' -o -name 'port.json' \) 2>/dev/null || true))
DECLARED_PORTS := $(sort $(patsubst $(PORTS_ROOT)/%,%,$(patsubst %/,%,$(dir $(PORT_TOMLS)))))

MAKEFILE_FRAGMENTS += $(MAKEFILE_CATALOG_FRAGMENTS)
