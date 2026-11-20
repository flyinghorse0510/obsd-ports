.PHONY: sync-vendor import list-catalog

sync-vendor:
	"$(PYTHON)" -I "$(TOOLS_ROOT)/vendor/sync_openbsd_ports.py"

import:
	@test -n "$(PORT)" || { echo "usage: make import PORT=<category>/<name> [OPENBSD_VERSION=7.8|7.9|8.0|all]" >&2; exit 2; }
	"$(PYTHON)" -I "$(TOOLS_ROOT)/vendor/import_port.py" --version all $(PORT)

list-catalog:
	@"$(PYTHON)" -I "$(TOOLS_ROOT)/build_ports.py" list-catalog \
		--openbsd-version "$(OPENBSD_VERSION)" \
		$(if $(strip $(FILTER)),--filter "$(FILTER)",)
