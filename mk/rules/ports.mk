.PHONY: all list fetch build package

all: package

list:
	@$(REQUIRE_PYTHON)
	@"$(PYTHON)" -I "$(TOOLS_ROOT)/build_ports.py" list \
		--openbsd-version "$(OPENBSD_VERSION)" \
		--backend "$(COMPAT_BACKEND)" \
		--pal "$(COMPAT_PAL)" \
		$(if $(strip $(PORT)),--port "$(PORT)",)

fetch:
	@$(REQUIRE_PYTHON)
	"$(PYTHON)" -I "$(TOOLS_ROOT)/build_ports.py" fetch \
		--openbsd-version "$(OPENBSD_VERSION)" \
		--backend "$(COMPAT_BACKEND)" \
		--pal "$(COMPAT_PAL)" \
		--jobs "$(JOBS)" \
		$(if $(strip $(PORT)),--port "$(PORT)",)

build:
	@$(REQUIRE_PYTHON)
	@$(REQUIRE_LIBOBSDCOMPAT)
	LIBOBSDCOMPAT_ROOT="$(LIBOBSDCOMPAT_ROOT)" "$(PYTHON)" -I "$(TOOLS_ROOT)/build_ports.py" build \
		--openbsd-version "$(OPENBSD_VERSION)" \
		--backend "$(COMPAT_BACKEND)" \
		--pal "$(COMPAT_PAL)" \
		--libobsdcompat-root "$(LIBOBSDCOMPAT_ROOT)" \
		--jobs "$(JOBS)" \
		$(if $(strip $(PORT)),--port "$(PORT)",)

package: build
	@$(REQUIRE_PYTHON)
	@$(REQUIRE_LIBOBSDCOMPAT)
	LIBOBSDCOMPAT_ROOT="$(LIBOBSDCOMPAT_ROOT)" "$(PYTHON)" -I "$(TOOLS_ROOT)/build_ports.py" package \
		--openbsd-version "$(OPENBSD_VERSION)" \
		--backend "$(COMPAT_BACKEND)" \
		--pal "$(COMPAT_PAL)" \
		--libobsdcompat-root "$(LIBOBSDCOMPAT_ROOT)" \
		--jobs "$(JOBS)" \
		$(if $(strip $(PORT)),--port "$(PORT)",)
