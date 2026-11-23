.PHONY: all list list-extra fetch build package

all: package

list:
	@"$(PYTHON)" -I "$(TOOLS_ROOT)/build_ports.py" list \
		--openbsd-version "$(OPENBSD_VERSION)" \
		--backend "$(COMPAT_BACKEND)" \
		--pal "$(COMPAT_PAL)" \
		--section "$(SECTION)" \
		--build-root "$(BUILD_ROOT)" \
		$(if $(strip $(PORT)),--port "$(PORT)",)

list-extra:
	@"$(PYTHON)" -I "$(TOOLS_ROOT)/build_ports.py" list \
		--openbsd-version "$(OPENBSD_VERSION)" \
		--backend "$(COMPAT_BACKEND)" \
		--pal "$(COMPAT_PAL)" \
		--section extra \
		--build-root "$(BUILD_ROOT)" \
		$(if $(strip $(PORT)),--port "$(PORT)",)

fetch:
	"$(PYTHON)" -I "$(TOOLS_ROOT)/build_ports.py" fetch \
		--openbsd-version "$(OPENBSD_VERSION)" \
		--backend "$(COMPAT_BACKEND)" \
		--pal "$(COMPAT_PAL)" \
		--section "$(SECTION)" \
		--build-root "$(BUILD_ROOT)" \
		--jobs "$(JOBS)" \
		$(if $(strip $(PORT)),--port "$(PORT)",)

build:
	@$(REQUIRE_LIBOBSDCOMPAT)
	LIBOBSDCOMPAT_ROOT="$(LIBOBSDCOMPAT_ROOT)" "$(PYTHON)" -I "$(TOOLS_ROOT)/build_ports.py" build \
		--openbsd-version "$(OPENBSD_VERSION)" \
		--backend "$(COMPAT_BACKEND)" \
		--pal "$(COMPAT_PAL)" \
		--section "$(SECTION)" \
		--build-root "$(BUILD_ROOT)" \
		--libobsdcompat-root "$(LIBOBSDCOMPAT_ROOT)" \
		--jobs "$(JOBS)" \
		$(if $(strip $(PORT)),--port "$(PORT)",)

package: build
	@$(REQUIRE_LIBOBSDCOMPAT)
	LIBOBSDCOMPAT_ROOT="$(LIBOBSDCOMPAT_ROOT)" "$(PYTHON)" -I "$(TOOLS_ROOT)/build_ports.py" package \
		--openbsd-version "$(OPENBSD_VERSION)" \
		--backend "$(COMPAT_BACKEND)" \
		--pal "$(COMPAT_PAL)" \
		--section "$(SECTION)" \
		--build-root "$(BUILD_ROOT)" \
		--libobsdcompat-root "$(LIBOBSDCOMPAT_ROOT)" \
		--jobs "$(JOBS)" \
		$(if $(strip $(PORT)),--port "$(PORT)",)
