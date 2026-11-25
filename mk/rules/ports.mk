.PHONY: all list list-extra fetch build package

all: package

list:
	@$(REQUIRE_PYTHON)
	@"$(PYTHON)" -I "$(TOOLS_ROOT)/build_ports.py" list \
		--openbsd-version "$(OPENBSD_VERSION)" \
		--backend "$(COMPAT_BACKEND)" \
		--pal "$(COMPAT_PAL)" \
		--section "$(SECTION)" \
		--build-root "$(BUILD_ROOT)" \
		$(if $(strip $(COMPAT_SDK)),--sdk "$(COMPAT_SDK)",) \
		$(if $(strip $(PORT)),--port "$(PORT)",)

list-extra:
	@$(REQUIRE_PYTHON)
	@"$(PYTHON)" -I "$(TOOLS_ROOT)/build_ports.py" list \
		--openbsd-version "$(OPENBSD_VERSION)" \
		--backend "$(COMPAT_BACKEND)" \
		--pal "$(COMPAT_PAL)" \
		--section extra \
		--build-root "$(BUILD_ROOT)" \
		$(if $(strip $(COMPAT_SDK)),--sdk "$(COMPAT_SDK)",) \
		$(if $(strip $(PORT)),--port "$(PORT)",)

fetch:
	@$(REQUIRE_PYTHON)
	"$(PYTHON)" -I "$(TOOLS_ROOT)/build_ports.py" fetch \
		--openbsd-version "$(OPENBSD_VERSION)" \
		--backend "$(COMPAT_BACKEND)" \
		--pal "$(COMPAT_PAL)" \
		--section "$(SECTION)" \
		--build-root "$(BUILD_ROOT)" \
		$(if $(strip $(COMPAT_SDK)),--sdk "$(COMPAT_SDK)",) \
		--jobs "$(JOBS)" \
		$(if $(strip $(PORT)),--port "$(PORT)",)

build:
	@$(REQUIRE_PYTHON)
	@$(REQUIRE_LIBOBSDCOMPAT)
	LIBOBSDCOMPAT_ROOT="$(LIBOBSDCOMPAT_ROOT)" COMPAT_SDK="$(COMPAT_SDK)" "$(PYTHON)" -I "$(TOOLS_ROOT)/build_ports.py" build \
		--openbsd-version "$(OPENBSD_VERSION)" \
		--backend "$(COMPAT_BACKEND)" \
		--pal "$(COMPAT_PAL)" \
		--section "$(SECTION)" \
		--build-root "$(BUILD_ROOT)" \
		$(if $(strip $(COMPAT_SDK)),--sdk "$(COMPAT_SDK)",) \
		--libobsdcompat-root "$(LIBOBSDCOMPAT_ROOT)" \
		--jobs "$(JOBS)" \
		$(if $(strip $(PORT)),--port "$(PORT)",)

package: build
	@$(REQUIRE_PYTHON)
	@$(REQUIRE_LIBOBSDCOMPAT)
	LIBOBSDCOMPAT_ROOT="$(LIBOBSDCOMPAT_ROOT)" COMPAT_SDK="$(COMPAT_SDK)" "$(PYTHON)" -I "$(TOOLS_ROOT)/build_ports.py" package \
		--openbsd-version "$(OPENBSD_VERSION)" \
		--backend "$(COMPAT_BACKEND)" \
		--pal "$(COMPAT_PAL)" \
		--section "$(SECTION)" \
		--build-root "$(BUILD_ROOT)" \
		$(if $(strip $(COMPAT_SDK)),--sdk "$(COMPAT_SDK)",) \
		--libobsdcompat-root "$(LIBOBSDCOMPAT_ROOT)" \
		--jobs "$(JOBS)" \
		$(if $(strip $(PORT)),--port "$(PORT)",)
