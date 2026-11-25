.PHONY: check

check:
	@$(REQUIRE_PYTHON)
	@$(REQUIRE_LIBOBSDCOMPAT)
	LIBOBSDCOMPAT_ROOT="$(LIBOBSDCOMPAT_ROOT)" \
	XENOCARA_BUILD_DIR="$(XENOCARA_BUILD_DIR)" \
	OPENBSD_VERSION="$(OPENBSD_VERSION)" \
	COMPAT_BACKEND="$(COMPAT_BACKEND)" \
	COMPAT_PAL="$(COMPAT_PAL)" \
	COMPAT_SDK="$(COMPAT_SDK)" \
	SECTION="$(SECTION)" \
	"$(PYTHON)" -I "$(TOOLS_ROOT)/testing/run_check.py" \
		--openbsd-version "$(OPENBSD_VERSION)" \
		--backend "$(COMPAT_BACKEND)" \
		--pal "$(COMPAT_PAL)" \
		--section "$(SECTION)" \
		$(if $(strip $(COMPAT_SDK)),--sdk "$(COMPAT_SDK)",) \
		--libobsdcompat-root "$(LIBOBSDCOMPAT_ROOT)" \
		--jobs "$(JOBS)" \
		$(if $(strip $(PORT)),--port "$(PORT)",)
