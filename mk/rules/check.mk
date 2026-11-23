.PHONY: check

check:
	@$(REQUIRE_LIBOBSDCOMPAT)
	LIBOBSDCOMPAT_ROOT="$(LIBOBSDCOMPAT_ROOT)" \
	OPENBSD_VERSION="$(OPENBSD_VERSION)" \
	COMPAT_BACKEND="$(COMPAT_BACKEND)" \
	COMPAT_PAL="$(COMPAT_PAL)" \
	SECTION="$(SECTION)" \
	"$(PYTHON)" -I "$(TOOLS_ROOT)/testing/run_check.py" \
		--openbsd-version "$(OPENBSD_VERSION)" \
		--backend "$(COMPAT_BACKEND)" \
		--pal "$(COMPAT_PAL)" \
		--section "$(SECTION)" \
		--libobsdcompat-root "$(LIBOBSDCOMPAT_ROOT)" \
		--jobs "$(JOBS)" \
		$(if $(strip $(PORT)),--port "$(PORT)",)
