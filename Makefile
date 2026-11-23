# Top-level parser boundary for obsd-ports (modeled after libobsdcompat).
# Reject Make `$` expansion syntax in command-line overrides and recognized
# build-configuration environment variables while ignoring unrelated ambient
# shell environment variables (such as PS1 or IDE session metadata).
unexport $(foreach _top_command_line_name,$(.VARIABLES),$(if $(filter command line,$(origin $(_top_command_line_name))),$(_top_command_line_name)))
ifneq ($(origin MAKEOVERRIDES),undefined)
ifneq ($(value MAKEOVERRIDES),$${-*-command-variables-*-})
$(error MAKEOVERRIDES must remain GNU Make's canonical command-variable ledger)
endif
endif
override TOP_GUARDED_ENV_VARS := MAKEFILE_ROOT OPENBSD_VERSION COMPAT_BACKEND COMPAT_PAL LIBOBSDCOMPAT_ROOT SECTION PORT FILTER BUILD_ROOT CACHE_ROOT JOBS PYTHON
override TOP_UNSAFE_COMMAND_LINE_MAKE_VALUES := $(sort $(foreach _top_variable,$(.VARIABLES),$(if $(and $(filter command line,$(origin $(_top_variable))),$(findstring $$,$(value $(_top_variable)))),$(_top_variable))))
override TOP_UNSAFE_ENVIRONMENT_MAKE_VALUES := $(sort $(foreach _top_variable,$(TOP_GUARDED_ENV_VARS),$(if $(and $(filter environment,$(word 1,$(origin $(_top_variable)))),$(findstring $$,$(value $(_top_variable)))),$(_top_variable))))
ifneq ($(strip $(TOP_UNSAFE_COMMAND_LINE_MAKE_VALUES)),)
$(error command-line build values must not contain Make expansion syntax: $(TOP_UNSAFE_COMMAND_LINE_MAKE_VALUES))
endif
ifneq ($(strip $(TOP_UNSAFE_ENVIRONMENT_MAKE_VALUES)),)
$(error environment build values must not contain Make expansion syntax: $(TOP_UNSAFE_ENVIRONMENT_MAKE_VALUES))
endif
override SHELL := /bin/sh
override .SHELLFLAGS := -c

MAKEFILE_ROOT ?= mk

include $(MAKEFILE_ROOT)/root/main.mk
