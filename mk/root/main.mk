MAKEFILE_ROOT ?= mk

ifeq ($(filter default undefined,$(origin MAKECMDGOALS)),)
$(error MAKECMDGOALS must not be overridden)
endif

ifneq ($(filter clean distclean,$(MAKECMDGOALS)),)
ifneq ($(words $(MAKECMDGOALS)),1)
$(error clean/distclean must be the sole requested top-level goal)
endif
include $(MAKEFILE_ROOT)/root/clean.mk
else
include $(MAKEFILE_ROOT)/root/fragments.mk

MAKEFILE_FRAGMENTS = Makefile \
	$(MAKEFILE_ROOT_FRAGMENTS)

include $(MAKEFILE_CONFIG_LAYER)
include $(MAKEFILE_CATALOG_LAYER)
include $(MAKEFILE_RULES_LAYER)
endif
