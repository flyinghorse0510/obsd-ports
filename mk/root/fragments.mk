MAKEFILE_CONFIG_LAYER := $(MAKEFILE_ROOT)/config/main.mk
MAKEFILE_CATALOG_LAYER := $(MAKEFILE_ROOT)/catalog/main.mk
MAKEFILE_RULES_LAYER := $(MAKEFILE_ROOT)/rules/main.mk

MAKEFILE_ROOT_FRAGMENTS := \
	$(MAKEFILE_ROOT)/root/main.mk \
	$(MAKEFILE_ROOT)/root/fragments.mk \
	$(MAKEFILE_ROOT)/root/clean.mk
