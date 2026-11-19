include $(MAKEFILE_ROOT)/rules/fragments.mk
include $(MAKEFILE_ROOT)/rules/vendor.mk
include $(MAKEFILE_ROOT)/rules/ports.mk
include $(MAKEFILE_ROOT)/rules/check.mk
include $(MAKEFILE_ROOT)/rules/audit.mk

MAKEFILE_FRAGMENTS += $(MAKEFILE_RULES_FRAGMENTS)

.DEFAULT_GOAL := package
