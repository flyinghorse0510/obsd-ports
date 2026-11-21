# The release axis is data, not code: verified releases and the default
# (newest verified) come from config/versions/index.tsv.
OPENBSD_VERSIONS_MANIFEST := $(CONFIG_ROOT)/versions/index.tsv
OPENBSD_VERIFIED_VERSIONS := $(shell awk -F'\t' '$$1 !~ /^\#/ && $$1 != "version" && $$2 == "verified" { print $$1 }' "$(OPENBSD_VERSIONS_MANIFEST)" 2>/dev/null | sort -t. -k1,1n -k2,2n)
OPENBSD_DEFAULT_VERSION := $(lastword $(OPENBSD_VERIFIED_VERSIONS))
ifeq ($(strip $(OPENBSD_DEFAULT_VERSION)),)
$(error No verified releases declared in $(OPENBSD_VERSIONS_MANIFEST))
endif
OPENBSD_VERSION ?= $(OPENBSD_DEFAULT_VERSION)
OPENBSD_VERSION_FRAGMENT := $(CONFIG_ROOT)/versions/$(OPENBSD_VERSION).mk

ifeq ($(filter $(OPENBSD_VERSION),$(OPENBSD_VERIFIED_VERSIONS)),)
$(error Unsupported OPENBSD_VERSION='$(OPENBSD_VERSION)'. Verified releases in $(OPENBSD_VERSIONS_MANIFEST): $(OPENBSD_VERIFIED_VERSIONS))
endif
ifeq ($(wildcard $(OPENBSD_VERSION_FRAGMENT)),)
$(error OPENBSD_VERSION='$(OPENBSD_VERSION)' is listed in $(OPENBSD_VERSIONS_MANIFEST) but $(OPENBSD_VERSION_FRAGMENT) is missing)
endif

include $(OPENBSD_VERSION_FRAGMENT)
MAKEFILE_CONFIG_FRAGMENTS += $(OPENBSD_VERSION_FRAGMENT)

VENDOR_OPENBSD_PORTS_DIR := $(VENDOR_ROOT)/openbsd/versions/$(OPENBSD_VERSION)/ports
OPENBSD_CATALOG_TSV := $(CONFIG_ROOT)/versions/$(OPENBSD_VERSION)-catalog.tsv
