COMPAT_PAL_NAME := darwin
COMPAT_GUEST_ARCH := arm64
COMPAT_AUTOCONF_HOST := aarch64-unknown-$(OPENBSD_TRIPLE_OS)

ifeq ($(COMPAT_BACKEND),translate)
COMPAT_SDK ?= macosx
ifneq ($(COMPAT_SDK),macosx)
$(error COMPAT_BACKEND=translate COMPAT_PAL=darwin supports COMPAT_SDK=macosx (got '$(COMPAT_SDK)'))
endif
else ifeq ($(COMPAT_BACKEND),emulate)
COMPAT_SDK ?= iphonesimulator
ifeq ($(filter $(COMPAT_SDK),iphonesimulator iphoneos macosx),)
$(error COMPAT_BACKEND=emulate COMPAT_PAL=darwin supports COMPAT_SDK=iphonesimulator|iphoneos|macosx (got '$(COMPAT_SDK)'))
endif
else
COMPAT_SDK ?= macosx
endif

COMPAT_LANE_LEAF := darwin-$(COMPAT_SDK)
COMPAT_SDK_CC := $(SDK_ROOT)/bin/obsd-cc
COMPAT_SDK_CXX := $(SDK_ROOT)/bin/obsd-c++
COMPAT_SDK_AR := $(SDK_ROOT)/bin/obsd-ar
COMPAT_SDK_RANLIB := $(SDK_ROOT)/bin/obsd-ranlib
COMPAT_SDK_LD := $(SDK_ROOT)/bin/obsd-ld
COMPAT_SDK_NM := $(SDK_ROOT)/bin/obsd-nm
COMPAT_SDK_STRIP := $(SDK_ROOT)/bin/obsd-strip
COMPAT_SDK_PKG_CONFIG := $(SDK_ROOT)/bin/obsd-pkg-config
