BUILD_ROOT ?= build
CACHE_ROOT ?= .cache

.PHONY: clean distclean

# Standalone clean: requires zero external checkouts (LIBOBSDCOMPAT_ROOT).
clean:
	rm -rf -- "$(BUILD_ROOT)"

distclean:
	rm -rf -- "$(BUILD_ROOT)" "$(CACHE_ROOT)"
