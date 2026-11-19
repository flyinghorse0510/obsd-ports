# `sdk/` — Guest Cross-Compilation SDK

Provides a drop-in cross-compilation toolchain targeting OpenBSD (`7.8`, `7.9`, ...) guest binaries on `libobsdcompat`:

- `sdk/bin/obsd-cc`, `sdk/bin/obsd-c++` — Guest C/C++ compiler & relocatable WASM64 linker driver (`-m64 -pthread -O2 -fno-common -sSUPPORT_LONGJMP=0 -fsanitize-coverage=trace-pc,no-prune -D__OpenBSD__=1`, sysroot-isolated against `$(LIBOBSDCOMPAT_ROOT)/build/wasm-<ver>/include-root-<ver>` and `$(OBSD_STAGE_DIR)/usr/local/{include,lib}`, with undefined-symbol verification against `libobsdc-wasm-<ver>.a`).
- `sdk/bin/{obsd-ar,obsd-ranlib,obsd-ld,obsd-nm,obsd-strip,obsd-pkg-config,obsd-install}` — Hermetic binutils & `pkg-config` wrappers.
- `sdk/autoconf/config.site` — Pre-populated `ac_cv_*`, `curl_cv_*`, and `gl_cv_*` cache for `./configure --host=aarch64-unknown-openbsd<ver>`.
- `sdk/cmake/openbsd-wasm64.cmake` — CMake toolchain file (`-DCMAKE_TOOLCHAIN_FILE=...`).
