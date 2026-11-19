# Guest Cross-Compilation SDK & Target Adapters

## `sdk/bin/*`

- **`obsd-cc` / `obsd-c++`**:
  - Compiles C/C++ translation units with `-m64 -pthread -O2 -fno-common -fno-builtin -sSUPPORT_LONGJMP=0 -fsanitize-coverage=trace-pc,no-prune -D__OpenBSD__=1 -nostdinc` against `$(LIBOBSDCOMPAT_ROOT)/build/wasm-<ver>/include-root-<ver>` and staged port headers in `$(OBSD_STAGE_DIR)/usr/local/include`.
  - Transparently remaps `-I/usr/local/include*` and `-L/usr/local/lib*` to `$(OBSD_STAGE_DIR)/usr/local/{include,lib}` so `--with-foo=/usr/local` never leaks host Linux headers or libraries while keeping compiled-in guest paths (`/usr/local`, `/etc/ssl/cert.pem`) authentic.
  - Produces WASM64 relocatable executables via `wasm-ld -m wasm64 -r` (statically linking port `.a` libraries while leaving base OpenBSD `libobsdc-wasm-<ver>.a` symbols undefined) and verifies every undefined symbol against `libobsdc-wasm-<ver>.a` so `./configure` link checks (`AC_CHECK_FUNC`, `AC_CHECK_LIB`, `AC_SEARCH_LIBS`) report exact OpenBSD capabilities.
- **`obsd-pkg-config`**: Hermetic wrapper isolated to `$(OBSD_STAGE_DIR)/usr/local/{lib,share}/pkgconfig` plus synthesized base OpenBSD `.pc` descriptors (`openssl`, `libssl`, `libcrypto`, `libtls`, `zlib`, `curses`, `ncursesw`, `expat`, `libedit`).
- **`obsd-strip` / `obsd-install`**: Preserves WASM `linking` custom sections during `make install` / `install -s`.

## Standalone WASM64 Execution Helper (`targets/emulate/emscripten/merge_wasm_guest.py`)

`merge_wasm_guest.py` supports two workflows without touching `libobsdcompat/`:

1. **Full Guest Partial Merge (`merge-guest`)**:
   Combines `libobsdcompat`'s `applet-partials/*.o` + `obsd-ports`'s `applets/*.o` + `libobsdc-wasm-<ver>.a` into a windowed `guest-partial.o` + `wasm_applet_table.c` + `applet-table.tsv`.
2. **Standalone Node.js Guest Command Runner (`run-guest`)**:
   Links a fast cached Node.js WASM64 OpenBSD kernel with `/bin/ksh`, core OpenBSD utilities, all built port applets, staged `sysroot/usr/local`, `/etc/ssl/cert.pem`, terminfo, and an optional standalone `SVNP/1` TCP/UDP/DNS bridge (`--enable-network`) for automated testing (`tests/run_wasm_ports_tests.py`).
