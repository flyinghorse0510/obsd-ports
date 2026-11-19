# `targets/emulate/emscripten/`

Active v1 WASM64 packaging adapter & guest merger:

- `package_wasm.py` — Invoked by `make package COMPAT_BACKEND=emulate COMPAT_PAL=emscripten`. Produces `applets/<sym>.o`, `ports-applets.tsv`, `sysroot/usr/local/...`, `ports.svfs.gz`, `ports-owners.db`, and `packages/<pkgname>.tgz`.
- `merge_wasm_guest.py` — Links localized port applets alongside `libobsdcompat`'s base `applet-partials/*.o` and `libobsdc-wasm-<ver>.a` (`merge-guest`) or executes guest shell commands inside a standalone Node.js WASM64 OpenBSD kernel (`run-guest [--enable-network]`).
