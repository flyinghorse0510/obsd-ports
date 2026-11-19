# `obsd-ports` — Multi-Release, Multi-Backend OpenBSD Ports Builder & SDK

`obsd-ports` cross-compiles and packages authentic OpenBSD release ports (`7.8`, `7.9`, and future releases) against [`libobsdcompat`](../libobsdcompat) without modifying upstream OpenBSD vendor metadata.

## Multi-Axis Architecture

Every build is parameterized cleanly across three orthogonal axes:

1. **OpenBSD Release (`OPENBSD_VERSION`)**: `7.9` (default), `7.8` — declared in [`config/versions/index.tsv`](config/versions/index.tsv), backed by SHA256-verified official OpenBSD `ports.tar.gz` catalogs (`config/versions/<ver>-catalog.tsv`, ~10,500+ ports per release) and immutable port subtrees under `vendor/openbsd/versions/<ver>/ports/`.
2. **Compatibility Backend (`COMPAT_BACKEND`)**: `emulate` (default, crunched multi-call relocatable applets) and `translate` (standalone executables).
3. **Platform Abstraction Layer (`COMPAT_PAL`)**: `emscripten` (active v1 WASM64 browser & Node.js guest), with clean target seams for `wasi`, `darwin`, and `linux` declared in [`config/matrix/index.tsv`](config/matrix/index.tsv).

All build outputs isolate cleanly under `build/openbsd/<OPENBSD_VERSION>/<COMPAT_BACKEND>/<COMPAT_PAL>/`.

## Declaring `libobsdcompat` (Declared, Never Searched)

`obsd-ports` consumes `libobsdcompat` headers (`include-root-<ver>`), guest base libraries (`libobsdc-wasm-<ver>.a`), and `wasm_object_tool.py`. Following `ubibsd`'s convention, the `libobsdcompat` checkout is **declared, never searched**:

1. Explicit environment or Make variable: `LIBOBSDCOMPAT_ROOT=/abs/path/to/libobsdcompat`
2. Or a gitignored single-line file at the repository root:
   ```sh
   echo /abs/path/to/libobsdcompat > .libobsdcompat-root
   ```

`make clean` works standalone with zero external dependencies.

## Quickstart & Top-Level Make Targets

```sh
# Search the full ~10,600-port OpenBSD release catalog
make list-catalog OPENBSD_VERSION=7.9 FILTER=jq

# Import an unmodified OpenBSD port subtree for all active releases (7.8 + 7.9)
make import PORT=textproc/jq

# List declared port recipes under ports/ and their lane build status
make list OPENBSD_VERSION=7.9

# Fetch & verify distfile SHA256 digests against vendor/.../distinfo
make fetch OPENBSD_VERSION=7.9

# Cross-compile & stage ports into build/openbsd/<ver>/emulate/emscripten/stage
make build OPENBSD_VERSION=7.9
make build OPENBSD_VERSION=7.8

# Package applets/*.o, ports-applets.tsv, sysroot/usr/local, ports.svfs.gz,
# ports-owners.db, and per-port packages/*.tgz
make package OPENBSD_VERSION=7.9
make package OPENBSD_VERSION=7.8

# Run SDK + WASM64 port verification suite
make check OPENBSD_VERSION=7.9
make check OPENBSD_VERSION=7.8

# Run vendor immutability, Make hierarchy, layout, and matrix seam audits
make audit

# Remove build/ (standalone)
make clean
```

## Documentation

- [`docs/architecture.md`](docs/architecture.md) — Repository hierarchy, Make layers, vendor immutability, and output layout.
- [`docs/port-recipes.md`](docs/port-recipes.md) — `ports/<category>/<name>/port.toml` recipe contract & examples.
- [`docs/sdk-and-targets.md`](docs/sdk-and-targets.md) — `sdk/bin/obsd-*` cross-compiler flags, `config.site`, CMake toolchain, and `targets/` packaging adapters.
