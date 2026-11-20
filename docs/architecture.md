# Architecture & Multi-Axis Layout

## Directory Hierarchy

```text
obsd-ports/
├── Makefile                        # Guarded parser boundary -> mk/root/main.mk
├── config/
│   ├── versions/                   # OpenBSD release axis (index.tsv, 7.8.mk, 7.9.mk, 8.0.mk, *-catalog.tsv)
│   └── matrix/                     # Backend x PAL matrix (index.tsv, backends/*.mk, pals/*.mk)
├── mk/
│   ├── root/                       # Standalone clean + strict layer ordering
│   ├── config/                     # Parameterization & declared LIBOBSDCOMPAT_ROOT resolution
│   ├── catalog/                    # Port recipe discovery under ports/**
│   └── rules/                      # sync-vendor, import, fetch, build, package, check, audit
├── sdk/
│   ├── bin/                        # obsd-cc, obsd-c++, obsd-ar, obsd-ranlib, obsd-ld, obsd-nm, obsd-strip, obsd-pkg-config
│   ├── lib/obsd_toolchain.py       # Sysroot-remapping WASM64 compiler & symbol-verifying linker driver
│   ├── autoconf/config.site        # Cross-compilation cache for GNU configure & gnulib
│   └── cmake/openbsd-wasm64.cmake  # CMake cross-compilation toolchain
├── vendor/openbsd/versions/
│   ├── 7.8/ports/                  # Immutable OpenBSD 7.8 port Makefiles, distinfo, patches/*, pkg/*
│   ├── 7.9/ports/                  # Immutable OpenBSD 7.9 port Makefiles, distinfo, patches/*, pkg/*
│   └── 8.0/ports/                  # Immutable OpenBSD 8.0 port Makefiles, distinfo, patches/*, pkg/*
├── ports/                          # Declarative port build recipes (<category>/<name>/port.toml)
├── targets/
│   ├── emulate/{emscripten,wasi,darwin}/
│   └── translate/{darwin,linux}/
├── tools/
│   ├── build_ports.py              # Distinfo parser, fetcher, patch applier, topological builder
│   ├── vendor/                     # sync_openbsd_ports.py & import_port.py
│   ├── config/                     # locate-libobsdcompat.sh
│   ├── testing/                    # run_check.py
│   └── audit/                      # vendor-baseline.tsv & immutability/hierarchy/matrix audits
└── tests/                          # Automated dual-release WASM64 port test suite
```

## Immutable Vendor Tracking Strategy

Full OpenBSD `ports.tar.gz` archives contain ~220,000 tiny files per release (~440,000 files across `7.8` and `7.9`). To keep Git fast while retaining 100% upstream fidelity:

1. `tools/vendor/sync_openbsd_ports.py` downloads and verifies the official release `ports.tar.gz` tarballs against pinned SHA256 digests in `config/versions/index.tsv`, caches them in `.cache/openbsd/<ver>/ports.tar.gz`, and indexes all ~10,400–10,750+ ports into `config/versions/{7.8,7.9,8.0}-catalog.tsv`.
2. `tools/vendor/import_port.py <cat>/<name>` extracts the exact, unmodified upstream `<cat>/<name>/{Makefile,distinfo,patches/*,pkg/*,files/*}` (plus any ancestor `Makefile.inc` / `*.port.mk`) for every active release into `vendor/openbsd/versions/<ver>/ports/` and records per-file SHA256 digests in `tools/audit/vendor-baseline.tsv`.
3. Upstream `patches/patch-*` are applied inside `build/openbsd/<ver>/<backend>/<pal>/work/<cat>/<name>/` at build time — `vendor/` is never mutated, and `tools/audit/audit_vendor_clean.sh` enforces 0 byte/digest drift.

## Output Layout (`build/openbsd/<ver>/emulate/emscripten/`)

- `work/<port>/` — Extracted distfiles and patched build trees.
- `stage/usr/local/` — Cumulative staged `/usr/local/{bin,sbin,lib,include,share,man}` prefix used for inter-port dependency linking (`-I/usr/local/include`, `-L/usr/local/lib`, `.pc` files).
- `applets/<sym>.o` + `<sym>.meta.json` — Localized WASM64 relocatable applet closures (`obsd_applet_<sym>_main`).
- `ports-applets.tsv` — `<sym>\t<guest_path>\t<entry_sym>\tapplets/<sym>.o` manifest consumed by `sonvori-bsd-app` and `merge_wasm_guest.py`.
- `sysroot/usr/local/` — Clean `/usr/local` rootfs overlay (headers, `.a`, `.pc`, share files, helper scripts, manpages; raw WASM applet binaries omitted in favor of applet stubs).
- `ports.svfs.gz` — SVFS v1 gzip bundle of `/usr/local`.
- `ports-owners.db` & `ports-owners.tsv` — Binary `FR_RECORD` (`struct obsd_fr_disk`) and TSV ownership/mode tables.
- `packages/<pkgname>.tgz` — Per-port binary packages.
