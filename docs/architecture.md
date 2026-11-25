# Architecture & Multi-Axis Layout

## Directory Hierarchy

```text
obsd-ports/
├── Makefile                        # Guarded parser boundary -> mk/root/main.mk
├── config/
│   ├── versions/                   # OpenBSD release axis (index.tsv, 7.8.mk, 7.9.mk, 8.0.mk, *-catalog.tsv)
│   ├── matrix/                     # Canonical 5-cell Backend x PAL matrix (index.tsv, backends/*.mk, pals/*.mk)
│   └── extra/                      # Extra ports manifest (index.tsv)
├── mk/
│   ├── root/                       # Standalone clean + strict layer ordering
│   ├── config/                     # Parameterization & declared LIBOBSDCOMPAT_ROOT resolution
│   ├── catalog/                    # Port recipe discovery under ports/** and extra/** (SECTION=all|ports|extra)
│   └── rules/                      # sync-vendor, import, list, list-extra, fetch, build, package, check, audit
├── sdk/
│   ├── bin/                        # obsd-cc, obsd-c++, obsd-ar, obsd-ranlib, obsd-ld, obsd-nm, obsd-strip, obsd-pkg-config, obsd-cargo, obsd-rust-ld
│   ├── lib/obsd_toolchain.py       # Sysroot-remapping WASM64 & Darwin Mach-O compiler/linker driver
│   ├── rust/                       # wasm64-unknown-openbsd.json, obsd_rust.py, unwind_stub.c, 3D matrix Rust target mapper
│   ├── autoconf/                   # config.site & config.site.darwin
│   └── cmake/                      # openbsd-wasm64.cmake & openbsd-darwin.cmake
├── vendor/openbsd/versions/
│   ├── 7.8/ports/                  # Immutable OpenBSD 7.8 port Makefiles, distinfo, patches/*, pkg/*
│   ├── 7.9/ports/                  # Immutable OpenBSD 7.9 port Makefiles, distinfo, patches/*, pkg/*
│   └── 8.0/ports/                  # Immutable OpenBSD 8.0 port Makefiles, distinfo, patches/*, pkg/*
├── ports/                          # Declarative port build recipes (<category>/<name>/port.toml)
├── extra/                          # Self-contained OpenBSD-style extra ports (<category>/<name>/{Makefile,distinfo,pkg/*,port.toml})
├── targets/
│   ├── common/                     # Shared packaging.py (+CONTENTS, +DESC, SVFS, fakeroot owners)
│   ├── emulate/{emscripten,wasi,darwin}/
│   └── translate/{darwin,linux}/
├── tools/
│   ├── build_ports.py              # Distinfo parser, parallel fetcher, 3D matrix resolver, topological builder
│   ├── extra/                      # gen_cargo_distinfo.py (crates.inc & distinfo generator for MODULES=devel/cargo)
│   ├── vendor/                     # sync_openbsd_ports.py & import_port.py
│   ├── config/                     # locate-libobsdcompat.sh, obsd_versions.py, obsd_env.py
│   ├── testing/                    # run_check.py
│   └── audit/                      # vendor-baseline.tsv, audit_extra_ports.py & immutability/hierarchy/matrix audits
└── tests/                          # Automated multi-release WASM64 & Darwin port test suites
```

## 3D Matrix (`OPENBSD_VERSION x COMPAT_BACKEND x COMPAT_PAL` = 15 Matrix Cells) & `extra/` Section

1. **Release Axis (`config/versions/index.tsv`)**: OpenBSD `8.0` (`80` WASM64 ports: `77` `ports/*` + `3` `extra/*`; `53` Darwin ports), `7.9` (`67` WASM64 ports; `53` Darwin ports), and `7.8` (`66` WASM64 ports; `53` Darwin ports).
2. **Backend x PAL Matrix (`config/matrix/index.tsv`)**: Canonical 5 cells (`3 x 5 = 15` matrix cells):
   - `emulate/{emscripten,wasi,darwin}` (`COMPAT_PRODUCES_APPLETS := 1`, relocatable multi-call applet closures; `emulate/emscripten` active WASM64 lane, `emulate/darwin` active multi-core banked iOS/iPadOS lane via `COMPAT_SDK=iphonesimulator|iphoneos` enforcing strict W^X zero-JIT invariants).
   - `translate/{darwin,linux}` (`COMPAT_PRODUCES_APPLETS := 0`, standalone boundary executables; `translate/darwin` active macOS arm64 lane via `COMPAT_SDK=macosx`).
3. **Dual Port Sections (`SECTION=all|ports|extra`)**:
   - `ports/<category>/<name>/port.toml` builds against immutable upstream metadata in `vendor/openbsd/versions/<ver>/ports/`.
   - `extra/<category>/<name>/` hosts self-contained OpenBSD-style ports (`Makefile`, `crates.inc`, `distinfo`, `pkg/DESCR`, `pkg/PLIST`, `patches/patch-*`, `port.toml`) indexed in `config/extra/index.tsv` and audited by `tools/audit/audit_extra_ports.py` (currently `devel/forgecode` `2.14.0`, `devel/goose` `1.60.2`, and `misc/aichat` `0.30.0`).

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
