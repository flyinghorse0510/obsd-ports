# `extra/` — First-Class OpenBSD-Style Extra Ports Section

`extra/<category>/<name>/` hosts self-contained OpenBSD-style port directories for software not yet present in official OpenBSD `7.8`, `7.9`, or `8.0` `ports.tar.gz` trees, while keeping `vendor/openbsd/versions/<ver>/ports/` 100% immutable.

## Per-Port Contract (`extra/<category>/<name>/`)

1. `Makefile` — Authentic OpenBSD `bsd.port.mk` Makefile (`COMMENT`, `DISTNAME`/`PKGNAME`, `GH_*` or `DIST_TUPLE`, `CATEGORIES`, `HOMEPAGE`, `PERMIT_PACKAGE = Yes`, optional `MODULES = devel/cargo` + `.include "crates.inc"`, `.include <bsd.port.mk>`).
2. `crates.inc` *(optional, for `MODULES = devel/cargo`)* — `MODCARGO_CRATES += <crate> <ver> # <license>` lines generated via `tools/extra/gen_cargo_distinfo.py`.
3. `distinfo` — OpenBSD `SHA256 (<file>) = <base64>` and `SIZE (<file>) = <bytes>` pairs covering main tarballs, `DIST_TUPLE` archives, and `cargo/<crate>-<ver>.tar.gz` crates.
4. `pkg/DESCR` — Package description (`<= 80` columns).
5. `pkg/PLIST` — Packing list relative to `/usr/local` (`@bin bin/<name>`, manpages, completions, docs).
6. `patches/patch-*` *(optional)* — Unified diffs (`-p0` relative to `$WRKSRC`), applied once in `work/` without mutating `extra/`.
7. `port.toml` — Declarative 3D matrix recipe (`build_style = "cargo"` | `"gnu"` | `"cmake"` | `"make"` | `"script"`, `depends` across `ports/*` and `extra/*`, `[[applets]]`, and optional `[versions.*]` / `[backends.*]` / `[pals.*]` / `[targets.*]` / `[matrix.*]` overrides).
