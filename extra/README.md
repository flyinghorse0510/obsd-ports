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

## Current JIT-Free `extra/` Ports (`config/extra/index.tsv`)

All `extra/` ports enforce strict W^X / WASM64 / iOS zero-JIT compliance (`0` `wasmtime`, `cranelift`, `v8`, `deno_core`, `luajit`, or `pcre2_jit` symbols), keep valid 5-cell 3D matrix sections (`emulate/{emscripten,wasi,darwin}` + `translate/{darwin,linux}`), and build cleanly across OpenBSD `7.8`, `7.9`, and `8.0` on `emulate/emscripten`:

| Port | Package | Upstream | Exported Binaries & Highlights |
| :--- | :--- | :--- | :--- |
| `devel/forgecode` | `forgecode-2.14.0` | `antinomyhq/forge` | `/usr/local/bin/forge`, `/usr/local/bin/forgecode`, zsh integration (`share/forgecode/*.zsh`), autonomous coding agent (`read`, `fs_search`, `write`, `patch`, `shell`), SQLite `.forge.db` |
| `devel/goose` | `goose-1.60.2` | `block/goose` | `/usr/local/bin/goose`, multi-turn `developer` extension, pure-Rust `boa_engine` JS `code-mode` tool orchestration, MCP client, SQLite `sessions.db` |
| `misc/aichat` | `aichat-0.30.0` | `sigoden/aichat` | `/usr/local/bin/aichat`, bash/fish/zsh completions, SSE chat, `-e` shell assistant, `--session`, `hnsw_rs` + `bm25` `--rag`, `--agent`, PTY `--repl`, `--serve` (`/v1/*`, `/playground`, `/arena`) |

## Building, Auditing & Testing `extra/`

```sh
make list-extra OPENBSD_VERSION=8.0
make build package SECTION=extra OPENBSD_VERSION=8.0 JOBS=16
make audit-extra
python3 -I tests/wave5_extra_ai_agents.py --openbsd-version all
```
