# `obsd-ports` Automated WASM64 Dual-Release Test Suite (`tests/`)

End-to-end verification suite invoked via `make check OPENBSD_VERSION=7.8` and `make check OPENBSD_VERSION=7.9`.

## What `run_wasm_ports_tests.py` Verifies

1. **Build & Package Artifact Integrity (`7.8` and `7.9`)**:
   - Verifies all Wave-1 static libraries (`libbz2.a`, `liblzma.a`, `libzstd.a`, `libonig.a`, `libsqlite3.a`, `liblua5.4.a`, `libcurl.a`), public headers, `ports-applets.tsv`, localized `applets/<sym>.o` closures, `ports.svfs.gz`, `ports-owners.db`, and `.tgz` packages.
2. **Guest WASM64 Multi-Process Execution**:
   - Links all localized port applets with OpenBSD `<version>` guest `libc` (`libobsdc-wasm-<version>.a`) and Emscripten host PAL (`libobsd-wasm-host-<version>.a`), verifying `uname -r` matches the target OpenBSD release (`7.8` or `7.9`).
   - **`archivers/bzip2`**, **`archivers/xz`**, **`archivers/zstd`**: Compress + decompress round-trips across all multi-call entrypoints (`bzip2`/`bunzip2`/`bzcat`, `xz`/`unxz`/`xzcat`/`lzma`/`unlzma`/`lzcat`, `zstd`/`unzstd`/`zstdcat`), verifying byte-exact SHA256 digests.
   - **`textproc/jq`**: JSON structural transforms (`.openbsd.ports | join(",")`) and Oniguruma regex capture/filter pipelines.
   - **`databases/sqlite3`**: Persistent on-disk SQLite database creation, transactions, FTS5/JSON queries, and schema inspection on `/tmp/test.db`.
   - **`lang/lua/5.4`**: `lua54`, `lua` alias, and `luac54` bytecode compilation + execution of Fibonacci, coroutine, and table manipulation scripts.
   - **`sysutils/tree`**: Directory hierarchy rendering of `/usr/local`.
   - **`editors/nano`**: `nano --version` (verifying UTF-8 & nanorc support) AND interactive `openpty()` 80x24 curses terminal editing, UTF-8 text entry, save (`^O`), and clean exit (`^X`).
   - **`net/curl`**: `curl --version` (verifying OpenBSD LibreSSL + `zlib` + `zstd`) AND live HTTP + HTTPS TLS 1.3 (`curl -fsSL https://example.com`) with `/etc/ssl/cert.pem` certificate verification over `SVNP/1`.
