# `obsd-ports` — Multi-Release, Multi-Backend OpenBSD Ports Builder & SDK

`obsd-ports` cross-compiles and packages authentic OpenBSD release ports (`7.8`, `7.9`, `8.0`, and future releases) against [`libobsdcompat`](../libobsdcompat) without modifying upstream OpenBSD vendor metadata.

## Multi-Axis Architecture

Every build is parameterized cleanly across three orthogonal axes:

1. **OpenBSD Release (`OPENBSD_VERSION`)**: `8.0` (default), `7.9`, `7.8` — declared in [`config/versions/index.tsv`](config/versions/index.tsv), backed by SHA256-verified official OpenBSD `ports.tar.gz` catalogs (`config/versions/<ver>-catalog.tsv`, ~10,400–10,750+ ports per release) and immutable port subtrees under `vendor/openbsd/versions/<ver>/ports/`.
2. **Compatibility Backend (`COMPAT_BACKEND`)**: `emulate` (default, crunched multi-call relocatable applets) and `translate` (standalone executables).
3. **Platform Abstraction Layer (`COMPAT_PAL`)**: `emscripten` (active v1 WASM64 browser & Node.js guest), with clean target seams for `wasi`, `darwin`, and `linux` declared in [`config/matrix/index.tsv`](config/matrix/index.tsv).

All build outputs isolate cleanly under `build/openbsd/<OPENBSD_VERSION>/<COMPAT_BACKEND>/<COMPAT_PAL>/`.

## Declaring `libobsdcompat` (Declared, Never Searched)

`obsd-ports` consumes `libobsdcompat` headers (`include-root-<ver>`), guest base libraries (`libobsdc-wasm-<ver>.a`), and `wasm_object_tool.py`. Following `libobsdcompat`'s convention, the `libobsdcompat` checkout is **declared, never searched**:

1. Explicit environment or Make variable: `LIBOBSDCOMPAT_ROOT=/abs/path/to/libobsdcompat`
2. Or a gitignored single-line file at the repository root:
   ```sh
   echo /abs/path/to/libobsdcompat > .libobsdcompat-root
   ```

`make clean` works standalone with zero external dependencies.

## Built & Verified Ports Catalog (48 Ports across OpenBSD 7.8, 7.9 & 8.0)

All **48 ports** compile with `sdk/bin/obsd-cc` and `sdk/bin/obsd-c++` (including native WASM64 C++17/23 `libc++.a` + `libc++abi.a` with `-fwasm-exceptions` and per-exec constructor initialization) into **71 localized WASM64 applet closures** (**211** command paths on OpenBSD `7.8`, **207** command paths on OpenBSD `7.9` and `8.0`) plus static `.a` developer libraries, headers, `pkg-config` `.pc` metadata, configs, and manual pages:

| Category & Port | OpenBSD 7.8 | OpenBSD 7.9 | OpenBSD 8.0 | Exported Applets, Wrappers & Static Libraries |
| :--- | :--- | :--- | :--- | :--- |
| **VCS, Build & Dev** | | | | |
| `devel/git` | `2.51.0` | `2.53.0` | `2.55.0` | `git`, `git-remote-http`/`https`/`ftp`/`ftps`, `git-{receive,upload}-pack`, `git-shell`, `libgit.a`, `/usr/local/etc/gitconfig` |
| `devel/gmake` | `4.4.1` | `4.4.1` | `4.4.1` | `gmake` (POSIX pipe jobserver `-jN`) |
| `devel/tig` | `2.6.0` | `2.6.0` | `2.6.1` | `tig` curses Git TUI, `/usr/local/etc/tigrc` |
| `devel/universal-ctags` | `6.1.0` | `6.1.0` | `6.2.1` | `uctags`, `ureadtags` |
| `devel/pcre2` | `10.44` | `10.44` | `10.48` | `pcre2grep`, `pcre2test`, `libpcre2-{8,16,32,posix}.a` |
| `devel/pcre` | `8.45` | `8.45` | `8.45` | `pcregrep`, `pcretest`, `libpcre.a`, `libpcre16.a`, `libpcreposix.a` |
| **Languages & Databases** | | | | |
| `lang/lua/5.4` | `5.4.7` | `5.4.8` | `5.4.8` | `lua54`, `lua`, `luac54`, `liblua5.4.a` |
| `lang/quickjs` | `2024.01.13` | `2024.01.13` | `2024.01.13` | `qjs`, `qjsc`, `libquickjs.a` |
| `lang/jimtcl` | `0.80` | `0.81` | `0.81` | `jimsh`, `libjim.a` (with static SQLite3 + zlib extensions) |
| `lang/gawk` | `5.1.0` | `5.4.0` | `5.4.1` | `gawk` |
| `databases/sqlite3` | `3.50.4` | `3.51.3` | `3.53.2` | `sqlite3`, `libsqlite3.a` (FTS5 + JSON) |
| **Editors & Terminal UI** | | | | |
| `editors/vim` | `9.1.1706` | `9.2.0357` | `9.2.1125` | `vim`, `vimdiff`, `rvim`, `rview`, `xxd`, trimmed `share/vim` runtime |
| `editors/nano` | `8.6` | `8.7.1` | `9.2` | `nano`, `rnano`, syntax highlighting rules |
| `sysutils/ncdu` | `1.22` | `1.22` | `1.22` | `ncdu` curses disk usage analyzer |
| **Search, Text, XML & Markdown** | | | | |
| `sysutils/ugrep` | `7.4.2` | `7.6.0` | `7.8.3` | `ugrep`, `ug`, `ugrep-indexer`, `ug+`/`ugrep+` (WASM64 C++ + PCRE2 + `-z` archive search) |
| `textproc/the_silver_searcher` | `2.2.0` | `2.2.0` | `2.2.0` | `ag` |
| `sysutils/ggrep` | `3.11` | `3.11` | `3.11` | `ggrep`, `gegrep`, `gfgrep` (PCRE2) |
| `textproc/gsed` | `4.9` | `4.9` | `4.9` | `gsed` |
| `textproc/jq` | `1.8.1` | `1.8.1` | `1.8.2` | `jq`, `libjq.a` |
| `textproc/oniguruma` | `6.9.10` | `6.9.10` | `6.9.10` | `libonig.a` |
| `textproc/lowdown` | `2.0.2` | `3.0.1` | `3.1.1` | `lowdown`, `lowdown-diff`, `liblowdown.a` |
| `textproc/libxml` | `2.14.6` | `2.15.3` | `2.15.4` | `xmllint`, `xmlcatalog`, `libxml2.a` |
| `converters/libiconv` | `1.17` | `1.19` | `1.19` | `iconv`, `libiconv.a`, `libcharset.a` |
| `converters/dos2unix` | `7.5.2` | `7.5.5` | `7.5.7` | `dos2unix`, `mac2unix`, `unix2dos`, `unix2mac` |
| **Networking, Web & Sync** | | | | |
| `net/curl` | `8.16.0` | `8.19.0` | `8.22.0` | `curl`, `wcurl`, `libcurl.a` (LibreSSL + `/etc/ssl/cert.pem` + zlib + zstd) |
| `net/wget` | `1.25.0` | `1.25.0` | `1.25.0` | `wget`, `/usr/local/etc/wgetrc` (`ca_certificate = /etc/ssl/cert.pem`) |
| `www/links` | `1.03` | `1.03` | `1.03` | `links` text web browser (TLS SNI + `/etc/ssl/cert.pem` verification) |
| `net/rsync` | `3.4.1` | `3.4.1` | `3.5.1` | `rsync`, `rsync-ssl` (zstd + lz4 + xxh3 + iconv) |
| `net/socat` | `1.7.4.1` | `1.7.4.1` | `1.7.4.1` | `socat`, `procan`, `filan` |
| `net/iperf3` | `3.18` | `3.20` | `3.20` | `iperf3`, `libiperf.a` |
| **Archivers & Checksums** | | | | |
| `archivers/bzip2` | `1.0.8` | `1.0.8` | `1.0.8` | `bzip2`, `bunzip2`, `bzcat`, `bzip2recover`, `bzgrep`, `libbz2.a` |
| `archivers/xz` | `5.8.1` | `5.8.3` | `5.8.4` | `xz`, `unxz`, `xzcat`, `lzma`, `unlzma`, `lzcat`, `xzgrep`, `liblzma.a` |
| `archivers/zstd` | `1.5.7` | `1.5.7` | `1.5.7` | `zstd`, `unzstd`, `zstdcat`, `zstdgrep`, `zstdmt`, `libzstd.a` |
| `archivers/lz4` | `1.10.0` | `1.10.0` | `1.10.0` | `lz4`, `lz4c`, `lz4cat`, `unlz4`, `liblz4.a` |
| `archivers/pigz` | `2.8` | `2.8` | `2.8` | `pigz`, `unpigz` (multi-threaded zlib) |
| `archivers/zip` | `3.0` | `3.0` | `3.0` | `zip`, `zipcloak`, `zipnote`, `zipsplit` |
| `archivers/unzip` | `6.0` | `6.0` | `6.0` | `unzip`, `zipinfo`, `funzip`, `unzipsfx`, `zipgrep` |
| `archivers/gtar` | `1.35` | `1.35` | `1.35` | `gtar` |
| `archivers/libarchive` | `3.8.1` | `3.8.7` | `3.8.9` | `bsdtar`, `bsdcpio`, `bsdcat`, `bsdunzip`, `libarchive.a` |
| `archivers/p7zip` (`7zip` on `8.0`) | `17.06` | `17.06` | `26.03` | `7z`, `7za`, `7zr` (WASM64 C++ with native Wasm exceptions) |
| `sysutils/xxhash` | `0.8.3` | `0.8.3` | `0.8.3` | `xxhsum`, `xxh32sum`, `xxh64sum`, `xxh128sum`, `xxh3sum`, `libxxhash.a` |
| **GNU Core/Find, Sysutils & Graphics** | | | | |
| `sysutils/coreutils` | `9.7` | `9.10` | `9.11` | Single-binary `gcoreutils` + `gls`, `gstat`, `gdate`, `gsha256sum`, `gb2sum`, `gsort`, `gshuf`, `grealpath`, `gnproc`, `ggid`, `ggod`, `ggpr`, ... (`g*` aliases) |
| `misc/findutils` | `4.10.0` | `4.10.0` | `4.10.0` | `gfind`, `gxargs`, `glocate`, `gupdatedb`, `gfrcode` |
| `sysutils/tree` | `0.62` | `0.62` | `0.62` | `tree` |
| `sysutils/pv` | `1.9.34` | `1.10.5` | `1.12.0` | `pv` |
| `sysutils/entr` | `5.7` | `5.7` | `5.8` | `entr` (`kqueue` + VFS `stat` fallback) |
| `graphics/png` | `1.6.50` | `1.6.58` | `1.6.59` | `libpng.a`, `libpng16.a` |
| `graphics/libqrencode` | `4.1.1` | `4.1.1` | `4.1.1` | `qrencode`, `libqrencode.a` |

## Quickstart & Top-Level Make Targets

```sh
# Search the full ~10,750-port OpenBSD release catalog
make list-catalog OPENBSD_VERSION=8.0 FILTER=jq

# Import an unmodified OpenBSD port subtree for all active releases (7.8 + 7.9 + 8.0)
make import PORT=textproc/jq

# List declared port recipes under ports/ and their lane build status
make list OPENBSD_VERSION=8.0
make list OPENBSD_VERSION=7.9
make list OPENBSD_VERSION=7.8

# Fetch & verify distfile SHA256 digests against vendor/.../distinfo
make fetch OPENBSD_VERSION=8.0

# Cross-compile & stage ports into build/openbsd/<ver>/emulate/emscripten/stage
make build OPENBSD_VERSION=8.0
make build OPENBSD_VERSION=7.9
make build OPENBSD_VERSION=7.8

# Package applets/*.o, ports-applets.tsv, sysroot/usr/local, ports.svfs.gz,
# ports-owners.db, and per-port packages/*.tgz
make package OPENBSD_VERSION=8.0
make package OPENBSD_VERSION=7.9
make package OPENBSD_VERSION=7.8

# Run SDK + full 48-port WASM64 verification suites (Wave-1 + Foundation + Wave-2 Slices A-D)
make check OPENBSD_VERSION=8.0
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
- [`docs/sdk-and-targets.md`](docs/sdk-and-targets.md) — `sdk/bin/obsd-*` cross-compiler flags (`obsd-cc`, `obsd-c++`), `config.site`, CMake toolchain, and `targets/` packaging adapters.
