# Port Recipes (`ports/`)

Declarative cross-compilation recipes (`port.toml`) for OpenBSD `7.8`, `7.9`, and `8.0` packages built against unmodified upstream metadata in `vendor/openbsd/versions/<version>/ports/`.

## Wave-1 Ports

| Port | Category | Binaries / Applets | Static Libraries |
| :--- | :--- | :--- | :--- |
| `archivers/bzip2` | Archivers | `bzip2`, `bunzip2`, `bzcat`, `bzip2recover` | `libbz2.a` |
| `archivers/xz` | Archivers | `xz`, `unxz`, `xzcat`, `lzma`, `unlzma`, `lzcat` | `liblzma.a` |
| `archivers/zstd` | Archivers | `zstd`, `unzstd`, `zstdcat` | `libzstd.a` |
| `textproc/oniguruma` | Textproc | *(library)* | `libonig.a` |
| `textproc/jq` | Textproc | `jq` | `libjq.a` |
| `databases/sqlite3` | Databases | `sqlite3` | `libsqlite3.a` |
| `lang/lua/5.4` | Languages | `lua54`, `lua`, `luac54` | `liblua5.4.a` |
| `sysutils/tree` | Sysutils | `tree` | — |
| `editors/nano` | Editors | `nano` | — |
| `net/curl` | Network | `curl` | `libcurl.a` |
