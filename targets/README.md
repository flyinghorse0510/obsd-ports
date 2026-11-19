# `targets/` — Backend × PAL Packaging Adapters

Each directory `targets/<backend>/<pal>/` implements the final packaging phase (`make package`) for its target cell in `config/matrix/index.tsv`:

- `targets/emulate/emscripten/` (**Active v1**): Localizes staged WASM64 binaries into `applets/<sym>.o`, emits `ports-applets.tsv`, stages `/usr/local` into `sysroot/usr/local/...` + `ports.svfs.gz` + `ports-owners.db`, emits per-port `packages/<pkgname>.tgz`, and provides `merge_wasm_guest.py` for linking standalone or full-machine WASM64 guest runtimes.
- `targets/emulate/wasi/` (**Seam**): Headless WASI preview2 WASM64 emulate adapter seam.
- `targets/emulate/darwin/` (**Seam**): Darwin arm64 / iOS simulator crunched Mach-O emulate adapter seam.
- `targets/translate/darwin/` (**Seam**): macOS / iOS native standalone Mach-O translate boundary adapter seam.
- `targets/translate/linux/` (**Seam**): Linux aarch64/x86_64 native ELF64 translate boundary adapter seam.
