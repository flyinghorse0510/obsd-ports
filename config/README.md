# `config/` — Multi-Axis Release & Target Matrix Configuration

- `config/versions/` — OpenBSD release axis (`index.tsv`, `<ver>.mk`, and full ~12,000-port `<ver>-catalog.tsv`). Adding a future release (`8.0`) requires only adding a row in `config/versions/index.tsv` and `config/versions/8.0.mk`, then running `make sync-vendor`.
- `config/matrix/` — Backend (`emulate`, `translate`) × PAL (`emscripten`, `wasi`, `darwin`, `linux`) target matrix (`index.tsv`, `backends/*.mk`, `pals/*.mk`).
