# `mk/config/`

Multi-axis build configuration:
- `layout.mk` — Canonical repository roots (`config/`, `vendor/`, `ports/`, `sdk/`, `targets/`, `tools/`, `tests/`).
- `versions.mk` — OpenBSD release axis (`OPENBSD_VERSION`, validated against `config/versions/<ver>.mk`).
- `matrix.mk` — Backend × PAL target axis (`COMPAT_BACKEND` × `COMPAT_PAL`, computing `build/openbsd/<ver>/<backend>/<pal>/`).
- `dependencies.mk` — Strict declared-never-searched resolution of `LIBOBSDCOMPAT_ROOT` / `.libobsdcompat-root`.
