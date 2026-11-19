# `mk/` — Modular GNU Make Hierarchy

`obsd-ports` uses a strict 4-layer Make include graph modeled after `libobsdcompat/mk/`:

1. `mk/root/` — Parser boundary, standalone `clean`/`distclean`, layer dispatch.
2. `mk/config/` — Multi-axis parameterization (`OPENBSD_VERSION`, `COMPAT_BACKEND`, `COMPAT_PAL`, `LIBOBSDCOMPAT_ROOT` declaration).
3. `mk/catalog/` — Active port recipe discovery (`ports/**`) and release catalog pointers.
4. `mk/rules/` — Build, fetch, package, import, catalog listing, verification (`check`), and repository/vendor immutability `audit` targets.
