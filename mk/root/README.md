# `mk/root/`

Entrypoint Make layer included by top-level `Makefile`. Dispatches `clean` and `distclean` standalone without requiring `LIBOBSDCOMPAT_ROOT`, and otherwise loads `config -> catalog -> rules` in strict order.
