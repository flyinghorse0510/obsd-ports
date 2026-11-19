# `mk/rules/`

Top-level build & governance rules:
- `vendor.mk` — `make sync-vendor`, `make import PORT=cat/name`, `make list-catalog [FILTER=...]`.
- `ports.mk` — `make list`, `make fetch`, `make build`, `make package` (parameterized by `OPENBSD_VERSION`, `COMPAT_BACKEND`, `COMPAT_PAL`, `PORT`).
- `check.mk` — `make check` invoking `tools/testing/run_check.py` (SDK/builder verification + `tests/run_wasm_ports_tests.py` when present).
- `audit.mk` — `make audit` verifying vendor immutability, Make hierarchy, tree layout, and backend × PAL matrix seams.
