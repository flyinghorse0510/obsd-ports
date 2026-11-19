#!/usr/bin/env python3
"""Target seam stub for `COMPAT_BACKEND=emulate COMPAT_PAL=wasi`."""
import sys

sys.stderr.write(
    "package_wasm (emulate/wasi): target seam declared in config/matrix/index.tsv; "
    "active WASM64 lane in v1 is COMPAT_BACKEND=emulate COMPAT_PAL=emscripten.\n"
)
raise SystemExit(2)
