#!/usr/bin/env python3
"""Target seam stub for `COMPAT_BACKEND=emulate COMPAT_PAL=ios`."""
import sys

sys.stderr.write(
    "package_ios (emulate/ios): target seam declared in config/matrix/index.tsv "
    "(iOS/iPadOS arm64 W^X zero-JIT emulate lane); "
    "active lane in v1 is COMPAT_BACKEND=emulate COMPAT_PAL=emscripten.\n"
)
raise SystemExit(2)
