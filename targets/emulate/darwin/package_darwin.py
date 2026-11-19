#!/usr/bin/env python3
"""Target seam stub for `COMPAT_BACKEND=emulate COMPAT_PAL=darwin`."""
import sys

sys.stderr.write(
    "package_darwin (emulate/darwin): target seam declared in config/matrix/index.tsv; "
    "active lane in v1 is COMPAT_BACKEND=emulate COMPAT_PAL=emscripten.\n"
)
raise SystemExit(2)
