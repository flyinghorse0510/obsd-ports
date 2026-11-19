#!/usr/bin/env python3
"""Target seam stub for `COMPAT_BACKEND=translate COMPAT_PAL=linux`."""
import sys

sys.stderr.write(
    "package_linux (translate/linux): target seam declared in config/matrix/index.tsv; "
    "active lane in v1 is COMPAT_BACKEND=emulate COMPAT_PAL=emscripten.\n"
)
raise SystemExit(2)
