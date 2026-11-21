#!/usr/bin/env python3
"""obsd_env.py -- host-environment helpers shared by obsd-ports tools.

`ensure_emsdk_python()`: emsdk's `emcc`/`em++`/`emar` shell launchers run
`$EMSDK_PYTHON` (else whatever `python3` is first on PATH, which is 3.9 on
stock macOS and too old for emsdk). Pin it once, before any emsdk tool runs:
an explicit `$EMSDK_PYTHON` wins, then emsdk's bundled python
(`$LIBOBSDCOMPAT_ROOT/deps/emsdk/python/<ver>/bin/python3`), then the running
interpreter. Children inherit it through os.environ.
"""
from __future__ import annotations

import os
import pathlib
import sys


def ensure_emsdk_python(obsd_root: "pathlib.Path | str | None") -> str:
    cur = os.environ.get("EMSDK_PYTHON", "").strip()
    if cur:
        return cur
    chosen = sys.executable
    if obsd_root:
        bundled = sorted(pathlib.Path(obsd_root).glob("deps/emsdk/python/*/bin/python3"))
        if bundled:
            chosen = str(bundled[-1])
    os.environ["EMSDK_PYTHON"] = chosen
    return chosen
