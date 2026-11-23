#!/usr/bin/env python3
"""Ensure ggml.pc is staged in usr/local/lib/pkgconfig and lists all static ggml archives."""
from __future__ import annotations

import pathlib
import shutil
import sys

if len(sys.argv) >= 3 and sys.argv[1] == "--pre-configure":
    wrksrc = pathlib.Path(sys.argv[2])
    ops_h = wrksrc / "src/ggml-cpu/ops.h"
    if ops_h.is_file():
        s = ops_h.read_text(encoding="utf-8")
        if "hardware_destructive_interference_size" in s:
            ops_h.write_text(
                s.replace("#if defined(__cpp_lib_hardware_interference_size)", "#if 0"),
                encoding="utf-8",
            )
    raise SystemExit(0)

stage = pathlib.Path(sys.argv[1])
lib_pc = stage / "usr/local/lib/pkgconfig/ggml.pc"
share_pc = stage / "usr/local/share/pkgconfig/ggml.pc"

src_pc = lib_pc if lib_pc.is_file() else (share_pc if share_pc.is_file() else None)
if src_pc is None:
    raise SystemExit("fix_pc.py: ggml.pc not found after cmake --install")

lib_dir = stage / "usr/local/lib"
have_cpu = (lib_dir / "libggml-cpu.a").is_file()
have_base = (lib_dir / "libggml-base.a").is_file()

lines = []
for raw in src_pc.read_text(encoding="utf-8").splitlines():
    if raw.startswith("Libs:"):
        libs = ["-L${libdir}", "-lggml"]
        if have_cpu:
            libs.append("-lggml-cpu")
        if have_base:
            libs.append("-lggml-base")
        libs.extend(["-lm", "-lpthread"])
        lines.append("Libs: " + " ".join(libs))
    else:
        lines.append(raw)

text = "\n".join(lines) + "\n"
lib_pc.parent.mkdir(parents=True, exist_ok=True)
lib_pc.write_text(text, encoding="utf-8")
if share_pc.is_file():
    share_pc.write_text(text, encoding="utf-8")
