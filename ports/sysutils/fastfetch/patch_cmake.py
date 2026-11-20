#!/usr/bin/env python3
"""Adapt fastfetch CMakeLists.txt & platform stubs for OpenBSD WASM64 guest."""
from __future__ import annotations

import pathlib
import re
import sys


def main() -> int:
    wrksrc = pathlib.Path(sys.argv[1])
    cm_path = wrksrc / "CMakeLists.txt"
    cm = cm_path.read_text(encoding="utf-8")

    # Replace hardware ioctl/sndio modules unavailable in headless WASM64 guest with nosupport stubs
    replacements = {
        "src/detection/sound/sound_obsd.c": "src/detection/sound/sound_nosupport.c",
        "src/detection/bootmgr/bootmgr_bsd.c": "src/detection/bootmgr/bootmgr_nosupport.c",
        "src/detection/brightness/brightness_obsd.c": "src/detection/brightness/brightness_nosupport.c",
        "src/detection/gpu/gpu_obsd.c": "src/detection/gpu/gpu_nosupport.c",
        "src/detection/gpu/gpu_bsd.c": "src/detection/gpu/gpu_nosupport.c",
    }
    for old_rel, new_rel in replacements.items():
        cm = cm.replace(old_rel, new_rel)

    # Remove BSD DRM helper (uses <dev/pci/pcireg.h>) and libsndio link target
    cm = re.sub(r"^\s*src/detection/gpu/gpu_bsddrm\.c\s*\n", "", cm, flags=re.M)
    cm = re.sub(r'^\s*PRIVATE\s+"sndio"\s*\n', "", cm, flags=re.M)
    cm_path.write_text(cm, encoding="utf-8")

    sound_ns = wrksrc / "src/detection/sound/sound_nosupport.c"
    if not sound_ns.exists():
        sound_ns.write_text(
            '#include "sound.h"\n'
            "const char* ffDetectSound(FFSoundOptions* options, FFlist* devices) {\n"
            "    (void) options;\n"
            "    (void) devices;\n"
            '    return "Not supported on this platform";\n'
            "}\n",
            encoding="utf-8",
        )

    gpu_ns = wrksrc / "src/detection/gpu/gpu_nosupport.c"
    if not gpu_ns.exists():
        gpu_ns.write_text(
            '#include "gpu.h"\n'
            "const char* ffDetectGPUImpl(const FFGPUOptions* options, FFlist* gpus) {\n"
            "    (void) options;\n"
            "    (void) gpus;\n"
            '    return "Not supported on this platform";\n'
            "}\n",
            encoding="utf-8",
        )

    # Guard ELF dl_iterate_phdr behind __ELF__ so static WASM64 uses the fallback stub
    for lib_c in wrksrc.joinpath("src").rglob("library.c"):
        txt = lib_c.read_text(encoding="utf-8")
        if "__has_include(<link.h>)" in txt and "defined(__ELF__)" not in txt:
            lib_c.write_text(
                txt.replace("__has_include(<link.h>)", "defined(__ELF__) && __has_include(<link.h>)"),
                encoding="utf-8",
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
