#!/usr/bin/env python3
"""Enable `--program-prefix=g --enable-single-binary=symlinks` in GNU coreutils (`9.7` & `9.10`)."""
import os
import pathlib

wrksrc = pathlib.Path(os.environ["WRKSRC"])

# 1. Lift the configure guard that blocked --program-prefix with --enable-single-binary=symlinks
cfg_p = wrksrc / "configure"
cfg_st = cfg_p.stat()
cfg_src = cfg_p.read_text(encoding="utf-8")
cfg_needle = '  if ! test "`echo ls | sed \\"$program_transform_name\\"`" = \'ls\'; then'
cfg_repl = "  if false; then"
if cfg_needle in cfg_src:
    cfg_p.write_text(cfg_src.replace(cfg_needle, cfg_repl, 1), encoding="utf-8")
    os.utime(cfg_p, ns=(cfg_st.st_atime_ns, cfg_st.st_mtime_ns))
elif cfg_repl not in cfg_src:
    raise SystemExit(f"patch_multicall.py: expected guard not found in {cfg_p}")

# 2. Teach src/coreutils.c argv[0] dispatch to resolve `g*` aliases (`gls`, `ggid`, `ggod`, `ggpr`, `gcoreutils`)
cu_p = wrksrc / "src/coreutils.c"
cu_st = cu_p.stat()
cu_src = cu_p.read_text(encoding="utf-8")
cu_needle = "  launch_program (prog_name, argc, argv);"
cu_inject = cu_needle + """
  if (prog_name[0] == 'g' && prog_name[1] != '\\0'
      && strcmp (prog_name, "gcoreutils") != 0)
    {
      launch_program (prog_name + 1, argc, argv);
      if (strcmp (prog_name, "ggid") == 0
          || strcmp (prog_name, "ggod") == 0
          || strcmp (prog_name, "ggpr") == 0)
        launch_program (prog_name + 2, argc, argv);
    }
  if (strcmp (prog_name, "gcoreutils") == 0)
    prog_name = (char *) "coreutils";"""

if cu_inject not in cu_src:
    if cu_needle not in cu_src:
        raise SystemExit(f"patch_multicall.py: expected anchor not found in {cu_p}")
    cu_p.write_text(cu_src.replace(cu_needle, cu_inject, 1), encoding="utf-8")
    os.utime(cu_p, ns=(cu_st.st_atime_ns, cu_st.st_mtime_ns))
