# `targets/emulate/wasi/` — Target Seam

Target adapter seam for `COMPAT_BACKEND=emulate COMPAT_PAL=wasi` (WASI preview2 WASM64 guest). Shares the WASM64 relocatable applet format (`wasm_object_tool.py localize-applet` + `window-guest`) with `emulate/emscripten`, substituting a WASI host PAL archive at final link time.
