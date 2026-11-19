# `targets/emulate/darwin/` — Target Seam

Target adapter seam for `COMPAT_BACKEND=emulate COMPAT_PAL=darwin` (Darwin arm64 / iOS simulator crunched Mach-O multi-call emulate lane). Localizes Mach-O `.o` closures with `llvm-objcopy --redefine-sym` and packages `/usr/local` overlays for `ubibsd` / `BSDRuntime`.
