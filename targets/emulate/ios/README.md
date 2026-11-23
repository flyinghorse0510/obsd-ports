# `targets/emulate/ios/` — Target Seam

Target adapter seam for `COMPAT_BACKEND=emulate COMPAT_PAL=ios` (`arm64-apple-ios17.4*` / `iphoneos` & `iphonesimulator`, `COMPAT_PAL_VARIANT=ios`).

## iOS / iPadOS W^X & Zero-JIT Invariants

- Strict hardware/kernel W^X enforcement (`MAP_JIT` is unavailable to standard App Store / embedded processes).
- All guest ports targeting `emulate/ios` MUST be 100% AOT-compiled and JIT-free (no runtime code generation or executable page remapping).
- Localizes static `arm64` Mach-O `.o` applet closures via `llvm-objcopy --redefine-sym` into a single crunched multi-call binary and stages `/usr/local` bundle overlays for `ubibsd` / `BSDRuntime`.
