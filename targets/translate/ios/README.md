# `targets/translate/ios/` — Target Seam

Target adapter seam for `COMPAT_BACKEND=translate COMPAT_PAL=ios` (`arm64-apple-ios17.4*` / `iphoneos` & `iphonesimulator`, `COMPAT_PAL_VARIANT=ios`).

## iOS / iPadOS W^X & Zero-JIT Invariants

- Enforces strict iOS/iPadOS W^X memory protection with zero JIT code generation (`jit_free = yes`).
- Links standalone `arm64` Mach-O boundary executables statically against `libobsdc-<ver>.a` + `libobsdcompat.a` (`BOUNDARY_SDK` `iphoneos`/`iphonesimulator`) for embedding in `ubibsd` / `BSDRuntime` bundles.
