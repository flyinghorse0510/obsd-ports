# `targets/emulate/darwin/` — Target Seam

Target adapter seam for `COMPAT_BACKEND=emulate COMPAT_PAL=darwin` (Darwin arm64 iPhoneOS / iPhoneSimulator crunched Mach-O multi-call emulate lane). Not implemented yet: `package_darwin.py` exits 2.

When implemented it localizes Mach-O `.o` closures with `llvm-objcopy --redefine-sym` against libobsdcompat's darwin emulate `include-root`, and emits `applets/<sym>.o`, `ports-applets.tsv` and `sysroot/usr/local` for the sonvori-terminal iOS/iPadOS app (`apps/ios`), which ingests them through `scripts/stage-rootfs.py` and `scripts/package-runtime.sh`.
