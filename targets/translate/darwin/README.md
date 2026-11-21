# `targets/translate/darwin/` — Target Seam

Target adapter seam for `COMPAT_BACKEND=translate COMPAT_PAL=darwin` (native standalone arm64 Mach-O executables linked against libobsdcompat's macOS translate boundary, `libobsdc-<ver>.a` + `libobsdcompat.a`). Not implemented yet: `package_darwin.py` exits 2.

When implemented it emits `sysroot/usr/local` (executables, data, man pages) and `packages/`, for the sonvori-terminal macOS app (`apps/macos`), which bundles them via `scripts/package-macos-runtime.sh`.
