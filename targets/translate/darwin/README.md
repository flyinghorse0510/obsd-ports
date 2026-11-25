# `targets/translate/darwin/` — macOS `translate` Target Adapter

Target packaging adapter for `COMPAT_BACKEND=translate COMPAT_PAL=darwin COMPAT_SDK=macosx` (`build/openbsd/<ver>/translate/darwin-macosx/`).

`package_darwin.py` consumes staged standalone arm64 Mach-O port binaries linked against `libobsdcompat`'s `libobsdc-<ver>.a`, strips non-global/debug symbols (`strip -x`), verifies zero host `/opt/homebrew`, `/usr/local`, or `libc++.1.dylib` imports (`otool -L`) and `MH_TWOLEVEL` namespace isolation (`otool -h`), ad-hoc codesigns (`codesign -f -s -`), and emits `bin/<sym>`, `standalone.tsv` (coalescing multi-call aliases), `ports-applets.tsv`, `sysroot/usr/local`, `ports-owners.db`, and `packages/*.tgz` for `sonvori-terminal`'s `scripts/package-macos-runtime.sh`.
