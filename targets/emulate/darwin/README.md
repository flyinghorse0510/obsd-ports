# `targets/emulate/darwin/` — iOS & Simulator `emulate` Target Adapter

Target packaging adapter for `COMPAT_BACKEND=emulate COMPAT_PAL=darwin COMPAT_SDK=iphonesimulator|iphoneos` (`build/openbsd/<ver>/emulate/darwin-<sdk>/`).

`package_darwin.py` localizes arm64 Mach-O relocatable port partials into `applets/<sym>.o` (`_obsd_applet_<sym>_main` sole external symbol, zero `(common)` tentative symbols, zero Mach-O `__thread_*` TLV sections, zero `__TEXT,__gcc_except_tab` sections, and zero `__DATA,__mod_init_func` sections via `libobsdcompat`'s `retype_guest_initializers.py`), and emits `ports-test-applets.tsv`, `ports-applets.tsv`, `sysroot/usr/local`, `ports-owners.db`, and `packages/*.tgz` for `sonvori-terminal`'s `scripts/package-runtime.sh` and `scripts/stage-rootfs.py`.
