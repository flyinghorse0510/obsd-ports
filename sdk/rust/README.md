# `sdk/rust/` — Hermetic OpenBSD `devel/cargo` Cross-Compilation SDK

Provides `wasm64-unknown-openbsd.json`, 3D `(OPENBSD_VERSION x COMPAT_BACKEND x COMPAT_PAL)` Rust target mappings across all 7 backend/PAL cells, file-locked hermetic `rustup` (`nightly` + `rust-src`) bootstrap into `.cache/sdk/host-rust`, patched `rust-src` + `libc` overlays, `sdk/bin/obsd-rust-ld`, and `sdk/bin/obsd-cargo`.

## 3D Matrix Target Mapping

| `COMPAT_BACKEND` | `COMPAT_PAL` | Rust Target Spec / Triple | Notes |
| :--- | :--- | :--- | :--- |
| `emulate` | `emscripten` | `sdk/rust/wasm64-unknown-openbsd.json` | Active WASM64 OpenBSD Unix PAL (`pthread` TLS in `obsd_guest_data`, `panic=abort`, `+atomics,+simd128`). |
| `emulate` | `wasi` | `wasm32-wasip2` (`wasm64-wasi` seam) | WASI preview2 headless emulate seam. |
| `emulate` | `darwin` | `aarch64-apple-darwin` | macOS `arm64` Mach-O relocatable applet seam. |
| `emulate` | `ios` | `aarch64-apple-ios` | iOS/iPadOS `arm64` strict W^X zero-JIT Mach-O applet seam. |
| `translate` | `darwin` | `aarch64-apple-darwin` | macOS `arm64` standalone boundary executable seam. |
| `translate` | `ios` | `aarch64-apple-ios` | iOS/iPadOS `arm64` strict W^X zero-JIT standalone boundary seam. |
| `translate` | `linux` | `aarch64-unknown-linux-gnu` | Linux `aarch64` ELF64 standalone boundary seam. |
