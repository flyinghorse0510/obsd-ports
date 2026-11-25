#!/usr/bin/env python3
"""
obsd_rust.py -- Hermetic OpenBSD `MODULES = devel/cargo` SDK & Linker Driver.

Implements:
  1. 3D matrix target mapping (`(OPENBSD_VERSION, COMPAT_BACKEND, COMPAT_PAL)` ->
     `wasm64-unknown-openbsd.json` on `emulate/emscripten` and seam triples across
     the canonical 5-cell matrix `emulate/{emscripten,wasi,darwin}` and
     `translate/{darwin,linux}`, resolving `COMPAT_SDK` on `darwin` so
     `emulate/darwin` maps to `aarch64-apple-ios-sim` / `aarch64-apple-ios` and
     `translate/darwin` maps to `aarch64-apple-darwin`).
  2. Idempotent, file-locked bootstrap of `rustup` (`nightly` + `rust-src`) into
     `.cache/sdk/host-rust` so concurrent invocations never race.
  3. Idempotent, file-locked preparation of:
       - `.cache/sdk/rust-sysroot-wasm64-<key>/`: symlinked nightly toolchain with
         patched `rust-src` (`stdarch`, `unwind`, `std/personality`,
         `compiler-builtins/float/cmp.rs`, and `vendor/libc`),
       - `.cache/sdk/rust-libc-wasm64-<key>/`: standalone zero-dependency patched
         OpenBSD `wasm64` (`aarch64` ABI layout) `libc` overlay for `[patch.crates-io]`,
       - `.cache/sdk/rust-unwind-<ver>-<key>/unwind_stub.o`: weak `_Unwind_*` &
         `backtrace*` stubs for `-C panic=abort`.
  4. `obsd-rust-ld`: Expands `@rspfile` linker arguments, translates `wasm-lld`
     flags to `sdk/bin/obsd-cc -nostdlib`, strips DWARF debug sections (`--strip-debug`)
     while preserving WebAssembly `linking` symbol tables for `wasm_object_tool.py`,
     promotes read-only relocatable segments (`.data.rel.ro` -> `.rodata.rel.ro`,
     `.data.rel.ro.*` -> `.rodata.rel.ro.*`) so `wasm_object_tool.py window-guest`
     keeps Rust trait vtables and `const` pointer tables out of per-process mutable
     `obsd_guest_data`, drops `-lcompiler_rt`/`-lexecinfo`/`-lunwind`, and links
     `unwind_stub.o`.
  5. `obsd-cargo`: Extracts `.cache/distfiles/cargo/<crate>-<ver>.tar.gz` into
     `$WRKBUILD/modcargo-crates/<crate>-<ver>` with `.cargo-checksum.json`, writes
     `$WRKBUILD/.cargo-home/config.toml` vendoring `[source.crates-io]` + any
     `Cargo.lock` `git+...` sources for 100% `--offline` builds, wires `[patch.crates-io]`
     for the `wasm64` OpenBSD `libc` overlay + port-supplied crate patches, isolates
     host vs target `CC`/`CXX`/`AR`/`PKG_CONFIG` (`HOST_CC=/usr/bin/clang`), and runs
     `cargo` with `AWS_LC_SYS_CMAKE_BUILDER=0`, `ONIGURUMA_NO_PKG_CONFIG=1`,
     `profile.release.strip="debuginfo"`, and `profile.release.lto=false`.
"""
from __future__ import annotations

import concurrent.futures
import fcntl
import hashlib
import json
import os
import pathlib
import platform
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import urllib.parse
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

SDK_RUST_DIR = pathlib.Path(__file__).resolve().parent
SDK_ROOT = SDK_RUST_DIR.parent
REPO_ROOT = SDK_ROOT.parent

PATCH_SCHEMA_VERSION = "obsd-wasm64-rust-v1"

# Canonical 5-cell Backend x PAL Rust target matrix
MATRIX_RUST_TARGETS: Dict[Tuple[str, str], Dict[str, Any]] = {
    ("emulate", "emscripten"): {
        "status": "active",
        "kind": "custom_json",
        "target_name": "wasm64-unknown-openbsd",
        "target_spec_rel": "sdk/rust/wasm64-unknown-openbsd.json",
        "cargo_env_suffix": "wasm64_unknown_openbsd",
        "cargo_upper_suffix": "WASM64_UNKNOWN_OPENBSD",
        "needs_build_std": True,
        "jit_free": True,
        "notes": "WASM64 OpenBSD Unix PAL emulate guest (Browser & Node.js)",
    },
    ("emulate", "wasi"): {
        "status": "seam",
        "kind": "builtin",
        "target_name": "wasm32-wasip2",
        "seam_wasm64_target": "wasm64-wasi",
        "cargo_env_suffix": "wasm32_wasip2",
        "cargo_upper_suffix": "WASM32_WASIP2",
        "needs_build_std": False,
        "jit_free": True,
        "notes": "WASI preview2 headless emulate seam (wasm64-wasi relocatable closure seam)",
    },
    ("emulate", "darwin"): {
        "status": "seam",
        "kind": "builtin",
        "target_name": "aarch64-apple-ios-sim",
        "cargo_env_suffix": "aarch64_apple_ios_sim",
        "cargo_upper_suffix": "AARCH64_APPLE_IOS_SIM",
        "needs_build_std": False,
        "jit_free": True,
        "notes": "iOS/iPadOS & Darwin arm64 strict W^X zero-JIT Mach-O emulate seam (COMPAT_SDK=iphonesimulator|iphoneos|macosx)",
    },
    ("translate", "darwin"): {
        "status": "seam",
        "kind": "builtin",
        "target_name": "aarch64-apple-darwin",
        "cargo_env_suffix": "aarch64_apple_darwin",
        "cargo_upper_suffix": "AARCH64_APPLE_DARWIN",
        "needs_build_std": False,
        "jit_free": True,
        "notes": "macOS arm64 standalone Mach-O translate boundary seam (COMPAT_SDK=macosx)",
    },
    ("translate", "linux"): {
        "status": "seam",
        "kind": "builtin",
        "target_name": "aarch64-unknown-linux-gnu",
        "cargo_env_suffix": "aarch64_unknown_linux_gnu",
        "cargo_upper_suffix": "AARCH64_UNKNOWN_LINUX_GNU",
        "needs_build_std": False,
        "jit_free": True,
        "notes": "Linux aarch64 ELF64 standalone translate boundary seam",
    },
}

DROPPED_RUST_LIBS: Set[str] = {
    "compiler_rt",
    "execinfo",
    "unwind",
    "gcc",
    "gcc_s",
    "gcc_eh",
    "dl",
    "rt",
    "System",
    "resolv",
}

CARGO_BUILD_SUBCOMMANDS: Set[str] = {
    "build",
    "b",
    "check",
    "c",
    "rustc",
    "test",
    "t",
    "bench",
    "install",
}


def die(msg: str, code: int = 1) -> "NoReturn":
    sys.stderr.write(f"obsd-rust: {msg}\n")
    raise SystemExit(code)


def resolve_cache_sdk_dir() -> pathlib.Path:
    cache_env = os.environ.get("OBSD_CACHE_ROOT", "").strip()
    base = pathlib.Path(cache_env).resolve() if cache_env else (REPO_ROOT / ".cache")
    sdk_cache = base / "sdk"
    sdk_cache.mkdir(parents=True, exist_ok=True)
    return sdk_cache


def resolve_distfiles_dir() -> pathlib.Path:
    cache_env = os.environ.get("OBSD_CACHE_ROOT", "").strip()
    base = pathlib.Path(cache_env).resolve() if cache_env else (REPO_ROOT / ".cache")
    d = base / "distfiles"
    d.mkdir(parents=True, exist_ok=True)
    return d


def resolve_libobsdcompat_root() -> pathlib.Path:
    env_val = os.environ.get("LIBOBSDCOMPAT_ROOT", "").strip()
    if env_val:
        p = pathlib.Path(env_val).resolve()
        if not (p / "vendor/openbsd/versions").is_dir():
            die(f"LIBOBSDCOMPAT_ROOT={p} has no vendor/openbsd/versions")
        return p
    locator = REPO_ROOT / "tools/config/locate-libobsdcompat.sh"
    proc = subprocess.run(["sh", str(locator)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr)
        raise SystemExit(proc.returncode)
    return pathlib.Path(proc.stdout.strip()).resolve()


def resolve_rust_matrix_target(
    openbsd_version: str,
    backend: str,
    pal: str,
    sdk: str = "",
) -> Dict[str, Any]:
    cell = MATRIX_RUST_TARGETS.get((backend, pal))
    if cell is None:
        die(
            f"unsupported (COMPAT_BACKEND, COMPAT_PAL)=({backend!r}, {pal!r}); "
            f"expected one of: {', '.join(f'{b}/{p}' for b, p in sorted(MATRIX_RUST_TARGETS))}"
        )
    out = dict(cell)
    out["openbsd_version"] = openbsd_version
    out["backend"] = backend
    out["pal"] = pal
    if pal == "darwin":
        resolved_sdk = (sdk or os.environ.get("COMPAT_SDK", "")).strip()
        if not resolved_sdk:
            resolved_sdk = "macosx" if backend == "translate" else "iphonesimulator"
        if backend == "translate":
            if resolved_sdk != "macosx":
                die(f"Darwin translate supports only COMPAT_SDK=macosx (got {resolved_sdk!r})")
            target_triple = "aarch64-apple-darwin"
        else:
            if resolved_sdk == "iphoneos":
                target_triple = "aarch64-apple-ios"
            elif resolved_sdk == "iphonesimulator":
                target_triple = "aarch64-apple-ios-sim"
            elif resolved_sdk == "macosx":
                target_triple = "aarch64-apple-darwin"
            else:
                die(
                    "Darwin emulate supports COMPAT_SDK=iphonesimulator|iphoneos|macosx "
                    f"(got {resolved_sdk!r})"
                )
        out["sdk"] = resolved_sdk
        out["target_name"] = target_triple
        out["cargo_env_suffix"] = target_triple.replace("-", "_")
        out["cargo_upper_suffix"] = target_triple.replace("-", "_").upper()
    if out["kind"] == "custom_json":
        spec_path = (REPO_ROOT / out["target_spec_rel"]).resolve()
        if not spec_path.is_file():
            die(f"missing Rust target spec file: {spec_path}")
        out["target_arg"] = str(spec_path)
    else:
        out["target_arg"] = out["target_name"]
    return out


def ensure_host_rust(cache_sdk: pathlib.Path) -> Dict[str, Any]:
    """
    Idempotently bootstrap hermetic `rustup` (`nightly` + `rust-src`) into
    `.cache/sdk/host-rust` under an exclusive `flock` so concurrent builds never race.
    """
    host_rust = cache_sdk / "host-rust"
    rustup_home = host_rust / "rustup"
    cargo_home = host_rust / "cargo"
    bin_dir = cargo_home / "bin"
    rustup_bin = bin_dir / "rustup"
    rustc_bin = bin_dir / "rustc"
    cargo_bin = bin_dir / "cargo"

    def _probe_ready() -> Optional[Dict[str, Any]]:
        if not (rustup_bin.is_file() and rustc_bin.is_file() and cargo_bin.is_file()):
            return None
        env = dict(os.environ)
        env["RUSTUP_HOME"] = str(rustup_home)
        env["CARGO_HOME"] = str(cargo_home)
        p_sys = subprocess.run(
            [str(rustc_bin), "+nightly", "--print", "sysroot"],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        if p_sys.returncode != 0:
            return None
        sysroot = pathlib.Path(p_sys.stdout.strip())
        if not (sysroot / "lib/rustlib/src/rust/library/Cargo.toml").is_file():
            return None
        p_vv = subprocess.run(
            [str(rustc_bin), "+nightly", "-vV"],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        if p_vv.returncode != 0:
            return None
        vv_txt = p_vv.stdout
        host_triple = ""
        for ln in vv_txt.splitlines():
            if ln.startswith("host:"):
                host_triple = ln.split(":", 1)[1].strip()
                break
        p_cargo = subprocess.run(
            [str(rustup_bin), "which", "--toolchain", "nightly", "cargo"],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        real_cargo = pathlib.Path(p_cargo.stdout.strip()) if p_cargo.returncode == 0 and p_cargo.stdout.strip() else cargo_bin
        return {
            "host_rust": host_rust,
            "rustup_home": rustup_home,
            "cargo_home": cargo_home,
            "sysroot": sysroot,
            "real_rustc": sysroot / "bin/rustc",
            "real_rustdoc": sysroot / "bin/rustdoc",
            "real_cargo": real_cargo,
            "rustc_vv": vv_txt,
            "host_triple": host_triple or f"{platform.machine() or 'aarch64'}-unknown-linux-gnu",
        }

    ready = _probe_ready()
    if ready is not None:
        return ready

    lock_path = cache_sdk / "host-rust.lock"
    with lock_path.open("w") as lock_fp:
        fcntl.flock(lock_fp.fileno(), fcntl.LOCK_EX)
        ready = _probe_ready()
        if ready is not None:
            return ready

        print(f"  [obsd-rust] bootstrapping hermetic rustup (nightly + rust-src) -> {host_rust}...", file=sys.stderr)
        rustup_home.mkdir(parents=True, exist_ok=True)
        cargo_home.mkdir(parents=True, exist_ok=True)
        boot_env = dict(os.environ)
        boot_env["RUSTUP_HOME"] = str(rustup_home)
        boot_env["CARGO_HOME"] = str(cargo_home)
        boot_env["RUSTUP_INIT_SKIP_PATH_CHECK"] = "yes"

        if not rustup_bin.is_file():
            with tempfile.NamedTemporaryFile(prefix="obsd-rustup-init-", suffix=".sh", delete=False) as tf:
                init_sh = pathlib.Path(tf.name)
            try:
                subprocess.run(
                    [
                        "curl",
                        "--proto",
                        "=https",
                        "--tlsv1.2",
                        "-fL",
                        "--retry",
                        "3",
                        "--connect-timeout",
                        "15",
                        "-sS",
                        "-o",
                        str(init_sh),
                        "https://sh.rustup.rs",
                    ],
                    env=boot_env,
                    check=True,
                )
                subprocess.run(
                    [
                        "sh",
                        str(init_sh),
                        "-y",
                        "--no-modify-path",
                        "--profile",
                        "minimal",
                        "--default-toolchain",
                        "nightly",
                        "-c",
                        "rust-src",
                    ],
                    env=boot_env,
                    check=True,
                )
            finally:
                init_sh.unlink(missing_ok=True)
        else:
            subprocess.run(
                [str(rustup_bin), "toolchain", "install", "nightly", "--profile", "minimal", "-c", "rust-src"],
                env=boot_env,
                check=True,
            )

        ready = _probe_ready()
        if ready is None:
            die(f"hermetic rustup bootstrap finished but nightly + rust-src not usable in {host_rust}")
        return ready


def patch_openbsd_libc_tree(libc_dir: pathlib.Path, strip_std_workspace_dep: bool = False) -> bool:
    """
    Idempotently patch a `libc` 0.2.x crate source tree so `target_arch = "wasm64"` +
    `target_os = "openbsd"` uses OpenBSD's LP64 `aarch64` struct/constant layout
    (matching `libobsdcompat`'s `include-root-<ver>/.machine == arm64`) without
    linking `-lexecinfo`.
    """
    mod_rs = libc_dir / "src/unix/bsd/netbsdlike/openbsd/mod.rs"
    if not mod_rs.is_file():
        return False

    orig = mod_rs.read_text(encoding="utf-8")
    txt = orig

    # 1. Remove/guard `#[link(name = "execinfo")]` on wasm64
    if '#[cfg_attr(not(target_arch = "wasm64"), link(name = "execinfo"))]' not in txt:
        txt = txt.replace(
            '#[link(name = "execinfo")]',
            '#[cfg_attr(not(target_arch = "wasm64"), link(name = "execinfo"))]',
        )

    # 2. Route `wasm64` to OpenBSD `aarch64` module
    if 'if #[cfg(any(target_arch = "aarch64", target_arch = "wasm64"))]' not in txt:
        if 'if #[cfg(target_arch = "aarch64")]' not in txt:
            die(f"expected `if #[cfg(target_arch = \"aarch64\")]` in {mod_rs}")
        txt = txt.replace(
            'if #[cfg(target_arch = "aarch64")]',
            'if #[cfg(any(target_arch = "aarch64", target_arch = "wasm64"))]',
            1,
        )

    if txt != orig:
        mod_rs.write_text(txt, encoding="utf-8")

    if strip_std_workspace_dep:
        cargo_toml = libc_dir / "Cargo.toml"
        if cargo_toml.is_file():
            ct_orig = cargo_toml.read_text(encoding="utf-8")
            ct = re.sub(
                r'\n*\[dependencies\.rustc-std-workspace-core\]\s*\n(?:[^\n\[][^\n]*\n)*',
                "\n",
                ct_orig,
            )
            ct = ct.replace('"rustc-std-workspace-core",', "").replace('"rustc-std-workspace-core"', "")
            if ct != ct_orig:
                cargo_toml.write_text(ct, encoding="utf-8")

    cksum = libc_dir / ".cargo-checksum.json"
    if cksum.is_file():
        try:
            old_ck = json.loads(cksum.read_text(encoding="utf-8"))
            pkg_hash = old_ck.get("package")
        except Exception:
            pkg_hash = None
        cksum.write_text(json.dumps({"files": {}, "package": pkg_hash}) + "\n", encoding="utf-8")
    elif not strip_std_workspace_dep:
        cksum.write_text('{"files":{}}\n', encoding="utf-8")
    return True


def _apply_rust_src_patches(rust_src_dir: pathlib.Path) -> pathlib.Path:
    """Apply the 5 verified `wasm64-unknown-openbsd` patches to a copied `rust-src` tree."""
    lib_dir = rust_src_dir / "library"

    # 1. stdarch/crates/core_arch/src/mod.rs
    core_arch_mod = lib_dir / "stdarch/crates/core_arch/src/mod.rs"
    ca_txt = core_arch_mod.read_text(encoding="utf-8")
    old_pub_wasm = '#[cfg(any(target_family = "wasm", doc))]\n    #[doc(cfg(target_family = "wasm"))]\n    #[unstable(feature = "simd_wasm64", issue = "90599")]\n    pub mod wasm {'
    new_pub_wasm = '#[cfg(any(target_family = "wasm", target_arch = "wasm32", target_arch = "wasm64", doc))]\n    #[doc(cfg(target_family = "wasm"))]\n    #[unstable(feature = "simd_wasm64", issue = "90599")]\n    pub mod wasm {'
    if new_pub_wasm not in ca_txt:
        if old_pub_wasm not in ca_txt:
            die(f"patch site 1a (`pub mod wasm`) not found in {core_arch_mod}")
        ca_txt = ca_txt.replace(old_pub_wasm, new_pub_wasm, 1)

    old_mod_wasm32 = '#[cfg(any(target_family = "wasm", doc))]\n#[doc(cfg(target_family = "wasm"))]\nmod wasm32;'
    new_mod_wasm32 = '#[cfg(any(target_family = "wasm", target_arch = "wasm32", target_arch = "wasm64", doc))]\n#[doc(cfg(target_family = "wasm"))]\nmod wasm32;'
    if new_mod_wasm32 not in ca_txt:
        if old_mod_wasm32 not in ca_txt:
            die(f"patch site 1b (`mod wasm32;`) not found in {core_arch_mod}")
        ca_txt = ca_txt.replace(old_mod_wasm32, new_mod_wasm32, 1)
    core_arch_mod.write_text(ca_txt, encoding="utf-8")

    # 2. unwind/src/types.rs & unwind/src/lib.rs
    uw_types = lib_dir / "unwind/src/types.rs"
    ut_txt = uw_types.read_text(encoding="utf-8")
    if 'any(target_family = "wasm", target_arch = "wasm32", target_arch = "wasm64") => 2,' not in ut_txt:
        if 'target_family = "wasm" => 2,' not in ut_txt:
            die(f"patch site 2a (`target_family = \"wasm\" => 2`) not found in {uw_types}")
        ut_txt = ut_txt.replace(
            'target_family = "wasm" => 2,',
            'any(target_family = "wasm", target_arch = "wasm32", target_arch = "wasm64") => 2,',
            1,
        )
    uw_types.write_text(ut_txt, encoding="utf-8")

    uw_lib = lib_dir / "unwind/src/lib.rs"
    ul_txt = uw_lib.read_text(encoding="utf-8")
    old_feat = '#![cfg_attr(\n    target_family = "wasm",\n    feature(link_llvm_intrinsics, simd_wasm64, asm_experimental_arch)\n)]'
    new_feat = '#![cfg_attr(\n    any(target_family = "wasm", target_arch = "wasm32", target_arch = "wasm64"),\n    feature(link_llvm_intrinsics, simd_wasm64, asm_experimental_arch)\n)]'
    if new_feat not in ul_txt:
        if old_feat not in ul_txt:
            die(f"patch site 2b (`#![cfg_attr(target_family = \"wasm\"...)]`) not found in {uw_lib}")
        ul_txt = ul_txt.replace(old_feat, new_feat, 1)

    # Ensure `wasm64` selects `mod wasm` BEFORE the `unix` arm in `unwind/src/lib.rs`
    wasm_arm_marker = 'any(target_family = "wasm", target_arch = "wasm32", target_arch = "wasm64") => {'
    if wasm_arm_marker not in ul_txt:
        old_unix_start = "    any(\n        unix,"
        new_wasm_before_unix = (
            '    any(target_family = "wasm", target_arch = "wasm32", target_arch = "wasm64") => {\n'
            "        mod types;\n"
            "        mod wasm;\n"
            "        pub use wasm::*;\n"
            "    }\n"
            "    any(\n        unix,"
        )
        if old_unix_start not in ul_txt:
            die(f"patch site 2c (`any(unix, ...)`) not found in {uw_lib}")
        # Remove trailing duplicate `target_family = "wasm" => { ... }` arm and insert before `unix`
        ul_txt = re.sub(
            r'\n\s*target_family = "wasm" => \{\s*mod types;\s*mod wasm;\s*pub use wasm::\*;\s*\}',
            "",
            ul_txt,
            count=1,
        )
        ul_txt = ul_txt.replace(old_unix_start, new_wasm_before_unix, 1)

    old_cxxabi = '#[cfg(target_os = "openbsd")]\n#[link(name = "c++abi")]'
    new_cxxabi = '#[cfg(all(target_os = "openbsd", not(target_arch = "wasm64")))]\n#[link(name = "c++abi")]'
    if new_cxxabi not in ul_txt:
        if old_cxxabi not in ul_txt:
            die(f"patch site 2d (`#[link(name = \"c++abi\")]`) not found in {uw_lib}")
        ul_txt = ul_txt.replace(old_cxxabi, new_cxxabi, 1)
    uw_lib.write_text(ul_txt, encoding="utf-8")

    # 3. std/src/sys/personality/mod.rs
    pers_mod = lib_dir / "std/src/sys/personality/mod.rs"
    pm_txt = pers_mod.read_text(encoding="utf-8")
    old_pers = 'any(target_env = "msvc", target_family = "wasm") => {'
    new_pers = 'any(target_env = "msvc", target_family = "wasm", target_arch = "wasm32", target_arch = "wasm64") => {'
    if new_pers not in pm_txt:
        if old_pers not in pm_txt:
            die(f"patch site 3 (`rust_eh_personality`) not found in {pers_mod}")
        pm_txt = pm_txt.replace(old_pers, new_pers, 1)
    pers_mod.write_text(pm_txt, encoding="utf-8")

    # 4. compiler-builtins/float/cmp.rs
    cmp_candidates = list(lib_dir.glob("compiler-builtins/**/src/float/cmp.rs")) + list(
        lib_dir.glob("vendor/compiler_builtins-*/src/float/cmp.rs")
    )
    if not cmp_candidates:
        die(f"patch site 4 (`compiler-builtins/.../float/cmp.rs`) not found under {lib_dir}")
    for cmp_rs in cmp_candidates:
        c_txt = cmp_rs.read_text(encoding="utf-8")
        old_cmp = 'any(target_arch = "aarch64", target_arch = "arm64ec", target_family = "wasm") => {'
        new_cmp = 'any(target_arch = "aarch64", target_arch = "arm64ec", target_family = "wasm", target_arch = "wasm32", target_arch = "wasm64") => {'
        if new_cmp not in c_txt:
            if old_cmp not in c_txt:
                die(f"patch site 4 (`CmpResult = i32`) not found in {cmp_rs}")
            c_txt = c_txt.replace(old_cmp, new_cmp, 1)
            cmp_rs.write_text(c_txt, encoding="utf-8")
        cb_cksum = cmp_rs.parents[2] / ".cargo-checksum.json"
        if cb_cksum.is_file():
            try:
                cb_pkg = json.loads(cb_cksum.read_text(encoding="utf-8")).get("package")
            except Exception:
                cb_pkg = None
            cb_cksum.write_text(json.dumps({"files": {}, "package": cb_pkg}) + "\n", encoding="utf-8")

    # 5. vendor/libc-*/src/unix/bsd/netbsdlike/openbsd/mod.rs
    libc_dirs = sorted(lib_dir.glob("vendor/libc-*"))
    if not libc_dirs:
        die(f"patch site 5 (`vendor/libc-*`) not found under {lib_dir}")
    for ld in libc_dirs:
        if not patch_openbsd_libc_tree(ld, strip_std_workspace_dep=False):
            die(f"failed patching OpenBSD wasm64 layout in {ld}")
    return libc_dirs[-1]


def ensure_patched_rust_sysroot_and_libc(cache_sdk: pathlib.Path, host_rust: Dict[str, Any]) -> Tuple[pathlib.Path, pathlib.Path]:
    """
    Prepare & cache:
      - `sysroot_dir`: `.cache/sdk/rust-sysroot-wasm64-<key>` (with `bin/rustc` & `bin/rustdoc`
        wrappers binding `--sysroot` to the patched `rust-src` tree)
      - `libc_overlay_dir`: `.cache/sdk/rust-libc-wasm64-<key>` (zero-dep patched `libc`
        crate for `[patch.crates-io]`)
    """
    sig_input = f"{PATCH_SCHEMA_VERSION}\n{host_rust['rustc_vv']}\n{pathlib.Path(__file__).read_text(encoding='utf-8')}"
    key = hashlib.sha256(sig_input.encode("utf-8")).hexdigest()[:16]
    sysroot_dir = cache_sdk / f"rust-sysroot-wasm64-{key}"
    libc_overlay_dir = cache_sdk / f"rust-libc-wasm64-{key}"
    stamp_file = sysroot_dir / ".obsd-wasm64-ready.stamp"

    if (
        stamp_file.is_file()
        and (sysroot_dir / "bin/rustc").is_file()
        and (libc_overlay_dir / "Cargo.toml").is_file()
    ):
        return sysroot_dir, libc_overlay_dir

    lock_path = cache_sdk / "rust-wasm64-prep.lock"
    with lock_path.open("w") as lock_fp:
        fcntl.flock(lock_fp.fileno(), fcntl.LOCK_EX)
        if (
            stamp_file.is_file()
            and (sysroot_dir / "bin/rustc").is_file()
            and (libc_overlay_dir / "Cargo.toml").is_file()
        ):
            return sysroot_dir, libc_overlay_dir

        orig_sysroot: pathlib.Path = host_rust["sysroot"]
        tmp_sysroot = cache_sdk / f".rust-sysroot-wasm64-{key}.{os.getpid()}.tmp"
        tmp_libc = cache_sdk / f".rust-libc-wasm64-{key}.{os.getpid()}.tmp"
        shutil.rmtree(tmp_sysroot, ignore_errors=True)
        shutil.rmtree(tmp_libc, ignore_errors=True)

        try:
            (tmp_sysroot / "bin").mkdir(parents=True, exist_ok=True)
            (tmp_sysroot / "lib/rustlib/src").mkdir(parents=True, exist_ok=True)

            for top_entry in orig_sysroot.iterdir():
                if top_entry.name in ("bin", "lib"):
                    continue
                os.symlink(top_entry, tmp_sysroot / top_entry.name)

            for lib_entry in (orig_sysroot / "lib").iterdir():
                if lib_entry.name == "rustlib":
                    continue
                os.symlink(lib_entry, tmp_sysroot / "lib" / lib_entry.name)

            for rl_entry in (orig_sysroot / "lib/rustlib").iterdir():
                if rl_entry.name == "src":
                    continue
                os.symlink(rl_entry, tmp_sysroot / "lib/rustlib" / rl_entry.name)

            dst_rust_src = tmp_sysroot / "lib/rustlib/src/rust"
            shutil.copytree(orig_sysroot / "lib/rustlib/src/rust", dst_rust_src, symlinks=True)
            patched_vendor_libc = _apply_rust_src_patches(dst_rust_src)

            # Populate stub `rustc-std-workspace-core-1.0.1` inside `library/vendor/` so Cargo's
            # offline `modcargo` resolver satisfies `libc`'s optional `rustc-std-workspace-core = "1.0.1"`
            # dependency in user graphs while `-Z build-std` overrides it with `library/rustc-std-workspace-core`.
            ws_stub = dst_rust_src / "library/vendor/rustc-std-workspace-core-1.0.1"
            (ws_stub / "src").mkdir(parents=True, exist_ok=True)
            (ws_stub / "Cargo.toml").write_text(
                '[package]\nname = "rustc-std-workspace-core"\nversion = "1.0.1"\nedition = "2021"\n',
                encoding="utf-8",
            )
            (ws_stub / "src/lib.rs").write_text("#![no_std]\n", encoding="utf-8")
            (ws_stub / ".cargo-checksum.json").write_text('{"files":{},"package":null}\n', encoding="utf-8")

            shutil.copytree(patched_vendor_libc, tmp_libc, symlinks=True)
            patch_openbsd_libc_tree(tmp_libc, strip_std_workspace_dep=False)

            # Write `rustc` and `rustdoc` wrappers that pin `--sysroot` to `sysroot_dir`
            for tool_name, real_bin in (("rustc", host_rust["real_rustc"]), ("rustdoc", host_rust["real_rustdoc"])):
                wrapper = tmp_sysroot / "bin" / tool_name
                wrapper.write_text(
                    "#!/bin/sh\n"
                    'SYSROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)\n'
                    'for arg in "$@"; do\n'
                    '  case "$arg" in\n'
                    '    --sysroot|--sysroot=*) exec "' + str(real_bin) + '" "$@" ;;\n'
                    "  esac\n"
                    "done\n"
                    'exec "' + str(real_bin) + '" --sysroot "$SYSROOT_DIR" "$@"\n',
                    encoding="utf-8",
                )
                wrapper.chmod(0o755)

            shutil.rmtree(libc_overlay_dir, ignore_errors=True)
            tmp_libc.replace(libc_overlay_dir)
            shutil.rmtree(sysroot_dir, ignore_errors=True)
            tmp_sysroot.replace(sysroot_dir)
            stamp_file.write_text(key + "\n", encoding="utf-8")
        finally:
            shutil.rmtree(tmp_sysroot, ignore_errors=True)
            shutil.rmtree(tmp_libc, ignore_errors=True)

    return sysroot_dir, libc_overlay_dir


def ensure_unwind_stub_obj(cache_sdk: pathlib.Path, openbsd_version: str, obsd_root: pathlib.Path) -> pathlib.Path:
    stub_c = SDK_RUST_DIR / "unwind_stub.c"
    obsd_cc = SDK_ROOT / "bin/obsd-cc"
    sig = hashlib.sha256(
        f"{openbsd_version}:{obsd_root}:{stub_c.read_text(encoding='utf-8')}".encode("utf-8")
    ).hexdigest()[:16]
    out_dir = cache_sdk / f"rust-unwind-{openbsd_version}-{sig}"
    out_obj = out_dir / "unwind_stub.o"
    if out_obj.is_file():
        return out_obj

    out_dir.mkdir(parents=True, exist_ok=True)
    lock_path = cache_sdk / f"rust-unwind-{openbsd_version}.lock"
    with lock_path.open("w") as lock_fp:
        fcntl.flock(lock_fp.fileno(), fcntl.LOCK_EX)
        if out_obj.is_file():
            return out_obj
        env = dict(os.environ)
        env["OPENBSD_VERSION"] = openbsd_version
        env["LIBOBSDCOMPAT_ROOT"] = str(obsd_root)
        tmp_obj = out_dir / f".unwind_stub.{os.getpid()}.o"
        subprocess.run(
            [str(obsd_cc), "-c", "-O2", str(stub_c), "-o", str(tmp_obj)],
            env=env,
            check=True,
        )
        tmp_obj.replace(out_obj)
    return out_obj


def expand_rsp_args(argv: Sequence[str]) -> List[str]:
    out: List[str] = []
    for a in argv:
        if a.startswith("@") and len(a) > 1:
            rsp_path = pathlib.Path(a[1:])
            if rsp_path.is_file():
                txt = rsp_path.read_text(encoding="utf-8", errors="replace")
                out.extend(expand_rsp_args(shlex.split(txt, posix=True)))
                continue
        out.append(a)
    return out


def _read_uleb(buf: bytes, pos: int) -> Tuple[int, int]:
    res = 0
    shift = 0
    while True:
        b = buf[pos]
        pos += 1
        res |= (b & 0x7F) << shift
        if (b & 0x80) == 0:
            return res, pos
        shift += 7


def _encode_uleb(val: int) -> bytes:
    out = bytearray()
    while True:
        b = val & 0x7F
        val >>= 7
        if val != 0:
            b |= 0x80
        out.append(b)
        if val == 0:
            return bytes(out)


def _encode_wasm_str(s: str) -> bytes:
    raw = s.encode("utf-8")
    return _encode_uleb(len(raw)) + raw


def rewrite_wasm_relro_segments(obj_path: pathlib.Path) -> int:
    """
    Promote ELF/WASM RELRO segment names (`.data.rel.ro` -> `.rodata.rel.ro` and
    `.data.rel.ro.*` -> `.rodata.rel.ro.*`) inside WASM `linking` v2 `WASM_SEGMENT_INFO`
    so `wasm_object_tool.py window-guest` (`nm.startswith(".data.")`) leaves immutable
    Rust trait vtables and `const` pointer tables in shared read-only `.rodata` instead
    of sweeping them into per-process mutable `obsd_guest_data`.
    """
    if not obj_path.is_file():
        return 0
    data = obj_path.read_bytes()
    if len(data) < 8 or data[:8] != b"\x00asm\x01\x00\x00\x00":
        return 0

    out = bytearray(data[:8])
    pos = 8
    rewritten = 0

    while pos < len(data):
        sec_id = data[pos]
        sec_len, body_pos = _read_uleb(data, pos + 1)
        sec_end = body_pos + sec_len
        if sec_id == 0:
            nlen, npos = _read_uleb(data, body_pos)
            sec_name = data[npos : npos + nlen].decode("utf-8", "replace")
            if sec_name == "linking":
                ver, p = _read_uleb(data, npos + nlen)
                if ver == 2:
                    new_subsecs: List[Tuple[int, bytes]] = []
                    while p < sec_end:
                        stype = data[p]
                        slen, sp = _read_uleb(data, p + 1)
                        spayload = data[sp : sp + slen]
                        p = sp + slen
                        if stype == 5:  # WASM_SEGMENT_INFO
                            cnt, qp = _read_uleb(spayload, 0)
                            seg_buf = bytearray(_encode_uleb(cnt))
                            for _ in range(cnt):
                                sl2, qp = _read_uleb(spayload, qp)
                                nm = spayload[qp : qp + sl2].decode("utf-8")
                                qp += sl2
                                align, qp = _read_uleb(spayload, qp)
                                flags, qp = _read_uleb(spayload, qp)
                                if nm == ".data.rel.ro":
                                    nm = ".rodata.rel.ro"
                                    rewritten += 1
                                elif nm.startswith(".data.rel.ro."):
                                    nm = ".rodata.rel.ro." + nm[len(".data.rel.ro.") :]
                                    rewritten += 1
                                seg_buf += _encode_wasm_str(nm)
                                seg_buf += _encode_uleb(align)
                                seg_buf += _encode_uleb(flags)
                            spayload = bytes(seg_buf)
                        new_subsecs.append((stype, spayload))

                    if rewritten > 0:
                        linking_body = bytearray(_encode_wasm_str("linking") + _encode_uleb(ver))
                        for stype, spayload in new_subsecs:
                            linking_body.append(stype)
                            linking_body += _encode_uleb(len(spayload))
                            linking_body += spayload
                        out.append(0)
                        out += _encode_uleb(len(linking_body))
                        out += linking_body
                        pos = sec_end
                        continue
        out += data[pos:sec_end]
        pos = sec_end

    if rewritten > 0:
        st_mode = obj_path.stat().st_mode & 0o7777
        tmp_p = obj_path.with_suffix(obj_path.suffix + f".{os.getpid()}.relro.tmp")
        tmp_p.write_bytes(bytes(out))
        tmp_p.chmod(st_mode)
        tmp_p.replace(obj_path)
    return rewritten


def run_rust_ld(raw_argv: Sequence[str]) -> int:
    """
    `obsd-rust-ld`: Translate `rustc`'s `wasm-lld` invocation into `sdk/bin/obsd-cc -nostdlib`
    so Rust binaries emit verified WASM64 OpenBSD relocatable objects (with static constructors
    wrapped per-exec, undefined symbols checked against `libobsdc-wasm-<ver>.a`, and WASM
    `linking` symbol tables preserved for `wasm_object_tool.py localize-applet`).
    """
    argv = expand_rsp_args(raw_argv)
    openbsd_version = os.environ.get("OPENBSD_VERSION", "8.0").strip() or "8.0"
    obsd_root = resolve_libobsdcompat_root()
    cache_sdk = resolve_cache_sdk_dir()
    unwind_obj = ensure_unwind_stub_obj(cache_sdk, openbsd_version, obsd_root)

    obsd_cc = SDK_ROOT / "bin/obsd-cc"
    cc_args: List[str] = ["-nostdlib"]
    output_path: Optional[str] = None
    strip_debug = False

    i = 0
    n = len(argv)
    while i < n:
        a = argv[i]
        if a in ("-flavor", "-m", "-z", "-mllvm", "--export", "--export-if-defined", "--entry", "-e", "-soname", "-rpath") and i + 1 < n:
            i += 2
            continue
        if a.startswith(
            (
                "--export=",
                "--export-if-defined=",
                "--entry=",
                "--max-memory=",
                "--initial-memory=",
                "--global-base=",
                "--table-base=",
                "-plugin-opt=",
                "--plugin-opt=",
                "--lto-",
                "-O",
                "-z",
            )
        ):
            i += 1
            continue
        if a in (
            "--import-memory",
            "--shared-memory",
            "--export-table",
            "--import-table",
            "--growable-table",
            "--experimental-pic",
            "--no-entry",
            "--relocatable",
            "-r",
            "--gc-sections",
            "--no-gc-sections",
            "--export-dynamic",
            "--export-all",
            "--eh-frame-hdr",
            "--as-needed",
            "--no-as-needed",
            "-Bstatic",
            "-Bdynamic",
            "--Bstatic",
            "--Bdynamic",
            "--strip-all",
            "-s",
            "--fatal-warnings",
            "--no-demangle",
        ):
            i += 1
            continue
        if a in ("--strip-debug", "-S"):
            strip_debug = True
            i += 1
            continue
        if a in ("--whole-archive", "--no-whole-archive"):
            cc_args.append(f"-Wl,{a}")
            i += 1
            continue
        if a == "-o" and i + 1 < n:
            output_path = argv[i + 1]
            i += 2
            continue
        if a.startswith("-o") and len(a) > 2:
            output_path = a[2:]
            i += 1
            continue
        if a == "-L" and i + 1 < n:
            cc_args.extend(["-L", argv[i + 1]])
            i += 2
            continue
        if a.startswith("-L") and len(a) > 2:
            cc_args.append(a)
            i += 1
            continue
        if a == "-l" and i + 1 < n:
            lib = argv[i + 1]
            if lib not in DROPPED_RUST_LIBS:
                cc_args.extend(["-l", lib])
            i += 2
            continue
        if a.startswith("-l") and len(a) > 2:
            lib = a[2:]
            if lib not in DROPPED_RUST_LIBS:
                cc_args.append(a)
            i += 1
            continue
        if a.startswith("-"):
            # Ignore unrecognized wasm-lld-only flags while forwarding -Wl,*
            if a.startswith("-Wl,"):
                cc_args.append(a)
            i += 1
            continue
        cc_args.append(a)
        i += 1

    if strip_debug:
        cc_args.append("-Wl,--strip-debug")
    cc_args.append(str(unwind_obj))
    if output_path is not None:
        cc_args.extend(["-o", output_path])

    rc = subprocess.run([str(obsd_cc), *cc_args]).returncode
    if rc == 0 and output_path is not None:
        rewrite_wasm_relro_segments(pathlib.Path(output_path))
    return rc


def _sha256_hex(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fp:
        while True:
            chunk = fp.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _extract_single_crate_archive(task: Tuple[pathlib.Path, pathlib.Path]) -> None:
    archive_path, dest_dir = task
    if (dest_dir / ".cargo-checksum.json").is_file() and (dest_dir / "Cargo.toml").is_file():
        return
    pkg_sha = _sha256_hex(archive_path)
    tmp_parent = dest_dir.parent / f".extract-{dest_dir.name}.{os.getpid()}"
    shutil.rmtree(tmp_parent, ignore_errors=True)
    tmp_parent.mkdir(parents=True, exist_ok=True)
    try:
        with tarfile.open(archive_path, "r:*") as tf:
            tf.extractall(path=tmp_parent, filter="data")
        subdirs = [p for p in tmp_parent.iterdir() if p.is_dir()]
        extracted = subdirs[0] if len(subdirs) == 1 else tmp_parent
        shutil.rmtree(dest_dir, ignore_errors=True)
        shutil.move(str(extracted), str(dest_dir))
        (dest_dir / ".cargo-checksum.json").write_text(
            json.dumps({"files": {}, "package": pkg_sha}) + "\n",
            encoding="utf-8",
        )
    finally:
        shutil.rmtree(tmp_parent, ignore_errors=True)


def parse_distinfo_cargo_crates(port_dir: Optional[pathlib.Path]) -> List[Tuple[str, pathlib.Path]]:
    """Return `[(crate_ver_stem, archive_path), ...]` for `cargo/<stem>.tar.gz` entries in `distinfo`."""
    if port_dir is None:
        return []
    distinfo = port_dir / "distinfo"
    if not distinfo.is_file():
        return []
    distfiles_dir = resolve_distfiles_dir()
    skip_raw = os.environ.get("OBSD_SKIP_DISTFILES_JSON", "").strip()
    skip_set = set(json.loads(skip_raw)) if skip_raw else set()

    seen: Set[str] = set()
    out: List[Tuple[str, pathlib.Path]] = []
    for raw in distinfo.read_text(encoding="utf-8", errors="replace").splitlines():
        m = re.match(r"^SHA256\s*\((cargo/([^)]+?)\.tar\.gz)\)\s*=", raw.strip())
        if not m:
            continue
        rel_fn, stem = m.group(1), m.group(2)
        if rel_fn in skip_set or f"{stem}.tar.gz" in skip_set or stem in seen:
            continue
        seen.add(stem)
        ar = distfiles_dir / rel_fn
        if ar.is_file():
            out.append((stem, ar))
    return out


def parse_git_sources_from_lockfile(lock_path: pathlib.Path) -> List[Dict[str, str]]:
    if not lock_path.is_file():
        return []
    try:
        data = tomllib.loads(lock_path.read_text(encoding="utf-8"))
    except Exception:
        return []
    seen: Set[str] = set()
    sources: List[Dict[str, str]] = []
    for pkg in data.get("package", []):
        src = str(pkg.get("source", ""))
        if not src.startswith("git+"):
            continue
        no_frag = src.split("#", 1)[0]
        if no_frag in seen:
            continue
        seen.add(no_frag)
        raw_url = no_frag[len("git+") :]
        parsed = urllib.parse.urlsplit(raw_url)
        base_git_url = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))
        q = urllib.parse.parse_qs(parsed.query)
        entry: Dict[str, str] = {"key": no_frag, "git": base_git_url}
        for k in ("rev", "tag", "branch"):
            if k in q and q[k]:
                entry[k] = q[k][0]
        sources.append(entry)
    return sources


def prepare_cargo_workspace(
    wrksrc: pathlib.Path,
    wrkbuild: pathlib.Path,
    port_dir: Optional[pathlib.Path],
    sysroot_dir: pathlib.Path,
    libc_overlay_dir: pathlib.Path,
    target_cfg: Dict[str, Any],
    manifest_path: pathlib.Path,
    jobs: int,
) -> Tuple[pathlib.Path, pathlib.Path]:
    """
    Prepare `$WRKBUILD/modcargo-crates` and `$WRKBUILD/.cargo-home/config.toml` for
    100% `--offline` OpenBSD `MODULES = devel/cargo` builds.
    """
    vendor_dir = wrkbuild / "modcargo-crates"
    vendor_dir.mkdir(parents=True, exist_ok=True)

    # If `separate_build` placed `DIST_TUPLE` or pre-extracted crates in `$WRKSRC/modcargo-crates`,
    # surface them inside `$WRKBUILD/modcargo-crates` cleanly.
    src_vendor = wrksrc / "modcargo-crates"
    if src_vendor.resolve() != vendor_dir.resolve() and src_vendor.is_dir():
        for item in sorted(src_vendor.iterdir()):
            dst = vendor_dir / item.name
            if not dst.exists():
                shutil.move(str(item), str(dst))

    # Extract any `cargo/<crate>-<ver>.tar.gz` from `distinfo` not yet extracted
    crate_archives = parse_distinfo_cargo_crates(port_dir)
    missing_tasks = [
        (ar_p, vendor_dir / stem)
        for stem, ar_p in crate_archives
        if not (vendor_dir / stem / "Cargo.toml").is_file()
    ]
    if missing_tasks:
        workers = min(max(jobs, 4), 24, len(missing_tasks))
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            list(pool.map(_extract_single_crate_archive, missing_tasks))

    # Ensure every crate directory in `modcargo-crates/` (including `DIST_TUPLE` git crates and
    # crates touched by `patches/patch-*`) has a clean `.cargo-checksum.json` (`"files": {}` +
    # preserved `"package"` SHA256 for crates.io crates, or `null` for git crates).
    archive_sha_by_stem = {stem: _sha256_hex(ar_p) for stem, ar_p in crate_archives}
    has_vendored_crates = False
    for sub in sorted(vendor_dir.iterdir()):
        if not sub.is_dir() or sub.name.startswith("."):
            continue
        if (sub / "Cargo.toml").is_file():
            has_vendored_crates = True
            if sub.name.startswith("libc-") and target_cfg["target_name"] == "wasm64-unknown-openbsd":
                patch_openbsd_libc_tree(sub, strip_std_workspace_dep=False)
            cksum = sub / ".cargo-checksum.json"
            pkg_sha = archive_sha_by_stem.get(sub.name)
            if pkg_sha is None and cksum.is_file():
                try:
                    pkg_sha = json.loads(cksum.read_text(encoding="utf-8")).get("package")
                except Exception:
                    pkg_sha = None
            cksum.write_text(json.dumps({"files": {}, "package": pkg_sha}) + "\n", encoding="utf-8")

    # Resolve port-supplied `[patch.crates-io]` entries (`OBSD_CARGO_PATCH_CRATES_JSON`)
    patch_crates: Dict[str, pathlib.Path] = {}
    if target_cfg["target_name"] == "wasm64-unknown-openbsd":
        patch_crates["libc"] = libc_overlay_dir

    raw_patches = os.environ.get("OBSD_CARGO_PATCH_CRATES_JSON", "").strip()
    if raw_patches:
        user_map = json.loads(raw_patches)
        if isinstance(user_map, dict):
            for crate_nm, rel_or_abs in user_map.items():
                p = pathlib.Path(str(rel_or_abs))
                if not p.is_absolute():
                    for base in (wrksrc, wrkbuild, *( [port_dir] if port_dir else [] )):
                        cand = (base / p).resolve()
                        if cand.is_dir():
                            p = cand
                            break
                if not p.is_dir():
                    die(f"cargo_patch_crates[{crate_nm!r}] directory does not exist: {rel_or_abs}")
                patch_crates[str(crate_nm)] = p.resolve()

    cargo_home = wrkbuild / ".cargo-home"
    cargo_home.mkdir(parents=True, exist_ok=True)
    rustc_wrapper = sysroot_dir / "bin/rustc"
    rustdoc_wrapper = sysroot_dir / "bin/rustdoc"

    cfg_lines: List[str] = [
        "# AUTO-GENERATED by sdk/bin/obsd-cargo",
        "[build]",
        f"rustc = {json.dumps(str(rustc_wrapper))}",
        f"rustdoc = {json.dumps(str(rustdoc_wrapper))}",
        "",
        "[net]",
        "offline = true",
        "",
        "[term]",
        "color = 'never'",
        "progress.when = 'never'",
        "",
    ]

    if has_vendored_crates and target_cfg["needs_build_std"]:
        # `-Z build-std=std,panic_abort` resolves `std`'s own crates (`cfg-if`, `gimli`,
        # `miniz_oxide`, `object`, `hashbrown`, `rustc-demangle`, `compiler_builtins`, etc.)
        # through `[source.crates-io] -> modcargo` when `replace-with = 'modcargo'` is active.
        # Symlink any absent crates from `<sysroot>/lib/rustlib/src/rust/library/vendor/*` into
        # `modcargo-crates/` so both user crates and `std` resolve 100% offline!
        std_vendor_dir = sysroot_dir / "lib/rustlib/src/rust/library/vendor"
        if std_vendor_dir.is_dir():
            for std_crate in sorted(std_vendor_dir.iterdir()):
                if not std_crate.is_dir() or not (std_crate / "Cargo.toml").is_file():
                    continue
                dst_link = vendor_dir / std_crate.name
                if not dst_link.exists() and not dst_link.is_symlink():
                    os.symlink(std_crate, dst_link)

    if has_vendored_crates:
        cfg_lines.extend(
            [
                "[source.modcargo]",
                f"directory = {json.dumps(str(vendor_dir))}",
                "",
                "[source.crates-io]",
                "replace-with = 'modcargo'",
                "",
            ]
        )
        lock_path = manifest_path.with_name("Cargo.lock")
        if not lock_path.is_file():
            lock_path = wrksrc / "Cargo.lock"
        for gs in parse_git_sources_from_lockfile(lock_path):
            cfg_lines.append(f"[source.{json.dumps(gs['key'])}]")
            cfg_lines.append(f"git = {json.dumps(gs['git'])}")
            for qk in ("rev", "tag", "branch"):
                if qk in gs:
                    cfg_lines.append(f"{qk} = {json.dumps(gs[qk])}")
            cfg_lines.append("replace-with = 'modcargo'")
            cfg_lines.append("")

    if patch_crates:
        cfg_lines.append("[patch.crates-io]")
        for crate_nm, crate_path in sorted(patch_crates.items()):
            cfg_lines.append(f"{crate_nm} = {{ path = {json.dumps(str(crate_path))} }}")
        cfg_lines.append("")

    (cargo_home / "config.toml").write_text("\n".join(cfg_lines), encoding="utf-8")
    return cargo_home, vendor_dir


def build_isolated_cargo_env(
    host_rust: Dict[str, Any],
    sysroot_dir: pathlib.Path,
    cargo_home: pathlib.Path,
    wrkbuild: pathlib.Path,
    target_cfg: Dict[str, Any],
    openbsd_version: str,
    obsd_root: pathlib.Path,
    stage_dir: pathlib.Path,
) -> Dict[str, str]:
    env = dict(os.environ)
    guest_cflags = env.get("CFLAGS", "-O2")
    guest_cxxflags = env.get("CXXFLAGS", "-O2")
    guest_cppflags = env.get("CPPFLAGS", f"-I{stage_dir}/usr/local/include")

    # Remove unscoped cross-compiler variables from ambient environment so host
    # `[build-dependencies]` (e.g. `zstd-sys` in `goose`) and `build.rs` scripts
    # compile natively for the Linux host instead of invoking WASM64 `obsd-cc`.
    for unscoped in (
        "CC",
        "CXX",
        "CPP",
        "AR",
        "RANLIB",
        "LD",
        "NM",
        "STRIP",
        "PKG_CONFIG",
        "CFLAGS",
        "CXXFLAGS",
        "CPPFLAGS",
        "LDFLAGS",
        "LIBS",
        "CONFIG_SITE",
        "CMAKE_TOOLCHAIN_FILE",
    ):
        env.pop(unscoped, None)

    host_cc = shutil.which("/usr/bin/clang") or shutil.which("clang") or shutil.which("gcc") or "cc"
    host_cxx = shutil.which("/usr/bin/clang++") or shutil.which("clang++") or shutil.which("g++") or "c++"
    host_ar = shutil.which("/usr/bin/ar") or shutil.which("llvm-ar") or shutil.which("ar") or "ar"
    host_ranlib = shutil.which("/usr/bin/ranlib") or shutil.which("llvm-ranlib") or shutil.which("ranlib") or "ranlib"
    host_pc = shutil.which("/usr/bin/pkg-config") or shutil.which("pkg-config") or "pkg-config"

    host_triple = host_rust["host_triple"]
    host_u = host_triple.replace("-", "_")

    env["HOST_CC"] = host_cc
    env["HOST_CXX"] = host_cxx
    env["HOST_AR"] = host_ar
    env["HOST_CFLAGS"] = "-O2"
    env["HOST_CXXFLAGS"] = "-O2"
    env[f"CC_{host_u}"] = host_cc
    env[f"CXX_{host_u}"] = host_cxx
    env[f"AR_{host_u}"] = host_ar
    env[f"RANLIB_{host_u}"] = host_ranlib
    env[f"PKG_CONFIG_{host_u}"] = host_pc
    env[f"CFLAGS_{host_u}"] = "-O2"
    env[f"CXXFLAGS_{host_u}"] = "-O2"

    sdk_bin = SDK_ROOT / "bin"
    env["OBSD_PORTS_ROOT"] = str(REPO_ROOT)
    env["LIBOBSDCOMPAT_ROOT"] = str(obsd_root)
    env["OPENBSD_VERSION"] = openbsd_version
    env["COMPAT_BACKEND"] = target_cfg["backend"]
    env["COMPAT_PAL"] = target_cfg["pal"]
    env["OBSD_STAGE_DIR"] = str(stage_dir)

    t_sfx = target_cfg["cargo_env_suffix"]
    t_up = target_cfg["cargo_upper_suffix"]

    if target_cfg["target_name"] == "wasm64-unknown-openbsd":
        env[f"CC_{t_sfx}"] = str(sdk_bin / "obsd-cc")
        env[f"CXX_{t_sfx}"] = str(sdk_bin / "obsd-c++")
        env[f"AR_{t_sfx}"] = str(sdk_bin / "obsd-ar")
        env[f"RANLIB_{t_sfx}"] = str(sdk_bin / "obsd-ranlib")
        env[f"PKG_CONFIG_{t_sfx}"] = str(sdk_bin / "obsd-pkg-config")
        env[f"PKG_CONFIG_ALLOW_CROSS_{t_sfx}"] = "1"
        env[f"CFLAGS_{t_sfx}"] = f"{guest_cflags} {guest_cppflags}".strip()
        env[f"CXXFLAGS_{t_sfx}"] = f"{guest_cxxflags} {guest_cppflags}".strip()
        env[f"CARGO_TARGET_{t_up}_LINKER"] = str(sdk_bin / "obsd-rust-ld")

    env.setdefault("AWS_LC_SYS_CMAKE_BUILDER", "0")
    env.setdefault("ONIGURUMA_NO_PKG_CONFIG", "1")
    env.setdefault("LIBSQLITE3_SYS_BUNDLED", "1")

    env["RUSTUP_HOME"] = str(host_rust["rustup_home"])
    env["CARGO_HOME"] = str(cargo_home)
    env.setdefault("CARGO_TARGET_DIR", str(wrkbuild / "target"))
    env["RUSTC"] = str(sysroot_dir / "bin/rustc")
    env["RUSTDOC"] = str(sysroot_dir / "bin/rustdoc")

    extra_rf = env.get("MODCARGO_RUSTFLAGS", "").strip()
    if extra_rf:
        existing_rf = env.get(f"CARGO_TARGET_{t_up}_RUSTFLAGS", "").strip()
        env[f"CARGO_TARGET_{t_up}_RUSTFLAGS"] = f"{existing_rf} {extra_rf}".strip()

    path_parts = [
        str(sdk_bin),
        str(sysroot_dir / "bin"),
        str(host_rust["cargo_home"] / "bin"),
        env.get("PATH", "/usr/bin:/bin"),
    ]
    env["PATH"] = ":".join(path_parts)
    return env


def run_obsd_cargo(argv: Sequence[str]) -> int:
    openbsd_version = os.environ.get("OPENBSD_VERSION", "8.0").strip() or "8.0"
    backend = os.environ.get("COMPAT_BACKEND", "emulate").strip() or "emulate"
    pal = os.environ.get("COMPAT_PAL", "emscripten").strip() or "emscripten"
    sdk = os.environ.get("COMPAT_SDK", "").strip()

    if argv and argv[0] == "target-info":
        # Lightweight query mode (no rustup bootstrap required)
        import argparse

        ap = argparse.ArgumentParser(prog="obsd-cargo target-info")
        ap.add_argument("--openbsd-version", default=openbsd_version)
        ap.add_argument("--backend", default=backend)
        ap.add_argument("--pal", default=pal)
        ap.add_argument("--sdk", default=sdk)
        ns = ap.parse_args(list(argv[1:]))
        info = resolve_rust_matrix_target(ns.openbsd_version, ns.backend, ns.pal, ns.sdk)
        print(json.dumps(info, indent=2, sort_keys=True))
        return 0

    target_cfg = resolve_rust_matrix_target(openbsd_version, backend, pal, sdk)
    obsd_root = resolve_libobsdcompat_root()
    cache_sdk = resolve_cache_sdk_dir()

    host_rust = ensure_host_rust(cache_sdk)
    sysroot_dir, libc_overlay_dir = ensure_patched_rust_sysroot_and_libc(cache_sdk, host_rust)
    if target_cfg["target_name"] == "wasm64-unknown-openbsd":
        ensure_unwind_stub_obj(cache_sdk, openbsd_version, obsd_root)

    cwd = pathlib.Path.cwd().resolve()
    wrksrc = pathlib.Path(os.environ.get("WRKSRC", str(cwd))).resolve()
    wrkbuild = pathlib.Path(os.environ.get("WRKBUILD", str(wrksrc))).resolve()
    port_dir_raw = os.environ.get("PORT_DIR", "").strip()
    vport_dir_raw = os.environ.get("VENDOR_PORT_DIR", "").strip()
    meta_port_dir: Optional[pathlib.Path] = None
    if port_dir_raw and (pathlib.Path(port_dir_raw) / "distinfo").is_file():
        meta_port_dir = pathlib.Path(port_dir_raw).resolve()
    elif vport_dir_raw and (pathlib.Path(vport_dir_raw) / "distinfo").is_file():
        meta_port_dir = pathlib.Path(vport_dir_raw).resolve()
    elif port_dir_raw and pathlib.Path(port_dir_raw).is_dir():
        meta_port_dir = pathlib.Path(port_dir_raw).resolve()

    stage_env = os.environ.get("OBSD_STAGE_DIR", os.environ.get("STAGE_DIR", "")).strip()
    stage_dir = (
        pathlib.Path(stage_env).resolve()
        if stage_env
        else (REPO_ROOT / "build/openbsd" / openbsd_version / backend / pal / "stage").resolve()
    )

    manifest_env = os.environ.get("OBSD_CARGO_MANIFEST_PATH", "").strip()
    manifest_path = pathlib.Path(manifest_env).resolve() if manifest_env else (wrksrc / "Cargo.toml")
    jobs = int(os.environ.get("JOBS", str(os.cpu_count() or 8)))

    cargo_home, _vendor_dir = prepare_cargo_workspace(
        wrksrc=wrksrc,
        wrkbuild=wrkbuild,
        port_dir=meta_port_dir,
        sysroot_dir=sysroot_dir,
        libc_overlay_dir=libc_overlay_dir,
        target_cfg=target_cfg,
        manifest_path=manifest_path,
        jobs=jobs,
    )

    if argv and argv[0] == "prepare":
        print(f"  [obsd-cargo] prepared {cargo_home / 'config.toml'} ({target_cfg['target_name']})")
        return 0

    env = build_isolated_cargo_env(
        host_rust=host_rust,
        sysroot_dir=sysroot_dir,
        cargo_home=cargo_home,
        wrkbuild=wrkbuild,
        target_cfg=target_cfg,
        openbsd_version=openbsd_version,
        obsd_root=obsd_root,
        stage_dir=stage_dir,
    )

    # Determine primary cargo subcommand (first non-option token)
    subcmd = ""
    for tok in argv:
        if not tok.startswith("-"):
            subcmd = tok
            break

    cmd: List[str] = [str(host_rust["real_cargo"])]
    user_args = list(argv)

    if subcmd in CARGO_BUILD_SUBCOMMANDS:
        has_target = any(a == "--target" or a.startswith("--target=") for a in user_args)
        has_offline = "--offline" in user_args
        if target_cfg["needs_build_std"]:
            cmd.extend(["-Z", "json-target-spec", "-Z", "build-std=std,panic_abort"])
        # Place subcommand first, then our target/profile overrides + user flags
        sub_idx = user_args.index(subcmd)
        cmd.extend(user_args[: sub_idx + 1])
        if not has_offline:
            cmd.append("--offline")
        if not has_target:
            cmd.extend(["--target", target_cfg["target_arg"]])
        cmd.extend(
            [
                "--config",
                'profile.release.strip="debuginfo"',
                "--config",
                "profile.release.lto=false",
                "--config",
                'profile.release.panic="abort"',
            ]
        )
        cmd.extend(user_args[sub_idx + 1 :])
    else:
        cmd.extend(user_args)

    return subprocess.run(cmd, env=env).returncode


def main() -> int:
    if len(sys.argv) < 2:
        die("usage: obsd_rust.py <rust-ld|cargo|target-info> [args...]")
    mode = sys.argv[1]
    rest = sys.argv[2:]
    if mode == "rust-ld":
        return run_rust_ld(rest)
    if mode == "cargo":
        return run_obsd_cargo(rest)
    if mode == "target-info":
        return run_obsd_cargo(["target-info", *rest])
    die(f"unknown obsd_rust mode: {mode}")


if __name__ == "__main__":
    raise SystemExit(main())
