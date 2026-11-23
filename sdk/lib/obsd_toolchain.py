#!/usr/bin/env python3
"""
obsd_toolchain.py -- Guest cross-compilation toolchain driver for `obsd-ports`.

Implements:
  - `obsd-cc` / `obsd-c++`: Compiles C/C++ sources against the declared
    `libobsdcompat` OpenBSD <version> sysroot (`include-root-<ver>`) in LP64
    WASM64 mode (`-m64 -pthread -O2 -fno-common -sSUPPORT_LONGJMP=0
    -fsanitize-coverage=trace-pc,no-prune -D__OpenBSD__=1`), remaps guest
    `/usr/local/{include,lib}` to `$(OBSD_STAGE_DIR)/usr/local/{include,lib}`
    so host Linux headers/libraries never leak, links relocatable WASM64 objects
    via `wasm-ld -m wasm64 -r`, and enforces symbol closure against
    `libobsdc-wasm-<ver>.a` so Autoconf/CMake link checks (`AC_CHECK_FUNC`,
    `AC_CHECK_LIB`, `AC_SEARCH_LIBS`) behave identically to a native OpenBSD
    toolchain.
  - `obsd-ar`, `obsd-ranlib`, `obsd-nm`, `obsd-ld`: Thin wrappers around the
    hermetic Emscripten/LLVM WASM64 binutils.
  - `obsd-strip` / `obsd-install`: Preserves WASM `linking` custom sections
    required for post-build applet localization (`wasm_object_tool.py`).
  - `obsd-pkg-config`: Hermetic `pkg-config` wrapper isolated strictly to staged
    port `.pc` files + synthesized base OpenBSD (`openssl`, `libssl`,
    `libcrypto`, `libtls`, `zlib`, `curses`, `ncursesw`, `expat`, `libedit`)
    `.pc` descriptors.
"""
from __future__ import annotations

import concurrent.futures
import fcntl
import hashlib
import json
import os
import pathlib
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Dict, List, Optional, Sequence, Set, Tuple

SDK_ROOT = pathlib.Path(__file__).resolve().parents[1]
REPO_ROOT = SDK_ROOT.parent

# Base OpenBSD libraries provided directly inside `libobsdc-wasm-<ver>.a`.
# Deliberately excludes absent libraries (iconv, intl, panel, form, menu, etc.)
# so `./configure` accurately detects what is and is not in base OpenBSD.
BASE_OPENBSD_LIBS: Set[str] = {
    "c",
    "m",
    "pthread",
    "util",
    "kvm",
    "z",
    "curses",
    "ncurses",
    "ncursesw",
    "tinfo",
    "termcap",
    "termlib",
    "edit",
    "readline",
    "expat",
    "cbor",
    "crypto",
    "ssl",
    "tls",
    "event",
}

WASM_BOUNDARY_IMPORTS: Set[str] = {
    "__obsd_wasm_gate",
    "__obsd_wasm_setjmp",
    "__obsd_wasm_longjmp",
    "__obsd_guest_tcb",
    "__obsd_guest_tcb_set",
    "__sanitizer_cov_trace_pc",
    "__stack_pointer",
    "__indirect_function_table",
    "__linear_memory",
    "__tls_base",
    "__tls_size",
    "__tls_align",
    "emscripten_return_address",
}

COMPILER_RT_BUILTINS: Set[str] = {
    "__addtf3",
    "__subtf3",
    "__multf3",
    "__divtf3",
    "__eqtf2",
    "__netf2",
    "__getf2",
    "__gttf2",
    "__letf2",
    "__lttf2",
    "__unordtf2",
    "__extenddftf2",
    "__extendsftf2",
    "__trunctfdf2",
    "__trunctfsf2",
    "__fixtfdi",
    "__fixtfsi",
    "__fixtfti",
    "__fixunstfdi",
    "__fixunstfsi",
    "__fixunstfti",
    "__floatditf",
    "__floatsitf",
    "__floattitf",
    "__floatunditf",
    "__floatunsitf",
    "__floatuntitf",
    "__multi3",
    "__divti3",
    "__udivti3",
    "__modti3",
    "__umodti3",
    "__ashlti3",
    "__lshrti3",
    "__ashrti3",
    "__muldc3",
    "__mulsc3",
    "__multc3",
    "__divdc3",
    "__divsc3",
    "__divtc3",
}

IGNORED_WL_PREFIXES = (
    "-soname",
    "-h,",
    "-rpath",
    "--rpath",
    "--version-script",
    "--export-dynamic",
    "-export-dynamic",
    "-E",
    "--as-needed",
    "--no-as-needed",
    "-Bdynamic",
    "-Bstatic",
    "-bdynamic",
    "-bstatic",
    "--enable-new-dtags",
    "--disable-new-dtags",
    "-O",
    "-s",
    "-x",
    "-z,",
    "--strip-all",
    "--gc-sections",
    "--no-undefined",
    "--allow-shlib-undefined",
    "--copy-dt-needed-entries",
    "--no-copy-dt-needed-entries",
)

SOURCE_EXTS = {".c", ".cc", ".cpp", ".cxx", ".C", ".s", ".S", ".m"}


def die(msg: str, code: int = 1) -> "NoReturn":
    sys.stderr.write(f"obsd-sdk: {msg}\n")
    raise SystemExit(code)


def resolve_libobsdcompat_root() -> pathlib.Path:
    env_val = os.environ.get("LIBOBSDCOMPAT_ROOT", "").strip()
    if env_val:
        p = pathlib.Path(env_val).resolve()
        if not (p / "vendor/openbsd/versions").is_dir():
            die(f"LIBOBSDCOMPAT_ROOT={p} has no vendor/openbsd/versions")
        return p

    locator = REPO_ROOT / "tools/config/locate-libobsdcompat.sh"
    proc = subprocess.run(
        ["sh", str(locator)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr)
        raise SystemExit(proc.returncode)
    return pathlib.Path(proc.stdout.strip()).resolve()


class ToolchainContext:
    def __init__(self) -> None:
        self.openbsd_version = os.environ.get("OPENBSD_VERSION", "8.0").strip() or "8.0"
        self.backend = os.environ.get("COMPAT_BACKEND", "emulate").strip() or "emulate"
        self.pal = os.environ.get("COMPAT_PAL", "emscripten").strip() or "emscripten"
        self.obsd_root = resolve_libobsdcompat_root()

        stage_env = os.environ.get("OBSD_STAGE_DIR", "").strip()
        if stage_env:
            self.stage_dir = pathlib.Path(stage_env).resolve()
        else:
            self.stage_dir = (
                REPO_ROOT / "build/openbsd" / self.openbsd_version / self.backend / self.pal / "stage"
            ).resolve()

        self.cache_dir = REPO_ROOT / ".cache/sdk"
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        self.wasm_build_dir = self.obsd_root / f"build/wasm-{self.openbsd_version}"
        self.include_root = self.wasm_build_dir / f"include-root-{self.openbsd_version}"
        self.base_archive = self.wasm_build_dir / f"libobsdc-wasm-{self.openbsd_version}.a"

        emsdk_root = self.obsd_root / "deps/emsdk"
        em_dir = emsdk_root / "upstream/emscripten"
        llvm_bin = emsdk_root / "upstream/bin"
        self.em_dir = em_dir
        self.emcc = em_dir / "emcc"
        self.emcxx = em_dir / "em++"
        self.emar = em_dir / "emar"
        self.emranlib = em_dir / "emranlib"
        self.wasm_ld = llvm_bin / "wasm-ld"
        self.llvm_nm = llvm_bin / "llvm-nm"
        self.em_sysroot = em_dir / "cache/sysroot"

        if not self.emcc.is_file():
            die(f"missing Emscripten compiler at {self.emcc} (run bootstrap_emsdk.sh in libobsdcompat)")

    def clang_resource_include(self) -> str:
        stamp = f"{self.emcc}:{self.emcc.stat().st_mtime_ns}"
        key = hashlib.sha1(stamp.encode()).hexdigest()[:16]
        cache_file = self.cache_dir / f"clang-res-{key}.txt"
        if cache_file.is_file():
            return cache_file.read_text(encoding="utf-8").strip()
        out = subprocess.check_output([str(self.emcc), "-print-resource-dir"], text=True).strip()
        inc = str(pathlib.Path(out) / "include")
        cache_file.write_text(inc + "\n", encoding="utf-8")
        return inc

    def allowed_undefined_symbols(self) -> Set[str]:
        if not self.base_archive.is_file():
            die(f"missing base OpenBSD WASM archive: {self.base_archive}")
        st = self.base_archive.stat()
        sig = f"{self.base_archive}:{st.st_size}:{st.st_mtime_ns}"
        key = hashlib.sha1(sig.encode()).hexdigest()[:16]
        cache_file = self.cache_dir / f"allowed-undefs-{self.openbsd_version}-{key}.json"
        if cache_file.is_file():
            return set(json.loads(cache_file.read_text(encoding="utf-8")))

        out = subprocess.check_output(
            [str(self.llvm_nm), "--defined-only", "-g", str(self.base_archive)],
            text=True,
            stderr=subprocess.DEVNULL,
        )
        allowed: Set[str] = set(WASM_BOUNDARY_IMPORTS) | set(COMPILER_RT_BUILTINS)
        for ln in out.splitlines():
            ps = ln.split()
            if len(ps) >= 3 and not ln.endswith(":"):
                allowed.add(ps[-1])

        for rt_cand in (
            self.em_sysroot / "lib/wasm64-emscripten/libclang_rt.builtins-mt.a",
            self.em_sysroot / "lib/wasm64-emscripten/libclang_rt.builtins.a",
            self.em_sysroot / "lib/wasm64-emscripten/libcompiler_rt-mt.a",
            self.em_sysroot / "lib/wasm64-emscripten/libcompiler_rt.a",
        ):
            if rt_cand.is_file():
                rt_out = subprocess.check_output(
                    [str(self.llvm_nm), "--defined-only", "-g", str(rt_cand)],
                    text=True,
                    stderr=subprocess.DEVNULL,
                )
                for ln in rt_out.splitlines():
                    ps = ln.split()
                    if len(ps) >= 3 and not ln.endswith(":"):
                        allowed.add(ps[-1])
                break

        tmp = cache_file.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(sorted(allowed)), encoding="utf-8")
        tmp.replace(cache_file)
        return allowed

    def remap_include_dir(self, path_str: str) -> Optional[str]:
        p = path_str.strip()
        if p.startswith("="):
            p = p[1:]
        norm = os.path.normpath(p)
        if norm == "/usr/include" or norm.startswith("/usr/include/"):
            sub = norm[len("/usr/include") :].lstrip("/")
            return str(self.include_root / sub) if sub else str(self.include_root)
        if norm == "/usr/local/include" or norm.startswith("/usr/local/include/"):
            sub = norm[len("/usr/local/include") :].lstrip("/")
            base = self.stage_dir / "usr/local/include"
            return str(base / sub) if sub else str(base)
        return path_str

    def remap_lib_dir(self, path_str: str) -> Optional[str]:
        p = path_str.strip()
        if p.startswith("="):
            p = p[1:]
        norm = os.path.normpath(p)
        if norm in ("/usr/lib", "/lib", "/usr/lib64", "/lib64"):
            return None
        if norm == "/usr/local/lib" or norm.startswith("/usr/local/lib/"):
            sub = norm[len("/usr/local/lib") :].lstrip("/")
            base = self.stage_dir / "usr/local/lib"
            return str(base / sub) if sub else str(base)
        return path_str


def is_source_file(arg: str) -> bool:
    if arg.startswith("-") or arg == "-":
        return False
    _, ext = os.path.splitext(arg)
    return ext in SOURCE_EXTS


def is_object_or_archive(arg: str) -> bool:
    if arg.startswith("-"):
        return False
    if arg.endswith((".o", ".lo", ".a", ".rlib", ".so")):
        return True
    if ".so." in os.path.basename(arg):
        return True
    p = pathlib.Path(arg)
    if p.is_file():
        try:
            with p.open("rb") as fp:
                hdr = fp.read(8)
            if hdr == b"\x00asm\x01\x00\x00\x00" or hdr.startswith((b"!<arch>\n", b"!<thin>\n")):
                return True
        except OSError:
            pass
    return False


LIBCPP_CONFIG_SITE_TEXT = """\
#ifndef _LIBCPP___CONFIG_SITE
#define _LIBCPP___CONFIG_SITE

#define _LIBCPP_ABI_VERSION 2
#define _LIBCPP_ABI_NAMESPACE __2
#define _LIBCPP_ABI_FORCE_ITANIUM 0
#define _LIBCPP_ABI_FORCE_MICROSOFT 0
#define _LIBCPP_HAS_THREADS 1
#define _LIBCPP_HAS_MONOTONIC_CLOCK 1
#define _LIBCPP_HAS_MUSL_LIBC 0
#define _LIBCPP_HAS_THREAD_API_PTHREAD 1
#define _LIBCPP_HAS_THREAD_API_EXTERNAL 0
#define _LIBCPP_HAS_THREAD_API_WIN32 0
#define _LIBCPP_HAS_THREAD_API_C11 0
#define _LIBCPP_HAS_VENDOR_AVAILABILITY_ANNOTATIONS 0
#define _LIBCPP_HAS_FILESYSTEM 1
#define _LIBCPP_HAS_RANDOM_DEVICE 1
#define _LIBCPP_HAS_LOCALIZATION 1
#define _LIBCPP_HAS_UNICODE 1
#define _LIBCPP_HAS_WIDE_CHARACTERS 1
#define _LIBCPP_HAS_TIME_ZONE_DATABASE 0
#define _LIBCPP_INSTRUMENTED_WITH_ASAN 0
#define _LIBCPP_PSTL_BACKEND_SERIAL
#define _LIBCPP_HARDENING_MODE_DEFAULT _LIBCPP_HARDENING_MODE_NONE
#define _LIBCPP_ASSERTION_SEMANTIC_DEFAULT _LIBCPP_ASSERTION_SEMANTIC_HARDENING_DEPENDENT
#define _LIBCPP_LIBC_PICOLIBC 0
#define _LIBCPP_LIBC_NEWLIB 0
#define _LIBCPP_LIBC_LLVM_LIBC 0

#endif // _LIBCPP___CONFIG_SITE
"""

THREADS_H_SHIM_TEXT = """\
#ifndef _OBSD_SDK_THREADS_H
#define _OBSD_SDK_THREADS_H
#ifndef __cplusplus
#ifndef thread_local
#define thread_local _Thread_local
#endif
#endif
#endif
"""

OBSD_CXX_SUPPORT_C = """\
#include <nl_types.h>

__attribute__((visibility("default"), weak)) void *__dso_handle = (void *)0;

__attribute__((visibility("default"), weak)) nl_catd
catopen(const char *name, int oflag)
{
\t(void)name;
\t(void)oflag;
\treturn (nl_catd)-1;
}

__attribute__((visibility("default"), weak)) char *
catgets(nl_catd catd, int set_id, int msg_id, const char *s)
{
\t(void)catd;
\t(void)set_id;
\t(void)msg_id;
\treturn (char *)s;
}

__attribute__((visibility("default"), weak)) int
catclose(nl_catd catd)
{
\t(void)catd;
\treturn 0;
}
"""


def ensure_cxx_config_dir(ctx: ToolchainContext) -> pathlib.Path:
    cfg_dir = ctx.cache_dir / f"cxx-cfg-{ctx.openbsd_version}"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    for fname, content in (
        ("__config_site", LIBCPP_CONFIG_SITE_TEXT),
        ("threads.h", THREADS_H_SHIM_TEXT),
    ):
        target = cfg_dir / fname
        if not target.is_file() or target.read_text(encoding="utf-8") != content:
            tmp = target.with_suffix(f".{os.getpid()}.tmp")
            tmp.write_text(content, encoding="utf-8")
            tmp.replace(target)
    return cfg_dir


def ensure_cxx_runtime(ctx: ToolchainContext) -> Tuple[pathlib.Path, pathlib.Path]:
    """
    Build & cache WASM64 `-pthread` `libc++.a` + `libc++abi.a` (with native Wasm EH
    `-fwasm-exceptions` + `-sSUPPORT_LONGJMP=0`) compiled directly against the
    OpenBSD `<ver>` sysroot (`include-root-<ver>`) so `FILE`/`errno`/`pthread_mutex_t`/
    `stat`/`locale` layouts match `libobsdc-wasm-<ver>.a` 100%.
    """
    if not ctx.include_root.is_dir():
        die(f"missing OpenBSD {ctx.openbsd_version} include root: {ctx.include_root}")

    sig_src = (
        f"cxx-rt-v2:{ctx.openbsd_version}:{ctx.emcxx.stat().st_mtime_ns}:"
        f"{ctx.base_archive.stat().st_mtime_ns if ctx.base_archive.is_file() else 0}:"
        f"{LIBCPP_CONFIG_SITE_TEXT}:{OBSD_CXX_SUPPORT_C}"
    )
    key = hashlib.sha256(sig_src.encode("utf-8")).hexdigest()[:16]
    rt_dir = ctx.cache_dir / f"cxx-rt-{ctx.openbsd_version}-{key}"
    libcxx_a = rt_dir / "libc++.a"
    libcxxabi_a = rt_dir / "libc++abi.a"
    stamp_file = rt_dir / "cxx-rt.stamp"

    if stamp_file.is_file() and libcxx_a.is_file() and libcxxabi_a.is_file():
        return libcxx_a, libcxxabi_a

    rt_dir.mkdir(parents=True, exist_ok=True)
    lock_path = ctx.cache_dir / f"cxx-rt-{ctx.openbsd_version}.lock"
    with lock_path.open("w") as lock_fp:
        fcntl.flock(lock_fp.fileno(), fcntl.LOCK_EX)
        if stamp_file.is_file() and libcxx_a.is_file() and libcxxabi_a.is_file():
            return libcxx_a, libcxxabi_a

        cfg_dir = ensure_cxx_config_dir(ctx)
        sp = ctx.obsd_root / "src/personalities/openbsd/runtime/backends/translate/boundary"
        res_inc = ctx.clang_resource_include()

        common = [
            "-m64",
            "-pthread",
            "-O2",
            "-fno-common",
            "-fno-builtin",
            "-fwasm-exceptions",
            "-sSUPPORT_LONGJMP=0",
            "-fsanitize-coverage=func,trace-pc",
            "-Wno-invalid-noreturn",
            "-Wno-unsupported-visibility",
            "-Wno-ignored-attributes",
            "-Wno-macro-redefined",
            "-Wno-unused-but-set-variable",
            "-Wno-unqualified-std-cast-call",
            "-Wno-unknown-warning-option",
            "-Wno-user-defined-literals",
            "-U__APPLE__",
            "-U__MACH__",
            "-U__EMSCRIPTEN__",
            "-U__linux__",
            "-U__gnu_linux__",
            "-Ulinux",
            "-D__OpenBSD__=1",
            "-D__unix__=1",
            "-D__LP64__=1",
            "-D_LP64=1",
            "-DLIBOBSDCOMPAT_OBJECT_FORMAT_WASM=1",
            "-DLIBOBSDCOMPAT_KERN_GATE=1",
            "-DLIBOBSDCOMPAT_BOUNDARY_BACKEND_EMULATE=1",
            "-DHAVE_ATTRIBUTE__BOUNDED__=1",
            "-nostdinc",
        ]
        sys_incs = [
            "-isystem",
            str(cfg_dir),
            "-isystem",
            str(ctx.em_dir / "system/lib/libcxx/include"),
            "-isystem",
            str(ctx.em_dir / "system/lib/libcxxabi/include"),
            "-isystem",
            str(sp / "wasm-gate-shadow"),
            "-isystem",
            str(sp),
            "-isystem",
            str(ctx.wasm_build_dir / "gen"),
            "-isystem",
            str(ctx.include_root),
            "-include",
            str(sp / "formats/wasm_compat.h"),
            "-idirafter",
            res_inc,
        ]

        with tempfile.TemporaryDirectory(prefix=f"obsd-cxx-rt-{ctx.openbsd_version}-") as td:
            tp = pathlib.Path(td)
            tasks: List[Tuple[str, List[str]]] = []

            sup_c = tp / "obsd_cxx_support.c"
            sup_o = tp / "obsd_cxx_support.o"
            sup_c.write_text(OBSD_CXX_SUPPORT_C, encoding="utf-8")
            tasks.append(("support", [str(ctx.emcc), "-c", *common, *sys_incs, str(sup_c), "-o", str(sup_o)]))

            uw_o = tp / "Unwind-wasm.o"
            tasks.append(
                (
                    "unwind",
                    [
                        str(ctx.emcc),
                        "-c",
                        *common,
                        "-DNDEBUG",
                        "-D_LIBUNWIND_HIDE_SYMBOLS",
                        "-Wno-c23-extensions",
                        "-I",
                        str(ctx.em_dir / "system/lib/libunwind/include"),
                        *sys_incs,
                        str(ctx.em_dir / "system/lib/libunwind/src/Unwind-wasm.c"),
                        "-o",
                        str(uw_o),
                    ],
                )
            )

            abi_objs: List[pathlib.Path] = []
            abi_files = [
                "abort_message.cpp",
                "cxa_aux_runtime.cpp",
                "cxa_default_handlers.cpp",
                "cxa_demangle.cpp",
                "cxa_guard.cpp",
                "cxa_handlers.cpp",
                "cxa_virtual.cpp",
                "cxa_thread_atexit.cpp",
                "cxa_vector.cpp",
                "fallback_malloc.cpp",
                "stdlib_new_delete.cpp",
                "stdlib_exception.cpp",
                "stdlib_stdexcept.cpp",
                "stdlib_typeinfo.cpp",
                "private_typeinfo.cpp",
                "cxa_exception_storage.cpp",
                "cxa_exception.cpp",
                "cxa_personality.cpp",
            ]
            for fn in abi_files:
                o = tp / f"abi_{fn}.o"
                abi_objs.append(o)
                tasks.append(
                    (
                        f"cxxabi:{fn}",
                        [
                            str(ctx.emcxx),
                            "-c",
                            "-nostdinc++",
                            "-std=c++23",
                            *common,
                            "-DNDEBUG",
                            "-DHAVE___CXA_THREAD_ATEXIT_IMPL=1",
                            "-D_LIBCPP_BUILDING_LIBRARY",
                            "-D_LIBCPP_DISABLE_VISIBILITY_ANNOTATIONS",
                            "-D_LIBCXXABI_BUILDING_LIBRARY",
                            "-D_LIBCXXABI_DISABLE_VISIBILITY_ANNOTATIONS",
                            "-DLIBCXXABI_NON_DEMANGLING_TERMINATE",
                            "-I",
                            str(ctx.em_dir / "system/lib/libcxx/src"),
                            "-I",
                            str(ctx.em_dir / "system/lib/libunwind/include"),
                            *sys_incs,
                            str(ctx.em_dir / "system/lib/libcxxabi/src" / fn),
                            "-o",
                            str(o),
                        ],
                    )
                )

            exclude = {
                "xlocale_zos.cpp",
                "mbsnrtowcs.cpp",
                "wcsnrtombs.cpp",
                "int128_builtins.cpp",
                "libdispatch.cpp",
                "locale_win32.cpp",
                "thread_win32.cpp",
                "support.cpp",
                "compiler_rt_shims.cpp",
                "time_zone.cpp",
                "tzdb.cpp",
                "tzdb_list.cpp",
                "text_encoding.cpp",
            }
            cxx_objs: List[pathlib.Path] = []
            cxx_src_root = ctx.em_dir / "system/lib/libcxx/src"
            for src in sorted(cxx_src_root.rglob("*.cpp")):
                rel = src.relative_to(cxx_src_root).as_posix()
                if src.name in exclude or rel.startswith(
                    ("experimental/", "pstl/", "support/win32/", "support/ibm/", "support/zos/")
                ):
                    continue
                o = tp / f"cxx_{rel.replace('/', '__')}.o"
                cxx_objs.append(o)
                tasks.append(
                    (
                        f"cxx:{rel}",
                        [
                            str(ctx.emcxx),
                            "-c",
                            "-nostdinc++",
                            "-std=c++23",
                            *common,
                            "-DNDEBUG",
                            "-DLIBCXX_BUILDING_LIBCXXABI=1",
                            "-D_LIBCPP_BUILDING_LIBRARY",
                            "-D_LIBCPP_AVAILABILITY_MINIMUM_HEADER_VERSION=23",
                            "-D_LIBCPP_DISABLE_VISIBILITY_ANNOTATIONS",
                            "-D_LIBCPP_HAS_NO_PRAGMA_SYSTEM_HEADER",
                            "-DLIBC_NAMESPACE=__llvm_libc",
                            "-I",
                            str(cxx_src_root),
                            "-I",
                            str(ctx.em_dir / "system/lib/llvm-libc"),
                            *sys_incs,
                            str(src),
                            "-o",
                            str(o),
                        ],
                    )
                )

            def _compile_one(item: Tuple[str, List[str]]) -> Tuple[str, int, str]:
                lbl, cmd_vec = item
                p = subprocess.run(cmd_vec, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                return lbl, p.returncode, p.stderr

            with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count() or 8) as pool:
                for lbl, rc, err_txt in pool.map(_compile_one, tasks):
                    if rc != 0:
                        die(f"failed building WASM64 C++ runtime ({lbl}):\n{err_txt}")

            tmp_cxx = tp / "libc++.a"
            tmp_abi = tp / "libc++abi.a"
            subprocess.run([str(ctx.emar), "rcs", str(tmp_cxx), *[str(x) for x in cxx_objs]], check=True)
            subprocess.run(
                [str(ctx.emar), "rcs", str(tmp_abi), *[str(x) for x in abi_objs], str(uw_o), str(sup_o)],
                check=True,
            )

            shutil.copy2(tmp_cxx, libcxx_a)
            shutil.copy2(tmp_abi, libcxxabi_a)
            shutil.copy2(tmp_cxx, rt_dir / "libc++-noexcept.a")
            shutil.copy2(tmp_abi, rt_dir / "libc++abi-noexcept.a")
            stamp_file.write_text(key + "\n", encoding="utf-8")

    return libcxx_a, libcxxabi_a


def build_guest_compile_flags(ctx: ToolchainContext, is_cxx: bool, preprocess_only: bool) -> Tuple[List[str], List[str]]:
    sp = ctx.obsd_root / "src/personalities/openbsd/runtime/backends/translate/boundary"
    shadow_inc = sp / "wasm-gate-shadow"
    wasm_compat_h = sp / "formats/wasm_compat.h"
    gen_dir = ctx.wasm_build_dir / "gen"

    if not ctx.include_root.is_dir():
        die(f"missing OpenBSD {ctx.openbsd_version} include root: {ctx.include_root}")

    prefix_flags = [
        "-m64",
        "-pthread",
        "-O2",
        "-fno-common",
        "-fno-builtin",
        "-sSUPPORT_LONGJMP=0",
        "-Wno-invalid-noreturn",
        "-Wno-unsupported-visibility",
        "-Wno-ignored-attributes",
        "-Wno-macro-redefined",
    ]
    if is_cxx:
        prefix_flags.extend(
            [
                "-fwasm-exceptions",
                "-D_LIBCPP_DISABLE_VISIBILITY_ANNOTATIONS",
                "-D_LIBCXXABI_DISABLE_VISIBILITY_ANNOTATIONS",
            ]
        )
    if not preprocess_only:
        prefix_flags.append("-fsanitize-coverage=func,trace-pc" if is_cxx else "-fsanitize-coverage=trace-pc,no-prune")

    prefix_flags.extend(
        [
            "-U__APPLE__",
            "-U__MACH__",
            "-U__EMSCRIPTEN__",
            "-U__linux__",
            "-U__gnu_linux__",
            "-Ulinux",
            "-D__OpenBSD__=1",
            "-D__unix__=1",
            "-D__LP64__=1",
            "-D_LP64=1",
            "-DLIBOBSDCOMPAT_OBJECT_FORMAT_WASM=1",
            "-DLIBOBSDCOMPAT_KERN_GATE=1",
            "-DLIBOBSDCOMPAT_BOUNDARY_BACKEND_EMULATE=1",
            "-DHAVE_ATTRIBUTE__BOUNDED__=1",
            "-nostdinc",
        ]
    )
    if is_cxx:
        prefix_flags.append("-nostdinc++")

    suffix_flags: List[str] = []
    if is_cxx:
        cxx_cfg = ensure_cxx_config_dir(ctx)
        libcxx_inc = ctx.em_dir / "system/lib/libcxx/include"
        libcxxabi_inc = ctx.em_dir / "system/lib/libcxxabi/include"
        suffix_flags.extend(
            [
                "-isystem",
                str(cxx_cfg),
                "-isystem",
                str(libcxx_inc),
                "-isystem",
                str(libcxxabi_inc),
            ]
        )

    stage_inc = ctx.stage_dir / "usr/local/include"
    if stage_inc.is_dir():
        suffix_flags.extend(["-isystem", str(stage_inc)])

    suffix_flags.extend(
        [
            "-isystem",
            str(shadow_inc),
            "-isystem",
            str(sp),
            "-isystem",
            str(gen_dir),
            "-isystem",
            str(ctx.include_root),
            *(["-include", str(wasm_compat_h)] if not preprocess_only else []),
            "-idirafter",
            ctx.clang_resource_include(),
        ]
    )
    return prefix_flags, suffix_flags


def resolve_lo_file(path_str: str) -> str:
    """Resolve GNU libtool `.lo` wrapper text files to the real `.o` object."""
    if not path_str.endswith(".lo"):
        return path_str
    p = pathlib.Path(path_str)
    if not p.is_file():
        return path_str
    try:
        head = p.read_bytes()[:64]
        if head.startswith(b"\x00asm"):
            return path_str
        txt = p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return path_str
    pic_obj = None
    non_pic_obj = None
    for ln in txt.splitlines():
        s = ln.strip()
        if s.startswith("non_pic_object="):
            val = s.split("=", 1)[1].strip().strip("'\"")
            if val and val != "none":
                non_pic_obj = val
        elif s.startswith("pic_object="):
            val = s.split("=", 1)[1].strip().strip("'\"")
            if val and val != "none":
                pic_obj = val
    chosen = non_pic_obj or pic_obj
    if chosen:
        cand = p.parent / chosen
        if cand.is_file():
            return str(cand)
    return path_str


def resolve_library(
    ctx: ToolchainContext,
    name: str,
    lib_dirs: Sequence[str],
    stage_lib_dir: pathlib.Path,
) -> Tuple[Optional[str], bool]:
    """
    Resolve `-l<name>`:
      - Returns `(archive_path, True)` if a port or SDK C++ static library is found.
      - Returns `(None, True)` if `<name>` is a verified base OpenBSD library in `libobsdc-wasm-<ver>.a`.
      - Returns `(None, False)` if not found.
    """
    search_dirs = list(lib_dirs)
    if stage_lib_dir.is_dir():
        s_str = str(stage_lib_dir)
        if s_str not in search_dirs:
            search_dirs.append(s_str)

    if name.startswith(":"):
        exact = name[1:]
        for d in search_dirs:
            cand = pathlib.Path(d) / exact
            if cand.is_file():
                return str(cand), True
        return None, False

    for d in search_dirs:
        dp = pathlib.Path(d)
        cand_a = dp / f"lib{name}.a"
        if cand_a.is_file():
            return str(cand_a), True
        # Also support lib<name>.la libtool descriptors pointing to old_library='lib<name>.a'
        cand_la = dp / f"lib{name}.la"
        if cand_la.is_file():
            try:
                for ln in cand_la.read_text(encoding="utf-8", errors="replace").splitlines():
                    if ln.startswith("old_library="):
                        old_lib = ln.split("=", 1)[1].strip().strip("'\"")
                        if old_lib:
                            for sub in (dp / old_lib, dp / ".libs" / old_lib):
                                if sub.is_file():
                                    return str(sub), True
            except OSError:
                pass

    if name in ("c++", "stdc++", "c++-noexcept"):
        libcxx_a, _ = ensure_cxx_runtime(ctx)
        return str(libcxx_a), True
    if name in ("c++abi", "supc++", "unwind", "c++abi-noexcept"):
        _, libcxxabi_a = ensure_cxx_runtime(ctx)
        return str(libcxxabi_a), True
    if name in ("gcc", "gcc_s"):
        return None, True

    if name in BASE_OPENBSD_LIBS:
        return None, True

    return None, False


def wrap_wasm_init_funcs(ctx: ToolchainContext, obj_path: pathlib.Path, tmp_dir: pathlib.Path) -> int:
    """
    When a linked WASM64 relocatable binary defines a guest main entrypoint AND
    carries `WASM_INIT_FUNCS` static constructors (e.g. C++ `std::ios_base::Init`
    or global object constructors), synthesize a per-exec entry wrapper that
    invokes all `WASM_INIT_FUNCS` in priority order before calling the real
    `main`. Required because `wasm_object_tool.py window-guest` strips module-level
    `WASM_INIT_FUNCS` so guest constructors never run on the host at module load.
    """
    emulate_tools = ctx.obsd_root / "tools/build/personalities/openbsd/backends/emulate"
    if str(emulate_tools) not in sys.path:
        sys.path.insert(0, str(emulate_tools))
    import wasm_object_tool as wot  # type: ignore

    data = obj_path.read_bytes()
    if data[:8] != wot.WASM_MAGIC:
        return 0

    func_types: List[Tuple[List[int], List[int]]] = []
    imported_func_type_idxs: List[int] = []
    defined_func_type_idxs: List[int] = []
    has_inits = False
    pos = 8

    while pos < len(data):
        sec_id = data[pos]
        sec_len, body = wot.read_uleb(data, pos + 1)
        sec_end = body + sec_len
        if sec_id == 1:
            cnt, p = wot.read_uleb(data, body)
            for _ in range(cnt):
                form = data[p]
                p += 1
                if form != 0x60:
                    return 0
                pcnt, p = wot.read_uleb(data, p)
                params = list(data[p : p + pcnt])
                p += pcnt
                rcnt, p = wot.read_uleb(data, p)
                results = list(data[p : p + rcnt])
                p += rcnt
                func_types.append((params, results))
        elif sec_id == 2:
            cnt, p = wot.read_uleb(data, body)
            for _ in range(cnt):
                mlen, p = wot.read_uleb(data, p)
                p += mlen
                flen, p = wot.read_uleb(data, p)
                p += flen
                kind = data[p]
                p += 1
                if kind == 0:
                    tidx, p = wot.read_uleb(data, p)
                    imported_func_type_idxs.append(tidx)
                elif kind == 1:
                    p += 1
                    flags, p = wot.read_uleb(data, p)
                    _, p = wot.read_uleb(data, p)
                    if flags & 0x01:
                        _, p = wot.read_uleb(data, p)
                elif kind == 2:
                    flags, p = wot.read_uleb(data, p)
                    _, p = wot.read_uleb(data, p)
                    if flags & 0x01:
                        _, p = wot.read_uleb(data, p)
                elif kind == 3:
                    p += 2
                elif kind == 4:
                    p += 1
                    _, p = wot.read_uleb(data, p)
        elif sec_id == 3:
            cnt, p = wot.read_uleb(data, body)
            for _ in range(cnt):
                tidx, p = wot.read_uleb(data, p)
                defined_func_type_idxs.append(tidx)
        elif sec_id == 0:
            nlen, npos = wot.read_uleb(data, body)
            sname = data[npos : npos + nlen].decode("utf-8", "replace")
            if sname == "linking":
                ver, p = wot.read_uleb(data, npos + nlen)
                if ver == 2:
                    while p < sec_end:
                        stype = data[p]
                        slen, sp = wot.read_uleb(data, p + 1)
                        if stype == wot.WASM_INIT_FUNCS and slen > 0:
                            icnt, _ = wot.read_uleb(data[sp : sp + slen], 0)
                            if icnt > 0:
                                has_inits = True
                        p = sp + slen
        pos = sec_end

    if not has_inits:
        return 0

    all_func_types = imported_func_type_idxs + defined_func_type_idxs
    entry_orig_name: Optional[str] = None
    entry_arity = 2
    entry_ret_void = False
    ordered_ctor_names: List[str] = []

    def _transform(subsecs: List[Tuple[int, bytes]]) -> List[Tuple[int, bytes]]:
        nonlocal entry_orig_name, entry_arity, entry_ret_void
        syms = None
        inits: List[Tuple[int, int]] = []
        for stype, payload in subsecs:
            if stype == wot.WASM_SYMBOL_TABLE:
                syms = wot.parse_symbols(payload)
            elif stype == wot.WASM_INIT_FUNCS:
                cnt, ip = wot.read_uleb(payload, 0)
                for _ in range(cnt):
                    prio, ip = wot.read_uleb(payload, ip)
                    sidx, ip = wot.read_uleb(payload, ip)
                    inits.append((prio, sidx))

        if not syms or not inits:
            return subsecs

        chosen_idx: Optional[int] = None
        for cand in ("obsd_tool_main", "__main_argc_argv", "main"):
            for idx, s in enumerate(syms):
                if (
                    s["kind"] == wot.SYMTAB_FUNCTION
                    and not (s["flags"] & (wot.WASM_SYM_UNDEFINED | wot.WASM_SYM_BINDING_LOCAL))
                    and s.get("name") == cand
                ):
                    chosen_idx = idx
                    entry_orig_name = cand
                    break
            if chosen_idx is not None:
                break

        if chosen_idx is None or entry_orig_name is None:
            return subsecs

        elem_idx = syms[chosen_idx]["elem_idx"]
        params, results = func_types[all_func_types[elem_idx]]
        entry_arity = len(params)
        entry_ret_void = len(results) == 0

        sidx_to_name: Dict[int, str] = {}
        for _, (prio, sidx) in sorted(enumerate(inits), key=lambda x: (x[1][0], x[0])):
            if sidx not in sidx_to_name:
                cname = f"__obsd_ctor_fn_{len(sidx_to_name)}"
                sidx_to_name[sidx] = cname
                wot.make_exported_default(syms[sidx], cname)
            ordered_ctor_names.append(sidx_to_name[sidx])

        wot.make_exported_default(syms[chosen_idx], "__obsd_real_main")
        if entry_orig_name == "__main_argc_argv":
            for idx, s in enumerate(syms):
                if (
                    idx != chosen_idx
                    and s["kind"] == wot.SYMTAB_FUNCTION
                    and not (s["flags"] & wot.WASM_SYM_UNDEFINED)
                    and s.get("name") == "main"
                ):
                    wot.make_local(s, prefix="__obsd_unused$")

        new_subsecs: List[Tuple[int, bytes]] = []
        for stype, payload in subsecs:
            if stype == wot.WASM_INIT_FUNCS:
                continue
            if stype == wot.WASM_SYMBOL_TABLE:
                new_subsecs.append((stype, wot.serialize_symbols(syms)))
            else:
                new_subsecs.append((stype, payload))
        return new_subsecs

    rewritten_bytes = wot.rewrite_wasm_object(data, _transform)
    if entry_orig_name is None or not ordered_ctor_names:
        return 0

    target_o = tmp_dir / "init_target.o"
    target_o.write_bytes(rewritten_bytes)

    rtype = "void" if entry_ret_void else "int"
    if entry_arity == 0:
        sig_decl, call_args = "void", ""
    elif entry_arity == 1:
        sig_decl, call_args = "int argc", "argc"
    elif entry_arity == 2:
        sig_decl, call_args = "int argc, char **argv", "argc, argv"
    else:
        sig_decl, call_args = "int argc, char **argv, char **envp", "argc, argv, envp"

    unique_ctors = list(dict.fromkeys(ordered_ctor_names))
    lines = [f"extern void {c}(void);" for c in unique_ctors]
    lines.append(f"extern {rtype} __obsd_real_main({sig_decl});")
    lines.append(f'{rtype} __obsd_ctor_entry({sig_decl}) __asm__("{entry_orig_name}");')
    lines.append(f"{rtype} __obsd_ctor_entry({sig_decl}) {{")
    for c in ordered_ctor_names:
        lines.append(f"\t{c}();")
    if entry_ret_void:
        lines.append(f"\t__obsd_real_main({call_args});")
    else:
        lines.append(f"\treturn __obsd_real_main({call_args});")
    lines.append("}")

    wrap_c = tmp_dir / "ctor_wrap.c"
    wrap_o = tmp_dir / "ctor_wrap.o"
    wrap_c.write_text("\n".join(lines) + "\n", encoding="utf-8")

    rc = subprocess.run(
        [
            str(ctx.emcc),
            "-c",
            "-m64",
            "-pthread",
            "-O2",
            "-fno-common",
            "-fno-builtin",
            "-sSUPPORT_LONGJMP=0",
            "-fsanitize-coverage=trace-pc,no-prune",
            "-nostdinc",
            str(wrap_c),
            "-o",
            str(wrap_o),
        ]
    ).returncode
    if rc != 0:
        return rc

    return subprocess.run(
        [str(ctx.wasm_ld), "-m", "wasm64", "-r", str(wrap_o), str(target_o), "-o", str(obj_path)]
    ).returncode


def verify_undefined_symbols(ctx: ToolchainContext, obj_path: pathlib.Path) -> Optional[List[str]]:
    proc = subprocess.run(
        [str(ctx.llvm_nm), "-u", str(obj_path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if proc.returncode != 0:
        return [f"<llvm-nm failed: {proc.stderr.strip()}>"]
    undefs: Set[str] = set()
    for ln in proc.stdout.splitlines():
        ps = ln.split()
        if len(ps) >= 2 and ps[-2] == "U":
            undefs.add(ps[-1])
        elif len(ps) == 2 and ps[0] == "U":
            undefs.add(ps[1])
        elif len(ps) == 1 and not ln.endswith(":"):
            undefs.add(ps[0])

    # Also ignore symbols defined inside obj_path itself
    def_proc = subprocess.run(
        [str(ctx.llvm_nm), "--defined-only", str(obj_path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    defined_self: Set[str] = set()
    for ln in def_proc.stdout.splitlines():
        ps = ln.split()
        if len(ps) >= 2 and not ln.endswith(":"):
            defined_self.add(ps[-1])

    allowed = ctx.allowed_undefined_symbols()
    missing = sorted(s for s in (undefs - defined_self) if s not in allowed)
    return missing or None


def run_cc_driver(argv: List[str], is_cxx: bool) -> int:
    ctx = ToolchainContext()
    compiler_bin = str(ctx.emcxx if is_cxx else ctx.emcc)

    if not argv:
        proc = subprocess.run([compiler_bin])
        return proc.returncode

    if len(argv) == 1 and argv[0] == "-dumpmachine":
        print(f"aarch64-unknown-openbsd{ctx.openbsd_version}")
        return 0

    # Strip foreign `--target=*` / `-target <triple>` flags added by `cc-rs` or build
    # scripts when cross-compiling for `wasm64-unknown-openbsd` / `aarch64-unknown-openbsd*`.
    cleaned_argv: List[str] = []
    idx_t = 0
    while idx_t < len(argv):
        tok_t = argv[idx_t]
        if tok_t in ("-target", "--target") and idx_t + 1 < len(argv):
            idx_t += 2
            continue
        if tok_t.startswith(("--target=", "-target=")):
            idx_t += 1
            continue
        cleaned_argv.append(tok_t)
        idx_t += 1
    argv = cleaned_argv

    if not argv:
        return subprocess.run([compiler_bin]).returncode

    # Pure info queries with no source/object inputs
    has_inputs = False
    mode_compile_only = False
    mode_preprocess = False
    is_shared = False
    output_path: Optional[str] = None
    explicit_lang: Optional[str] = None

    i = 0
    while i < len(argv):
        a = argv[i]
        if a in ("-c", "-S"):
            mode_compile_only = True
        elif a in ("-E", "-M", "-MM"):
            mode_preprocess = True
        elif a == "-shared":
            is_shared = True
        elif a == "-o" and i + 1 < len(argv):
            output_path = argv[i + 1]
            i += 2
            continue
        elif a.startswith("-o") and len(a) > 2:
            output_path = a[2:]
        elif a == "-x" and i + 1 < len(argv):
            explicit_lang = argv[i + 1]
            i += 2
            continue
        elif a.startswith("-x") and len(a) > 2:
            explicit_lang = a[2:]
        elif a in ("-I", "-isystem", "-iquote", "-idirafter", "-include", "-L", "-l", "-MF", "-MT", "-MQ", "-D", "-U") and i + 1 < len(argv):
            i += 2
            continue
        elif a == "-" and explicit_lang is not None:
            has_inputs = True
        elif not a.startswith("-"):
            has_inputs = True
        i += 1

    if not has_inputs:
        # e.g. `obsd-cc --version`, `obsd-cc -v`, `obsd-cc -dumpversion`
        filtered_q = [x for x in argv if x not in ("-V", "-qversion")]
        if len(filtered_q) != len(argv) and not filtered_q:
            # Autoconf probes `$CC -V` and `$CC -qversion` expecting failure on Clang/GCC
            return subprocess.run([compiler_bin, *argv]).returncode
        return subprocess.run([compiler_bin, *argv]).returncode

    prefix_cf, suffix_cf = build_guest_compile_flags(ctx, is_cxx=is_cxx, preprocess_only=mode_preprocess)

    # Parse arguments into compile flags vs link inputs
    compile_user_args: List[str] = []
    lib_dirs: List[str] = []
    link_items: List[Tuple[str, str]] = []  # ("src"|"obj"|"lib", value)
    dep_args: List[str] = []
    cur_lang: Optional[str] = None

    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "-o" and i + 1 < len(argv):
            i += 2
            continue
        if a.startswith("-o") and len(a) > 2:
            i += 1
            continue
        if a in ("-fPIC", "-fpic", "-fPIE", "-fpie", "-pie", "-no-pie", "-rdynamic", "-static", "-shared", "-s"):
            i += 1
            continue
        if a in ("-pthread", "-pthreads"):
            i += 1
            continue
        if a in ("-I", "-isystem", "-iquote", "-idirafter") and i + 1 < len(argv):
            remapped = ctx.remap_include_dir(argv[i + 1])
            if remapped:
                compile_user_args.extend([a, remapped])
            i += 2
            continue
        if a.startswith("-I") and len(a) > 2:
            remapped = ctx.remap_include_dir(a[2:])
            if remapped:
                compile_user_args.extend(["-I", remapped])
            i += 1
            continue
        if a.startswith("-isystem") and len(a) > len("-isystem"):
            remapped = ctx.remap_include_dir(a[len("-isystem") :])
            if remapped:
                compile_user_args.extend(["-isystem", remapped])
            i += 1
            continue
        if a == "-L" and i + 1 < len(argv):
            remapped_l = ctx.remap_lib_dir(argv[i + 1])
            if remapped_l:
                lib_dirs.append(remapped_l)
            i += 2
            continue
        if a.startswith("-L") and len(a) > 2:
            remapped_l = ctx.remap_lib_dir(a[2:])
            if remapped_l:
                lib_dirs.append(remapped_l)
            i += 1
            continue
        if a == "-l" and i + 1 < len(argv):
            link_items.append(("lib", argv[i + 1]))
            i += 2
            continue
        if a.startswith("-l") and len(a) > 2:
            link_items.append(("lib", a[2:]))
            i += 1
            continue
        if a.startswith("-Wl,"):
            wl_parts = a[4:].split(",")
            idx_w = 0
            while idx_w < len(wl_parts):
                tok = wl_parts[idx_w]
                joined = ",".join(wl_parts[idx_w:])
                if any(joined.startswith(pref) for pref in IGNORED_WL_PREFIXES) or tok in ("", "-rpath", "-soname"):
                    if tok in ("-rpath", "-soname", "-h", "-z") and idx_w + 1 < len(wl_parts):
                        idx_w += 2
                    else:
                        idx_w += 1
                    continue
                if tok.startswith("-L") and len(tok) > 2:
                    rl = ctx.remap_lib_dir(tok[2:])
                    if rl:
                        lib_dirs.append(rl)
                    idx_w += 1
                    continue
                if tok.startswith("-l") and len(tok) > 2:
                    link_items.append(("lib", tok[2:]))
                    idx_w += 1
                    continue
                # Unknown linker flag: forward to wasm-ld check in link mode so invalid flag probes fail
                link_items.append(("ldflag", tok))
                idx_w += 1
            i += 1
            continue
        if a in ("-MF", "-MT", "-MQ") and i + 1 < len(argv):
            dep_args.extend([a, argv[i + 1]])
            i += 2
            continue
        if a in ("-MD", "-MMD", "-MP", "-MG"):
            dep_args.append(a)
            i += 1
            continue
        if a == "-x" and i + 1 < len(argv):
            cur_lang = argv[i + 1]
            compile_user_args.extend([a, cur_lang])
            i += 2
            continue
        if a.startswith("-x") and len(a) > 2:
            cur_lang = a[2:]
            compile_user_args.append(a)
            i += 1
            continue
        if (a == "-" and cur_lang is not None) or (cur_lang in ("c", "c++", "assembler", "assembler-with-cpp") and not a.startswith("-")):
            link_items.append(("src", a))
            compile_user_args.append(a)
            i += 1
            continue
        if is_source_file(a):
            link_items.append(("src", a))
            compile_user_args.append(a)
            i += 1
            continue
        if is_object_or_archive(a):
            link_items.append(("obj", resolve_lo_file(a)))
            i += 1
            continue
        compile_user_args.append(a)
        i += 1

    # Mode 1: Preprocess / Dependency generation / Compile-only (`-E`, `-M`, `-MM`, `-c`, `-S`)
    if mode_preprocess or mode_compile_only:
        cmd = [compiler_bin, *prefix_cf, *compile_user_args, *dep_args, *suffix_cf]
        if mode_compile_only and "-c" not in compile_user_args and "-S" not in compile_user_args:
            if "-S" in argv:
                cmd.append("-S")
            else:
                cmd.append("-c")
        if output_path is not None:
            cmd.extend(["-o", output_path])
        return subprocess.run(cmd).returncode

    # Mode 2: Link mode (compile any `.c`/`.cc` inputs to temp `.o`s, resolve `-l` libs, run `wasm-ld -m wasm64 -r`)
    out_file = pathlib.Path(output_path or "a.out")
    compile_only_flags = [x for x in compile_user_args if not is_source_file(x) and x != "-"]

    with tempfile.TemporaryDirectory(prefix="obsd-cc-") as tmpdir:
        tmp_p = pathlib.Path(tmpdir)
        ld_inputs: List[str] = []
        ld_extra_flags: List[str] = []
        src_idx = 0

        for kind, val in link_items:
            if kind == "src":
                tmp_obj = tmp_p / f"tu_{src_idx:03d}.o"
                src_idx += 1
                src_args = [val]
                c_cmd = [
                    compiler_bin,
                    "-c",
                    *prefix_cf,
                    *compile_only_flags,
                    *(dep_args if len([k for k, _ in link_items if k == "src"]) == 1 else []),
                    *src_args,
                    *suffix_cf,
                    "-o",
                    str(tmp_obj),
                ]
                rc = subprocess.run(c_cmd).returncode
                if rc != 0:
                    return rc
                ld_inputs.append(str(tmp_obj))
            elif kind == "obj":
                ld_inputs.append(val)
            elif kind == "lib":
                resolved_ar, ok = resolve_library(ctx, val, lib_dirs, ctx.stage_dir / "usr/local/lib")
                if not ok:
                    sys.stderr.write(f"obsd-ld: error: unable to find library -l{val}\n")
                    return 1
                if resolved_ar is not None and resolved_ar not in ld_inputs:
                    ld_inputs.append(resolved_ar)
            elif kind == "ldflag":
                ld_extra_flags.append(val)

        if not ld_inputs:
            sys.stderr.write("obsd-ld: error: no input files\n")
            return 1

        no_default_cxx = any(f in argv for f in ("-nostdlib", "-nostdlib++", "-nodefaultlibs"))
        if is_cxx and not no_default_cxx:
            libcxx_a, libcxxabi_a = ensure_cxx_runtime(ctx)
            for ar_p in (str(libcxx_a), str(libcxxabi_a)):
                if ar_p not in ld_inputs:
                    ld_inputs.append(ar_p)
        elif any(os.path.basename(x).startswith("libc++.") or os.path.basename(x).startswith("libc++-") for x in ld_inputs):
            _, libcxxabi_a = ensure_cxx_runtime(ctx)
            if str(libcxxabi_a) not in ld_inputs:
                ld_inputs.append(str(libcxxabi_a))

        out_file.parent.mkdir(parents=True, exist_ok=True)
        tmp_linked = out_file.parent / f".{out_file.name}.{os.getpid()}.wasm.tmp"
        ld_cmd = [
            str(ctx.wasm_ld),
            "-m",
            "wasm64",
            "-r",
            *ld_extra_flags,
            *ld_inputs,
            "-o",
            str(tmp_linked),
        ]
        ld_proc = subprocess.run(ld_cmd)
        if ld_proc.returncode != 0:
            tmp_linked.unlink(missing_ok=True)
            return ld_proc.returncode

        if not is_shared:
            init_rc = wrap_wasm_init_funcs(ctx, tmp_linked, tmp_p)
            if init_rc != 0:
                tmp_linked.unlink(missing_ok=True)
                return init_rc
            missing_syms = verify_undefined_symbols(ctx, tmp_linked)
            if missing_syms:
                tmp_linked.unlink(missing_ok=True)
                for sym in missing_syms[:25]:
                    sys.stderr.write(f"obsd-ld: error: undefined symbol: {sym}\n")
                if len(missing_syms) > 25:
                    sys.stderr.write(f"obsd-ld: error: ... and {len(missing_syms) - 25} more undefined symbols\n")
                return 1

        tmp_linked.chmod(0o755)
        tmp_linked.replace(out_file)
        return 0


def ensure_base_pkgconfig_dir(ctx: ToolchainContext) -> pathlib.Path:
    pc_dir = ctx.cache_dir / f"base-pkgconfig-{ctx.openbsd_version}"
    pc_dir.mkdir(parents=True, exist_ok=True)
    specs = {
        "zlib.pc": ("zlib", "OpenBSD base zlib compression library", "1.3.1", "-lz", ""),
        "openssl.pc": ("OpenSSL", "OpenBSD base LibreSSL TLS and cryptography", "3.9.0", "-lssl -lcrypto", ""),
        "libcrypto.pc": ("OpenSSL-libcrypto", "OpenBSD base LibreSSL cryptography library", "3.9.0", "-lcrypto", ""),
        "libssl.pc": ("OpenSSL-libssl", "OpenBSD base LibreSSL SSL/TLS library", "3.9.0", "-lssl -lcrypto", "Requires.private: libcrypto"),
        "libtls.pc": ("LibreSSL-libtls", "OpenBSD base libtls library", "3.9.0", "-ltls -lssl -lcrypto", ""),
        "curses.pc": ("curses", "OpenBSD base wide-char curses library", "6.4", "-lcurses", ""),
        "ncurses.pc": ("ncurses", "OpenBSD base curses (ncurses compat)", "6.4", "-lcurses", ""),
        "ncursesw.pc": ("ncursesw", "OpenBSD base wide-char curses", "6.4", "-lcurses", ""),
        "tinfo.pc": ("tinfo", "OpenBSD base terminfo library", "6.4", "-lcurses", ""),
        "expat.pc": ("expat", "OpenBSD base expat XML parser library", "2.6.0", "-lexpat", ""),
        "libedit.pc": ("libedit", "OpenBSD base command line editor library", "3.1", "-ledit -lcurses", ""),
    }
    for fname, (name, desc, ver, libs, extra) in specs.items():
        target = pc_dir / fname
        content = (
            "prefix=/usr\n"
            "exec_prefix=${prefix}\n"
            "libdir=${exec_prefix}/lib\n"
            "includedir=${prefix}/include\n\n"
            f"Name: {name}\n"
            f"Description: {desc}\n"
            f"Version: {ver}\n"
            f"Libs: {libs}\n"
            "Cflags:\n"
            + (f"{extra}\n" if extra else "")
        )
        if not target.is_file() or target.read_text(encoding="utf-8") != content:
            target.write_text(content, encoding="utf-8")
    return pc_dir


def run_pkg_config(argv: List[str]) -> int:
    host_pc = shutil.which("pkg-config")
    if not host_pc:
        die("host pkg-config executable not found")
    ctx = ToolchainContext()
    base_pc_dir = ensure_base_pkgconfig_dir(ctx)
    search_dirs = [
        str(ctx.stage_dir / "usr/local/lib/pkgconfig"),
        str(ctx.stage_dir / "usr/local/share/pkgconfig"),
        str(base_pc_dir),
    ]
    env = dict(os.environ)
    env.pop("PKG_CONFIG_PATH", None)
    env["PKG_CONFIG_LIBDIR"] = ":".join(search_dirs)
    # Keep prefix=/usr/local paths un-prefixed or remapped cleanly by obsd-cc;
    # always prefer --static so static transitive Libs.private (-lonig, -lzstd, etc.) are included!
    cmd = [host_pc]
    if "--static" not in argv:
        cmd.append("--static")
    cmd.extend(argv)
    return subprocess.run(cmd, env=env).returncode


def run_strip(argv: List[str]) -> int:
    """No-op strip preserving WASM `linking` custom sections."""
    out_path: Optional[str] = None
    inputs: List[str] = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "-o" and i + 1 < len(argv):
            out_path = argv[i + 1]
            i += 2
            continue
        if a.startswith("-o") and len(a) > 2:
            out_path = a[2:]
            i += 1
            continue
        if a.startswith("-"):
            i += 1
            continue
        inputs.append(a)
        i += 1
    if out_path and len(inputs) == 1 and os.path.abspath(inputs[0]) != os.path.abspath(out_path):
        shutil.copy2(inputs[0], out_path)
    return 0


def run_install_wrapper(argv: List[str]) -> int:
    """Wrap `/usr/bin/install`, dropping `-s` / `--strip` so WASM relocatable binaries keep symbols."""
    real_install = "/usr/bin/install"
    cleaned: List[str] = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a in ("-s", "--strip"):
            i += 1
            continue
        if a.startswith("--strip-program"):
            if "=" not in a and i + 1 < len(argv):
                i += 2
            else:
                i += 1
            continue
        if a.startswith("-") and not a.startswith("--") and len(a) > 2 and "s" in a[1:]:
            # e.g. `-cs` -> `-c`, except when previous flag takes an argument (`-m`, `-o`, `-g`, `-S`, `-t`)
            if a[1] not in ("m", "o", "g", "S", "t", "D"):
                stripped_flag = "-" + a[1:].replace("s", "")
                if stripped_flag != "-":
                    cleaned.append(stripped_flag)
                i += 1
                continue
        cleaned.append(a)
        i += 1
    return subprocess.run([real_install, *cleaned]).returncode


def main() -> int:
    if len(sys.argv) < 2:
        die("usage: obsd_toolchain.py <tool> [args...]")
    tool = sys.argv[1]
    rest = sys.argv[2:]

    if tool == "cc":
        return run_cc_driver(rest, is_cxx=False)
    if tool == "cxx":
        return run_cc_driver(rest, is_cxx=True)
    if tool == "ar":
        ctx = ToolchainContext()
        return subprocess.run([str(ctx.emar), *rest]).returncode
    if tool == "ranlib":
        ctx = ToolchainContext()
        # OpenBSD ranlib(1) accepts `-t` (used by GNU libtool `--mode=install` on
        # `*-*-openbsd*`); filter `-t` for `llvm-ranlib`/`emranlib` compatibility.
        filtered = [a for a in rest if a != "-t"]
        if not filtered:
            return 0
        return subprocess.run([str(ctx.emranlib), *filtered]).returncode
    if tool == "nm":
        ctx = ToolchainContext()
        return subprocess.run([str(ctx.llvm_nm), *rest]).returncode
    if tool == "ld":
        ctx = ToolchainContext()
        cmd = [str(ctx.wasm_ld)]
        if "-m" not in rest:
            cmd.extend(["-m", "wasm64"])
        cmd.extend(rest)
        return subprocess.run(cmd).returncode
    if tool == "strip":
        return run_strip(rest)
    if tool == "pkg-config":
        return run_pkg_config(rest)
    if tool == "install":
        return run_install_wrapper(rest)

    die(f"unknown SDK tool mode: {tool}")


if __name__ == "__main__":
    raise SystemExit(main())
