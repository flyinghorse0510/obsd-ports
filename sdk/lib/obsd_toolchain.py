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
        self.openbsd_version = os.environ.get("OPENBSD_VERSION", "7.9").strip() or "7.9"
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
    if arg.endswith((".o", ".lo", ".a", ".so")):
        return True
    if ".so." in os.path.basename(arg):
        return True
    p = pathlib.Path(arg)
    if p.is_file():
        try:
            with p.open("rb") as fp:
                hdr = fp.read(8)
            if hdr == b"\x00asm\x01\x00\x00\x00" or hdr.startswith(b"!<arch>\n"):
                return True
        except OSError:
            pass
    return False


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
    if not preprocess_only:
        prefix_flags.append("-fsanitize-coverage=trace-pc,no-prune")

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
        cxx_inc = ctx.em_sysroot / "include/c++/v1"
        if cxx_inc.is_dir():
            suffix_flags.extend(["-isystem", str(cxx_inc)])

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


def resolve_library(name: str, lib_dirs: Sequence[str], stage_lib_dir: pathlib.Path) -> Tuple[Optional[str], bool]:
    """
    Resolve `-l<name>`:
      - Returns `(archive_path, True)` if a port static/relocatable library is found.
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

    if name in BASE_OPENBSD_LIBS:
        return None, True

    return None, False


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
                resolved_ar, ok = resolve_library(val, lib_dirs, ctx.stage_dir / "usr/local/lib")
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
        return subprocess.run([str(ctx.emranlib), *rest]).returncode
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
