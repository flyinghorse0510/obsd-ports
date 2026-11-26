#!/usr/bin/env python3
"""
obsd_toolchain.py -- Multi-PAL Guest Cross-Compilation Toolchain Driver for `obsd-ports`.

Dispatches by `(COMPAT_PAL, COMPAT_BACKEND, COMPAT_SDK)`:
  1. `EmscriptenToolchain` (`COMPAT_PAL=emscripten`, `COMPAT_BACKEND=emulate`):
     - Compiles C/C++ sources against `libobsdcompat`'s OpenBSD `<ver>` WASM64
       sysroot (`include-root-<ver>`) in LP64 WASM64 mode (`-m64 -pthread -O2
       -fno-common -sSUPPORT_LONGJMP=0 -fsanitize-coverage=trace-pc,no-prune
       -D__OpenBSD__=1`), remaps `/usr/local/{include,lib}` to the staged port
       sysroot, links relocatable WASM64 objects via `wasm-ld -m wasm64 -r`,
       wraps `WASM_INIT_FUNCS` static constructors per-exec, and verifies symbol
       closure against `libobsdc-wasm-<ver>.a`.
  2. `DarwinToolchain` (`COMPAT_PAL=darwin`, `COMPAT_BACKEND=translate|emulate`,
     `COMPAT_SDK=macosx|iphonesimulator|iphoneos`):
     - Preserves `-ffixed-x18`, `-nostdinc`, `-fno-common`, `-femulated-tls`
       (OpenBSD `pthread_key_create`-backed `__emutls_get_address`, zero Mach-O
       `__thread_*` sections), and strict host header/dylib isolation (zero
       `/opt/homebrew`, `/usr/local`, or host `libc++.1.dylib` leaks).
     - Builds & caches a hermetic Darwin arm64 guest C++23 runtime (`libc++.a`,
       `libc++abi.a`, `libunwind.a`, `libobsd_emutls.a`) from `libobsdcompat`'s
       checked-out LLVM sources against the lane's OpenBSD guest include root,
       with `x18`-clean `libunwind` register save/restore, dyld-free Mach-O
       header unwind table lookup, and zero `__DATA,__mod_init_func` sections.
     - `translate` (`macosx`): loads compile/link flags from `libobsdcompat`'s
       `tool-probe-vector.tsv`, retypes & wraps any C/C++ static constructors via
       `retype_guest_initializers.py` so constructors run AFTER `startup.o`
       initializes the guest TIB/VFS/heap, links standalone arm64 Mach-O binaries
       against `libobsdc-<ver>.a`, verifies `otool -L`, and ad-hoc codesigns.
     - `emulate` (`iphonesimulator` | `iphoneos`): loads `CONSUMER_CFLAGS` and
       `OPENBSD_EMULATE_TARGET_FLAGS` from the `libobsdcompat` `emulate` lane,
       links relocatable Mach-O partials (`-nostdlib -Wl,-r,-S`), retypes & wraps
       static constructors so zero `__DATA,__mod_init_func` sections survive, and
       verifies undefined symbols against `libobsdc-<ver>.a` + the `emulate`
       import allow-list.
"""
from __future__ import annotations

import concurrent.futures
import fcntl
import hashlib
import json
import os
import pathlib
import re
import struct
import shlex
import shutil
import subprocess
import sys
import tempfile
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

SDK_ROOT = pathlib.Path(__file__).resolve().parents[1]
REPO_ROOT = SDK_ROOT.parent
sys.path.insert(0, str(REPO_ROOT / "tools/config"))
import obsd_versions  # noqa: E402  (release axis from config/versions/index.tsv)
import obsd_env  # noqa: E402  (EMSDK_PYTHON pinning)

# Base OpenBSD libraries provided directly inside `libobsdc-wasm-<ver>.a` / `libobsdc-<ver>.a`.
# Deliberately excludes absent libraries (iconv, intl, panel, form, menu, dl, etc.)
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

# Staged static port libraries in `stage/usr/local/lib/lib<name>.a` that are kept
# undefined in individual WASM64 port applet `.o` closures and linked once into
# `guest-partial.o`'s shared `B_lib` slice via `libobsdports-shared-wasm-<ver>.a`.
SHARED_PORT_LIBS: Set[str] = {
    "FOX-1.6",
    "fltk",
    "fltk_forms",
    "fltk_gl",
    "fltk_images",
    "jpeg",
    "webp",
    "webpdemux",
    "webpmux",
    "sharpyuv",
    "tiff",
    "tiffxx",
    "gif",
    "brotlicommon",
    "brotlidec",
    "brotlienc",
    "archive",
    "xml2",
    "zstd",
    "lzma",
    "bz2",
    "lz4",
    "iconv",
}

WASM_BOUNDARY_IMPORTS: Set[str] = {
    "__obsd_wasm_gate",
    "__obsd_wasm_setjmp",
    "__obsd_wasm_longjmp",
    "__obsd_guest_tcb",
    "__obsd_guest_tcb_set",
    "__emutls_get_address",
    "__sanitizer_cov_trace_pc",
    "__sanitizer_cov_trace_pc_guard",
    "__stack_pointer",
    "__indirect_function_table",
    "__linear_memory",
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

DARWIN_COMPILER_RT_INT128_SYMS: Set[str] = {
    "___divti3",
    "___udivti3",
    "___modti3",
    "___umodti3",
    "___multi3",
    "___ashlti3",
    "___lshrti3",
    "___ashrti3",
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

FORBIDDEN_HOST_PREFIXES = (
    "/opt/homebrew",
    "/usr/local/opt",
    "/usr/local/Cellar",
    "/opt/local",
    "/sw",
)

DARWIN_SANITIZED_ENV_KEYS = (
    "CPATH",
    "C_INCLUDE_PATH",
    "CPLUS_INCLUDE_PATH",
    "OBJC_INCLUDE_PATH",
    "LIBRARY_PATH",
    "COMPILER_PATH",
    "GCC_EXEC_PREFIX",
    "SDKROOT",
    "MACOSX_DEPLOYMENT_TARGET",
    "IPHONEOS_DEPLOYMENT_TARGET",
    "CCC_ADD_ARGS",
    "CCC_OVERRIDE_OPTIONS",
    "CLANG_CONFIG_FILE_SYSTEM_DIR",
    "CLANG_CONFIG_FILE_USER_DIR",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "DYLD_FRAMEWORK_PATH",
    "DYLD_FALLBACK_LIBRARY_PATH",
    "DYLD_FALLBACK_FRAMEWORK_PATH",
)

DARWIN_ENV_UNDEFS = (
    "-U__ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__",
    "-U__ENVIRONMENT_IPHONE_OS_VERSION_MIN_REQUIRED__",
    "-U__ENVIRONMENT_TV_OS_VERSION_MIN_REQUIRED__",
    "-U__ENVIRONMENT_WATCH_OS_VERSION_MIN_REQUIRED__",
    "-U__ENVIRONMENT_OS_VERSION_MIN_REQUIRED__",
)

MACHO_MAGICS = (
    b"\xcf\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf",
    b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xce",
    b"\xca\xfe\xba\xbe",
    b"\xbe\xba\xfe\xca",
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


def default_sdk_for(pal: str, backend: str) -> str:
    if pal != "darwin":
        return ""
    env_sdk = os.environ.get("COMPAT_SDK", "").strip()
    if env_sdk:
        return env_sdk
    return "macosx" if backend == "translate" else "iphonesimulator"


def is_source_file(arg: str) -> bool:
    if arg.startswith("-") or arg == "-":
        return False
    _, ext = os.path.splitext(arg)
    return ext in SOURCE_EXTS


def is_asm_source(arg: str) -> bool:
    if arg.startswith("-") or arg == "-":
        return False
    _, ext = os.path.splitext(arg)
    return ext in (".s", ".S")


def is_object_or_archive(arg: str) -> bool:
    if arg.startswith("-"):
        return False
    if arg.endswith((".o", ".lo", ".la", ".a", ".rlib", ".so")):
        return True
    if ".so." in os.path.basename(arg):
        return True
    p = pathlib.Path(arg)
    if p.is_file():
        try:
            with p.open("rb") as fp:
                hdr = fp.read(8)
            if (
                hdr == b"\x00asm\x01\x00\x00\x00"
                or hdr.startswith((b"!<arch>\n", b"!<thin>\n"))
                or (len(hdr) >= 4 and hdr[:4] in MACHO_MAGICS)
            ):
                return True
        except OSError:
            pass
    return False


def resolve_lo_file(path_str: str) -> str:
    """Resolve GNU libtool `.lo` / `.la` wrapper text files to the real `.o` / `.a` path."""
    if path_str.endswith(".la"):
        p = pathlib.Path(path_str)
        if p.is_file():
            try:
                for ln in p.read_text(encoding="utf-8", errors="replace").splitlines():
                    if ln.startswith("old_library="):
                        old_lib = ln.split("=", 1)[1].strip().strip("'\"")
                        if old_lib and old_lib != "none":
                            for cand in (p.parent / ".libs" / old_lib, p.parent / old_lib):
                                if cand.is_file():
                                    return str(cand)
            except OSError:
                pass
        return path_str
    if not path_str.endswith(".lo"):
        return path_str
    p = pathlib.Path(path_str)
    if not p.is_file():
        return path_str
    try:
        head = p.read_bytes()[:64]
        if head.startswith(b"\x00asm") or (len(head) >= 4 and head[:4] in MACHO_MAGICS):
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

DARWIN_EMUTLS_C = """\
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

struct __emutls_control {
\tsize_t size;
\tsize_t align;
\tunion {
\t\tuintptr_t index;
\t\tvoid *address;
\t} object;
\tvoid *value;
};

struct __obsd_emutls_slot {
\tconst void *ctrl;
\tpthread_key_t key;
\tstruct __obsd_emutls_slot *next;
};

static pthread_mutex_t __obsd_emutls_mtx = PTHREAD_MUTEX_INITIALIZER;
static struct __obsd_emutls_slot *__obsd_emutls_buckets[64];

static void
__obsd_emutls_dtor(void *ptr)
{
\tfree(ptr);
}

void *
__emutls_get_address(void *control_raw)
{
\tconst struct __emutls_control *ctrl = (const struct __emutls_control *)control_raw;
\tuintptr_t h = (((uintptr_t)control_raw >> 4) ^ ((uintptr_t)control_raw >> 12)) & 63U;
\tstruct __obsd_emutls_slot *slot = __atomic_load_n(&__obsd_emutls_buckets[h], __ATOMIC_ACQUIRE);
\tfor (; slot != NULL; slot = slot->next) {
\t\tif (slot->ctrl == control_raw)
\t\t\tbreak;
\t}

\tif (slot == NULL) {
\t\tpthread_mutex_lock(&__obsd_emutls_mtx);
\t\tslot = __obsd_emutls_buckets[h];
\t\tfor (; slot != NULL; slot = slot->next) {
\t\t\tif (slot->ctrl == control_raw)
\t\t\t\tbreak;
\t\t}
\t\tif (slot == NULL) {
\t\t\tslot = (struct __obsd_emutls_slot *)malloc(sizeof(*slot));
\t\t\tif (slot == NULL)
\t\t\t\tabort();
\t\t\tif (pthread_key_create(&slot->key, __obsd_emutls_dtor) != 0)
\t\t\t\tabort();
\t\t\tslot->ctrl = control_raw;
\t\t\tslot->next = __obsd_emutls_buckets[h];
\t\t\t__atomic_store_n(&__obsd_emutls_buckets[h], slot, __ATOMIC_RELEASE);
\t\t}
\t\tpthread_mutex_unlock(&__obsd_emutls_mtx);
\t}

\tvoid *mem = pthread_getspecific(slot->key);
\tif (mem == NULL) {
\t\tsize_t align = ctrl->align < sizeof(void *) ? sizeof(void *) : ctrl->align;
\t\tsize_t sz = ctrl->size == 0 ? 1 : ctrl->size;
\t\tif (posix_memalign(&mem, align, sz) != 0 || mem == NULL)
\t\t\tabort();
\t\tif (ctrl->value != NULL)
\t\t\tmemcpy(mem, ctrl->value, ctrl->size);
\t\telse
\t\t\tmemset(mem, 0, sz);
\t\tif (pthread_setspecific(slot->key, mem) != 0)
\t\t\tabort();
\t}
\treturn mem;
}
"""

DARWIN_UNWIND_FIND_REPL = """\
#elif defined(LIBOBSDCOMPAT_OBJECT_FORMAT_MACHO)
  struct obsd_mh64 {
    uint32_t magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, reserved;
  };
  struct obsd_lc {
    uint32_t cmd, cmdsize;
  };
  struct obsd_seg64 {
    uint32_t cmd, cmdsize;
    char segname[16];
    uint64_t vmaddr, vmsize, fileoff, filesize;
    uint32_t maxprot, initprot, nsects, flags;
  };
  struct obsd_sect64 {
    char sectname[16];
    char segname[16];
    uint64_t addr, size;
    uint32_t offset, align, reloff, nreloc, flags, r1, r2, r3;
  };
  uintptr_t page = (uintptr_t)targetAddr & ~(uintptr_t)0xfffULL;
  for (unsigned step = 0; step < 131072U && page >= 0x1000ULL; ++step, page -= 0x1000ULL) {
    const struct obsd_mh64 *mh = (const struct obsd_mh64 *)page;
    if (mh->magic != 0xfeedfacfU || mh->cputype != 0x0100000cU)
      continue;
    if (mh->filetype != 2U && mh->filetype != 6U)
      continue;
    const char *cur = (const char *)(mh + 1);
    for (uint32_t i = 0; i < mh->ncmds; ++i) {
      const struct obsd_lc *lc = (const struct obsd_lc *)cur;
      if (lc->cmdsize < sizeof(struct obsd_lc))
        break;
      if (lc->cmd == 0x19U && lc->cmdsize >= sizeof(struct obsd_seg64)) {
        const struct obsd_seg64 *seg = (const struct obsd_seg64 *)cur;
        if (__builtin_strncmp(seg->segname, "__TEXT", 16) == 0) {
          uintptr_t text_start = page;
          uintptr_t text_end = page + (uintptr_t)seg->vmsize;
          if (targetAddr < text_start || targetAddr >= text_end)
            return false;
          intptr_t slide = (intptr_t)page - (intptr_t)seg->vmaddr;
          info.dso_base = page;
          const struct obsd_sect64 *secs = (const struct obsd_sect64 *)(seg + 1);
          for (uint32_t j = 0; j < seg->nsects; ++j) {
            if (__builtin_strncmp(secs[j].sectname, "__unwind_info", 16) == 0 && secs[j].size != 0) {
              info.compact_unwind_section = (uintptr_t)((intptr_t)secs[j].addr + slide);
              info.compact_unwind_section_length = (size_t)secs[j].size;
            } else if (__builtin_strncmp(secs[j].sectname, "__eh_frame", 16) == 0 && secs[j].size != 0) {
              info.dwarf_section = (uintptr_t)((intptr_t)secs[j].addr + slide);
              info.dwarf_section_length = (size_t)secs[j].size;
            }
          }
          return (info.compact_unwind_section_length != 0 || info.dwarf_section_length != 0);
        }
      }
      cur += lc->cmdsize;
    }
    break;
  }
  return false;
"""


DARWIN_LIBM_MACHO_SHIM_H = """\
#include <sys/cdefs.h>
#define OBSD_MSTR_(x) #x
#define OBSD_MXSTR(x) OBSD_MSTR_(x)
#undef __strong_alias
#define __strong_alias(alias, sym) __asm__(".globl _" OBSD_MXSTR(alias) "\\n\\t.set _" OBSD_MXSTR(alias) ", _" OBSD_MXSTR(sym))
#undef __weak_alias
#define __weak_alias(alias, sym) __asm__(".globl _" OBSD_MXSTR(alias) "\\n\\t.set _" OBSD_MXSTR(alias) ", _" OBSD_MXSTR(sym))
#undef PROTO_DEPRECATED
#define PROTO_DEPRECATED(x) typeof(x) _libm_##x, x
#undef DEF_STD
#define DEF_STD(x) __asm__(".globl _" OBSD_MXSTR(x) "\\n\\t.set _" OBSD_MXSTR(x) ", _libm_" OBSD_MXSTR(x))
#undef DEF_NONSTD
#define DEF_NONSTD(x) DEF_STD(x)
#undef MAKE_UNUSED_CLONE
#define MAKE_UNUSED_CLONE(dst, src) __asm__(".globl _libm_" OBSD_MXSTR(dst) "\\n\\t.set _libm_" OBSD_MXSTR(dst) ", _libm_" OBSD_MXSTR(src))
#undef LDBL_UNUSED_CLONE
#define LDBL_UNUSED_CLONE(x) __asm__(".globl _" OBSD_MXSTR(x) "l\\n\\t.set _" OBSD_MXSTR(x) "l, _libm_" OBSD_MXSTR(x))
#undef LDBL_NONSTD_UNUSED_CLONE
#define LDBL_NONSTD_UNUSED_CLONE(x) LDBL_UNUSED_CLONE(x)
#undef LDBL_CLONE
#define LDBL_UNUSED_CLONE_BASE_(x) __asm__(".globl _" OBSD_MXSTR(x) "l\\n\\t.set _" OBSD_MXSTR(x) "l, _libm_" OBSD_MXSTR(x))
#define LDBL_CLONE(x) LDBL_UNUSED_CLONE_BASE_(x); __asm__(".globl _libm_" OBSD_MXSTR(x) "l\\n\\t.set _libm_" OBSD_MXSTR(x) "l, _libm_" OBSD_MXSTR(x))
#undef LDBL_NONSTD_CLONE
#define LDBL_NONSTD_CLONE(x) LDBL_CLONE(x)
"""


def ensure_cxx_config_dir(cache_dir: pathlib.Path, openbsd_version: str) -> pathlib.Path:
    cfg_dir = cache_dir / f"cxx-cfg-{openbsd_version}"
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


# ============================================================================
# EmscriptenToolchain (`COMPAT_PAL=emscripten`)
# ============================================================================


def resolve_active_x11_build_dir(openbsd_version: str, backend: str, pal: str) -> Optional[pathlib.Path]:
    if backend != "emulate" or pal != "emscripten":
        return None
    raw = os.environ.get("OBSD_X11_BUILD_DIR", "").strip() or os.environ.get("XENOCARA_BUILD_DIR", "").strip()
    if raw.lower() in ("none", "off", "0", "false"):
        return None
    if raw:
        p = pathlib.Path(raw).resolve()
        if not (p / "libobsdx11-libs.json").is_file():
            die(f"OBSD_X11_BUILD_DIR={p} is missing libobsdx11-libs.json")
        return p
    default_p = pathlib.Path("/var/tmp/sonvori-xenocara/build") / openbsd_version
    if (default_p / "libobsdx11-libs.json").is_file():
        return default_p.resolve()
    return None


class EmscriptenToolchain:
    def __init__(self) -> None:
        self.openbsd_version = obsd_versions.env_or_default_version()
        self.backend = os.environ.get("COMPAT_BACKEND", "emulate").strip() or "emulate"
        self.pal = os.environ.get("COMPAT_PAL", "emscripten").strip() or "emscripten"
        self.obsd_root = resolve_libobsdcompat_root()
        obsd_env.ensure_emsdk_python(self.obsd_root)

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

        self.x11_build_dir = resolve_active_x11_build_dir(self.openbsd_version, self.backend, self.pal)
        self.x11_sdk_usr = (self.x11_build_dir / "sdk/usr/X11R6") if self.x11_build_dir is not None else None
        self.x11_archive = (
            (self.x11_build_dir / f"libobsdx11-wasm-{self.openbsd_version}.a")
            if self.x11_build_dir is not None
            else None
        )
        self.shared_x11_libs: Set[str] = (
            set(json.loads((self.x11_build_dir / "libobsdx11-libs.json").read_text(encoding="utf-8")))
            if self.x11_build_dir is not None
            else set()
        )
        raw_sp = os.environ.get("OBSD_SHARED_PORT_LIBS", "1").strip().lower()
        self.shared_port_libs: Set[str] = (
            set(SHARED_PORT_LIBS)
            if (self.backend == "emulate" and self.pal == "emscripten" and raw_sp not in ("0", "off", "false", "none"))
            else set()
        )
        self._archive_def_cache: Dict[str, Set[str]] = {}

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
        if self.x11_archive is not None:
            if not self.x11_archive.is_file():
                die(f"missing Xenocara X11 WASM archive: {self.x11_archive}")
            xst = self.x11_archive.stat()
            sig += f"|x11:{self.x11_archive}:{xst.st_size}:{xst.st_mtime_ns}"
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

        if self.x11_archive is not None:
            x11_out = subprocess.check_output(
                [str(self.llvm_nm), "--defined-only", "-g", str(self.x11_archive)],
                text=True,
                stderr=subprocess.DEVNULL,
            )
            for ln in x11_out.splitlines():
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
        if self.x11_sdk_usr is not None and (norm == "/usr/X11R6/include" or norm.startswith("/usr/X11R6/include/")):
            sub = norm[len("/usr/X11R6/include") :].lstrip("/")
            base = self.x11_sdk_usr / "include"
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
        if self.x11_sdk_usr is not None and (norm == "/usr/X11R6/lib" or norm.startswith("/usr/X11R6/lib/")):
            sub = norm[len("/usr/X11R6/lib") :].lstrip("/")
            base = self.x11_sdk_usr / "lib"
            return str(base / sub) if sub else str(base)
        return path_str

    def is_shared_x11_archive_path(self, path_str: str) -> bool:
        if not self.shared_x11_libs or not path_str.endswith(".a"):
            return False
        bn = os.path.basename(path_str)
        if not (bn.startswith("lib") and len(bn) > 5):
            return False
        stem = bn[3:-2]
        if stem not in self.shared_x11_libs:
            return False
        norm = os.path.normpath(path_str)
        if norm.startswith("/usr/X11R6/lib/"):
            return True
        try:
            rp = pathlib.Path(norm).resolve()
        except OSError:
            return False
        if self.x11_build_dir is not None and rp.is_relative_to(self.x11_build_dir):
            return True
        stage_lib = (self.stage_dir / "usr/local/lib").resolve()
        if rp.is_relative_to(stage_lib):
            return True
        return False

    def shared_port_archive_stem(self, path_str: str) -> Optional[str]:
        if not self.shared_port_libs or not path_str.endswith(".a"):
            return None
        bn = os.path.basename(path_str)
        if not (bn.startswith("lib") and len(bn) > 5):
            return None
        stem = bn[3:-2]
        matched: Optional[str] = None
        if stem in self.shared_port_libs:
            matched = stem
        elif stem.endswith("-static") and stem[:-7] in self.shared_port_libs:
            matched = stem[:-7]
        if matched is None:
            return None
        p = pathlib.Path(path_str)
        return matched if p.is_file() else None

    def archive_defined_symbols(self, ar_path: pathlib.Path) -> Set[str]:
        rp = ar_path.resolve()
        st = rp.stat()
        sig = f"{rp}:{st.st_size}:{st.st_mtime_ns}"
        if sig in self._archive_def_cache:
            return self._archive_def_cache[sig]
        key = hashlib.sha1(sig.encode("utf-8")).hexdigest()[:16]
        cache_file = self.cache_dir / f"ar-defs-{self.openbsd_version}-{key}.json"
        if cache_file.is_file():
            syms = set(json.loads(cache_file.read_text(encoding="utf-8")))
            self._archive_def_cache[sig] = syms
            return syms
        out = subprocess.check_output(
            [str(self.llvm_nm), "--defined-only", "-g", str(rp)],
            text=True,
            stderr=subprocess.DEVNULL,
        )
        syms = set()
        for ln in out.splitlines():
            ps = ln.split()
            if len(ps) >= 3 and not ln.endswith(":"):
                syms.add(ps[-1])
        tmp = cache_file.with_suffix(f".{os.getpid()}.json.tmp")
        tmp.write_text(json.dumps(sorted(syms)), encoding="utf-8")
        tmp.replace(cache_file)
        self._archive_def_cache[sig] = syms
        return syms


# Backwards-compatibility alias
ToolchainContext = EmscriptenToolchain


def ensure_cxx_runtime(ctx: EmscriptenToolchain) -> Tuple[pathlib.Path, pathlib.Path]:
    """
    Build & cache WASM64 `-pthread` `libc++.a` + `libc++abi.a` (with native Wasm EH
    `-fwasm-exceptions` + `-sSUPPORT_LONGJMP=0`) compiled directly against the
    OpenBSD `<ver>` sysroot (`include-root-<ver>`) so `FILE`/`errno`/`pthread_mutex_t`/
    `stat`/`locale` layouts match `libobsdc-wasm-<ver>.a` 100%.
    """
    if not ctx.include_root.is_dir():
        die(f"missing OpenBSD {ctx.openbsd_version} include root: {ctx.include_root}")

    sig_src = (
        f"cxx-rt-v5:{ctx.openbsd_version}:{ctx.emcxx.stat().st_mtime_ns}:"
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

        cfg_dir = ensure_cxx_config_dir(ctx.cache_dir, ctx.openbsd_version)
        sp = ctx.obsd_root / "src/personalities/openbsd/runtime/backends/translate/boundary"
        res_inc = ctx.clang_resource_include()

        common = [
            "-m64",
            "-pthread",
            "-O2",
            "-fno-common",
            "-fno-builtin",
            "-femulated-tls",
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

            emulate_tools = ctx.obsd_root / "tools/build/personalities/openbsd/backends/emulate"
            if str(emulate_tools) not in sys.path:
                sys.path.insert(0, str(emulate_tools))
            import wasm_object_tool as wot  # type: ignore

            def _compile_one(item: Tuple[str, List[str]]) -> Tuple[str, int, str]:
                lbl, cmd_vec = item
                p = subprocess.run(cmd_vec, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                if p.returncode == 0:
                    wot.lower_emutls_file(pathlib.Path(cmd_vec[-1]))
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


def build_guest_compile_flags(
    ctx: EmscriptenToolchain, is_cxx: bool, preprocess_only: bool
) -> Tuple[List[str], List[str]]:
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
        "-femulated-tls",
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
        cxx_cfg = ensure_cxx_config_dir(ctx.cache_dir, ctx.openbsd_version)
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

    if ctx.x11_sdk_usr is not None:
        x11_inc = ctx.x11_sdk_usr / "include"
        if x11_inc.is_dir():
            suffix_flags.extend(["-isystem", str(x11_inc)])

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


def resolve_library(
    ctx: EmscriptenToolchain,
    name: str,
    lib_dirs: Sequence[str],
    stage_lib_dir: pathlib.Path,
) -> Tuple[Optional[str], bool]:
    if name in ctx.shared_x11_libs:
        return None, True

    search_dirs = list(lib_dirs)
    if stage_lib_dir.is_dir():
        s_str = str(stage_lib_dir)
        if s_str not in search_dirs:
            search_dirs.append(s_str)

    if name.startswith(":"):
        exact = name[1:]
        if exact.startswith("lib") and exact.endswith(".a") and exact[3:-2] in ctx.shared_x11_libs:
            return None, True
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


def wrap_wasm_init_funcs(ctx: EmscriptenToolchain, obj_path: pathlib.Path, tmp_dir: pathlib.Path) -> int:
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
            "-femulated-tls",
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


def verify_undefined_symbols(
    ctx: EmscriptenToolchain,
    obj_path: pathlib.Path,
    extra_archives: Sequence[pathlib.Path] = (),
) -> Optional[List[str]]:
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

    allowed = set(ctx.allowed_undefined_symbols())
    for ar_p in extra_archives:
        if ar_p.is_file():
            allowed |= ctx.archive_defined_symbols(ar_p)
    missing = sorted(s for s in (undefs - defined_self) if s not in allowed)
    return missing or None


def run_emscripten_cc_driver(argv: List[str], is_cxx: bool) -> int:
    ctx = EmscriptenToolchain()
    compiler_bin = str(ctx.emcxx if is_cxx else ctx.emcc)

    if not argv:
        return subprocess.run([compiler_bin]).returncode

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
        return subprocess.run([compiler_bin, *argv]).returncode

    prefix_cf, suffix_cf = build_guest_compile_flags(ctx, is_cxx=is_cxx, preprocess_only=mode_preprocess)

    compile_user_args: List[str] = []
    lib_dirs: List[str] = []
    link_items: List[Tuple[str, str]] = []
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
        if (a == "-" and cur_lang is not None) or (
            cur_lang in ("c", "c++", "assembler", "assembler-with-cpp") and not a.startswith("-")
        ):
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
            resolved_obj = resolve_lo_file(a)
            link_items.append(("obj", resolved_obj))
            if a.endswith(".la") and pathlib.Path(a).is_file():
                try:
                    for ln in pathlib.Path(a).read_text(encoding="utf-8", errors="replace").splitlines():
                        if ln.startswith("dependency_libs="):
                            dep_raw = ln.split("=", 1)[1].strip().strip("'\"")
                            for dtok in shlex.split(dep_raw):
                                if dtok.startswith("-L") and len(dtok) > 2:
                                    rl = ctx.remap_lib_dir(dtok[2:])
                                    if rl and rl not in lib_dirs:
                                        lib_dirs.append(rl)
                                elif dtok.startswith("-l") and len(dtok) > 2:
                                    link_items.append(("la_dep_lib", dtok[2:]))
                                elif dtok.endswith((".la", ".a")):
                                    ro = resolve_lo_file(dtok)
                                    if pathlib.Path(ro).is_file():
                                        link_items.append(("la_dep_obj", ro))
                except OSError:
                    pass
            i += 1
            continue
        compile_user_args.append(a)
        i += 1

    emulate_tools = ctx.obsd_root / "tools/build/personalities/openbsd/backends/emulate"
    if str(emulate_tools) not in sys.path:
        sys.path.insert(0, str(emulate_tools))
    import wasm_object_tool as wot  # type: ignore

    if mode_preprocess or mode_compile_only:
        cmd = [compiler_bin, *prefix_cf, *compile_user_args, *dep_args, *suffix_cf]
        is_asm_out = "-S" in compile_user_args or "-S" in argv
        if mode_compile_only and "-c" not in compile_user_args and "-S" not in compile_user_args:
            cmd.append("-S" if is_asm_out else "-c")
        if output_path is not None:
            cmd.extend(["-o", output_path])
        rc = subprocess.run(cmd).returncode
        if rc == 0 and mode_compile_only and not mode_preprocess and not is_asm_out:
            if output_path is not None:
                cand_o = pathlib.Path(output_path)
            else:
                srcs = [v for k, v in link_items if k == "src" and v != "-"]
                cand_o = pathlib.Path(os.path.splitext(os.path.basename(srcs[0]))[0] + ".o") if len(srcs) == 1 else None
            if cand_o is not None and cand_o.is_file():
                wot.lower_emutls_file(cand_o)
        return rc

    out_file = pathlib.Path(output_path or "a.out")
    compile_only_flags = [x for x in compile_user_args if not is_source_file(x) and x != "-"]

    with tempfile.TemporaryDirectory(prefix="obsd-cc-") as tmpdir:
        tmp_p = pathlib.Path(tmpdir)
        ld_inputs: List[str] = []
        ld_extra_flags: List[str] = []
        deferred_shared_archives: List[pathlib.Path] = []
        src_idx = 0

        for kind, val in link_items:
            if kind == "src":
                tmp_obj = tmp_p / f"tu_{src_idx:03d}.o"
                src_idx += 1
                c_cmd = [
                    compiler_bin,
                    "-c",
                    *prefix_cf,
                    *compile_only_flags,
                    *(dep_args if len([k for k, _ in link_items if k == "src"]) == 1 else []),
                    val,
                    *suffix_cf,
                    "-o",
                    str(tmp_obj),
                ]
                rc = subprocess.run(c_cmd).returncode
                if rc != 0:
                    return rc
                if tmp_obj.is_file():
                    wot.lower_emutls_file(tmp_obj)
                ld_inputs.append(str(tmp_obj))
            elif kind == "obj":
                if ctx.is_shared_x11_archive_path(val):
                    continue
                if not is_shared and ctx.shared_port_archive_stem(val) is not None:
                    rp = pathlib.Path(val).resolve()
                    if rp not in deferred_shared_archives:
                        deferred_shared_archives.append(rp)
                    continue
                ld_inputs.append(val)
            elif kind == "la_dep_obj":
                if ctx.is_shared_x11_archive_path(val):
                    continue
                if not is_shared and ctx.shared_port_archive_stem(val) is not None:
                    rp = pathlib.Path(val).resolve()
                    if rp not in deferred_shared_archives:
                        deferred_shared_archives.append(rp)
            elif kind == "la_dep_lib":
                resolved_ar, ok = resolve_library(ctx, val, lib_dirs, ctx.stage_dir / "usr/local/lib")
                if ok and resolved_ar is not None and not is_shared and ctx.shared_port_archive_stem(resolved_ar) is not None:
                    rp = pathlib.Path(resolved_ar).resolve()
                    if rp not in deferred_shared_archives:
                        deferred_shared_archives.append(rp)
            elif kind == "lib":
                resolved_ar, ok = resolve_library(ctx, val, lib_dirs, ctx.stage_dir / "usr/local/lib")
                if not ok:
                    sys.stderr.write(f"obsd-ld: error: unable to find library -l{val}\n")
                    return 1
                if resolved_ar is not None:
                    if not is_shared and ctx.shared_port_archive_stem(resolved_ar) is not None:
                        rp = pathlib.Path(resolved_ar).resolve()
                        if rp not in deferred_shared_archives:
                            deferred_shared_archives.append(rp)
                    elif resolved_ar not in ld_inputs:
                        ld_inputs.append(resolved_ar)
            elif kind == "ldflag":
                ld_extra_flags.append(val)

        if not ld_inputs:
            sys.stderr.write("obsd-ld: error: no input files\n")
            return 1

        no_default_cxx = any(f in argv for f in ("-nostdlib", "-nostdlib++", "-nodefaultlibs"))
        cxx_shared_in_x11 = "c++" in ctx.shared_x11_libs
        if is_cxx and not no_default_cxx and not cxx_shared_in_x11:
            libcxx_a, libcxxabi_a = ensure_cxx_runtime(ctx)
            for ar_p in (str(libcxx_a), str(libcxxabi_a)):
                if ar_p not in ld_inputs:
                    ld_inputs.append(ar_p)
        elif not cxx_shared_in_x11 and any(os.path.basename(x).startswith(("libc++.", "libc++-")) for x in ld_inputs):
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
            missing_syms = verify_undefined_symbols(ctx, tmp_linked, deferred_shared_archives)
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


# ============================================================================
# DarwinToolchain (`COMPAT_PAL=darwin`, `translate` & `emulate`)
# ============================================================================


class DarwinToolchain:
    def __init__(
        self,
        openbsd_version: Optional[str] = None,
        backend: Optional[str] = None,
        sdk: Optional[str] = None,
        obsd_root: Optional[pathlib.Path] = None,
        stage_dir: Optional[pathlib.Path] = None,
    ) -> None:
        self.openbsd_version = openbsd_version or obsd_versions.env_or_default_version()
        self.backend = backend or (os.environ.get("COMPAT_BACKEND", "translate").strip() or "translate")
        self.pal = "darwin"
        self.sdk = sdk or default_sdk_for("darwin", self.backend)
        if self.backend == "translate" and self.sdk != "macosx":
            die(f"Darwin translate supports only COMPAT_SDK=macosx (got '{self.sdk}')")
        if self.backend == "emulate" and self.sdk not in ("iphonesimulator", "iphoneos"):
            die(f"Darwin emulate supports COMPAT_SDK=iphonesimulator|iphoneos (got '{self.sdk}')")

        self.obsd_root = (obsd_root or resolve_libobsdcompat_root()).resolve()
        lane_leaf = f"darwin-{self.sdk}"
        stage_env = os.environ.get("OBSD_STAGE_DIR", "").strip()
        if stage_dir is not None:
            self.stage_dir = stage_dir.resolve()
        elif stage_env:
            self.stage_dir = pathlib.Path(stage_env).resolve()
        else:
            self.stage_dir = (
                REPO_ROOT / "build/openbsd" / self.openbsd_version / self.backend / lane_leaf / "stage"
            ).resolve()

        self.cache_dir = REPO_ROOT / ".cache/sdk"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.em_dir = self.obsd_root / "deps/emsdk/upstream/emscripten"

        self.cc_cmd = ["/usr/bin/xcrun", "--sdk", self.sdk, "clang", "--no-default-config"]
        self.cxx_cmd = ["/usr/bin/xcrun", "--sdk", self.sdk, "clang++", "--no-default-config"]
        self.ar_cmd = ["/usr/bin/xcrun", "--sdk", self.sdk, "ar"]
        self.ranlib_cmd = ["/usr/bin/xcrun", "--sdk", self.sdk, "ranlib"]
        self.nm_cmd = ["/usr/bin/xcrun", "--sdk", self.sdk, "nm"]
        self.ld_cmd = ["/usr/bin/xcrun", "--sdk", self.sdk, "ld"]

        if self.backend == "emulate":
            bank_dir = self.obsd_root / "tools/build/llvm-guest-bank"
            bank_sh = bank_dir / "compile_guest_banked_darwin.sh"
            if not bank_sh.is_file():
                die(f"missing multi-core guest bank compiler wrapper: {bank_sh}")
            bh = hashlib.sha256()
            for fn in ("compile_guest_banked_darwin.sh", "ObsdGuestBankPass.cpp", "obsd_norm_apple_ir.cpp"):
                fp = bank_dir / fn
                if fp.is_file():
                    bh.update(fn.encode("utf-8") + b":" + fp.read_bytes())
            self.guest_bank_digest = bh.hexdigest()[:16]
            self.cc_compile_cmd = ["/bin/bash", str(bank_sh), "--", *self.cc_cmd]
            self.cxx_compile_cmd = ["/bin/bash", str(bank_sh), "--", *self.cxx_cmd]
        else:
            self.guest_bank_digest = "unbanked"
            self.cc_compile_cmd = list(self.cc_cmd)
            self.cxx_compile_cmd = list(self.cxx_cmd)

        self.translate_info: Dict[str, Any] = {}
        self.emulate_info: Dict[str, str] = {}
        if self.backend == "translate":
            self.translate_info = self._load_translate_vector()
            self.include_root = pathlib.Path(self.translate_info["include_root"])
            self.base_archive = pathlib.Path(self.translate_info["base_archive"])
        else:
            self.emulate_info = self._load_emulate_lane()
            self.include_root = pathlib.Path(self.emulate_info["include_root"])
            self.base_archive = pathlib.Path(self.emulate_info["guest_archive"])

    def sanitized_env(self) -> Dict[str, str]:
        env = dict(os.environ)
        for k in DARWIN_SANITIZED_ENV_KEYS:
            env.pop(k, None)
        env["ZERO_AR_DATE"] = "1"
        return env

    def find_llvm_objcopy(self) -> pathlib.Path:
        env_oc = os.environ.get("OBJCOPY", "").strip()
        cands = [
            env_oc,
            "/opt/homebrew/opt/llvm/bin/llvm-objcopy",
            "/usr/local/opt/llvm/bin/llvm-objcopy",
            str(self.obsd_root / "deps/emsdk/upstream/bin/llvm-objcopy"),
            shutil.which("llvm-objcopy") or "",
        ]
        for c in cands:
            if c and os.path.isfile(c) and os.access(c, os.X_OK):
                return pathlib.Path(c).resolve()
        die("llvm-objcopy not found (install llvm or set OBJCOPY)")

    def _load_translate_vector(self) -> Dict[str, Any]:
        vec_path = (
            self.obsd_root
            / "build/openbsd"
            / self.openbsd_version
            / "translate/gen/guest-configure/tool-probe-vector.tsv"
        )
        if not vec_path.is_file():
            die(
                f"missing libobsdcompat translate probe vector: {vec_path}\n"
                f"  run `scripts/build-backend.sh --sdk macosx --release {self.openbsd_version}` first"
            )
        st = vec_path.stat()
        key = hashlib.sha256(f"tv1:{vec_path}:{st.st_mtime_ns}:{st.st_size}".encode()).hexdigest()[:16]
        cache_f = self.cache_dir / f"darwin-translate-vec-{self.openbsd_version}-{key}.json"
        if cache_f.is_file():
            return json.loads(cache_f.read_text(encoding="utf-8"))

        compile_flags: List[str] = []
        link_flags: List[str] = []
        base_archive = ""
        include_root = ""

        for raw in vec_path.read_text(encoding="utf-8").splitlines():
            if not raw or raw.startswith("#"):
                continue
            parts = raw.split("\t", 1)
            if len(parts) != 2:
                continue
            sec, tok = parts[0].strip(), parts[1]
            if sec == "compile":
                # Drop `-Dmain=obsd_tool_main` so C/C++ struct fields or methods
                # named `main` compile cleanly; `_main` is renamed at link time!
                if tok == "-Dmain=obsd_tool_main":
                    continue
                compile_flags.append(tok)
            elif sec == "link":
                if tok.endswith(".a") and "libobsdc-" in os.path.basename(tok):
                    base_archive = tok
                else:
                    link_flags.append(tok)

        for idx, tok in enumerate(compile_flags):
            if tok == "-I" and idx + 1 < len(compile_flags) and "compiler-include-root-" in compile_flags[idx + 1]:
                include_root = compile_flags[idx + 1]
                break
        if not include_root:
            include_root = str(
                self.obsd_root
                / f"build/openbsd-boundary/include-roots/{self.openbsd_version}-kern-gate/compiler-include-root-{self.openbsd_version}-kern-gate"
            )
        if not base_archive:
            base_archive = str(
                self.obsd_root / f"build/openbsd-boundary/obj-{self.openbsd_version}-kern-gate/libobsdc-{self.openbsd_version}.a"
            )

        rodata_tool = self.obsd_root / "tools/build/personalities/openbsd/backends/emulate/link_guest_partial.sh"
        rodata_placement = self.obsd_root / "src/personalities/openbsd/runtime/backends/emulate/core/guest_rodata_placement.tsv"
        rodata_ldflags = ""
        if rodata_tool.is_file() and rodata_placement.is_file():
            proc = subprocess.run(
                [
                    "/bin/bash",
                    str(rodata_tool),
                    "--placement-ldflags",
                    "--sdk",
                    "macosx",
                    "--placement",
                    str(rodata_placement),
                    "--item",
                    "kern-gate-translate",
                    "--rodata-segment",
                    "__GUEST_RODATA",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                env=self.sanitized_env(),
            )
            if proc.returncode == 0:
                rodata_ldflags = proc.stdout.strip()

        data = {
            "compile_flags": compile_flags,
            "link_flags": link_flags,
            "base_archive": base_archive,
            "include_root": include_root,
            "rodata_ldflags": rodata_ldflags,
        }
        tmp = cache_f.with_suffix(f".{os.getpid()}.tmp")
        tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
        tmp.replace(cache_f)
        return data

    def _load_emulate_lane(self) -> Dict[str, str]:
        suffix = f"-emulate-{self.sdk}"
        ident_path = (
            self.obsd_root
            / f"build/openbsd-boundary/obj-{self.openbsd_version}-kern-gate{suffix}/.object-build-identity"
        )
        arch_path = (
            self.obsd_root
            / f"build/openbsd-boundary/obj-{self.openbsd_version}-kern-gate{suffix}/libobsdc-{self.openbsd_version}.a"
        )
        if not ident_path.is_file() or not arch_path.is_file():
            die(
                f"missing libobsdcompat emulate outputs for OpenBSD {self.openbsd_version} ({self.sdk}):\n"
                f"  expected {arch_path}\n"
                f"  run `scripts/build-backend.sh --sdk {self.sdk} --release {self.openbsd_version}` first"
            )
        st_i = ident_path.stat()
        st_a = arch_path.stat()
        key = hashlib.sha256(
            f"em1:{self.openbsd_version}:{self.sdk}:{st_i.st_mtime_ns}:{st_i.st_size}:{st_a.st_mtime_ns}:{st_a.st_size}".encode()
        ).hexdigest()[:16]
        cache_f = self.cache_dir / f"darwin-emulate-lane-{self.openbsd_version}-{self.sdk}-{key}.json"
        if cache_f.is_file():
            return json.loads(cache_f.read_text(encoding="utf-8"))

        ident_kv: Dict[str, str] = {}
        for ln in ident_path.read_text(encoding="utf-8", errors="replace").splitlines():
            if "=" in ln:
                k, v = ln.split("=", 1)
                ident_kv[k.strip()] = v.strip()

        consumer_cflags = ident_kv.get("CONSUMER_CFLAGS", "")
        include_root = ident_kv.get("INCLUDE_ROOT", "")
        arch_flags = ident_kv.get("BOUNDARY_ARCH_FLAGS", "")
        if not consumer_cflags or not include_root:
            die(f"malformed {ident_path}: missing CONSUMER_CFLAGS or INCLUDE_ROOT")

        # Extract target_flags (-target ... -mcpu=... -fstack-check) matching OPENBSD_EMULATE_TARGET_FLAGS
        target_toks: List[str] = []
        af_toks = shlex.split(arch_flags)
        idx = 0
        while idx < len(af_toks):
            t = af_toks[idx]
            if t == "-arch" and idx + 1 < len(af_toks):
                idx += 2
                continue
            if t == "-isysroot" and idx + 1 < len(af_toks):
                idx += 2
                continue
            if t == "-target" and idx + 1 < len(af_toks):
                target_toks.extend([t, af_toks[idx + 1]])
                idx += 2
                continue
            target_toks.append(t)
            idx += 1

        data = {
            "consumer_cflags": consumer_cflags,
            "include_root": include_root,
            "guest_archive": str(arch_path),
            "guest_identity": str(ident_path),
            "target_flags": " ".join(target_toks),
        }
        tmp = cache_f.with_suffix(f".{os.getpid()}.tmp")
        tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
        tmp.replace(cache_f)
        return data

    def remap_include_dir(self, path_str: str) -> Optional[str]:
        p = path_str.strip()
        if p.startswith("="):
            p = p[1:]
        norm = os.path.normpath(p)
        if any(norm == pref or norm.startswith(pref + "/") for pref in FORBIDDEN_HOST_PREFIXES):
            return None
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
        if any(norm == pref or norm.startswith(pref + "/") for pref in FORBIDDEN_HOST_PREFIXES):
            return None
        if norm == "/usr/local/lib" or norm.startswith("/usr/local/lib/"):
            sub = norm[len("/usr/local/lib") :].lstrip("/")
            base = self.stage_dir / "usr/local/lib"
            return str(base / sub) if sub else str(base)
        return path_str

    def raw_boundary_flags(self) -> List[str]:
        if self.backend == "translate":
            return list(self.translate_info["compile_flags"])
        toks = shlex.split(self.emulate_info["consumer_cflags"])
        return [t for t in toks if t != "-c"]

    def split_compile_flags(
        self, is_cxx: bool, preprocess_only: bool, is_asm: bool = False
    ) -> Tuple[List[str], List[str]]:
        """
        Split lane guest flags into `(prefix_flags, suffix_flags)` so:
          1. C++ `libcxx/include` `-isystem` directories ALWAYS precede OpenBSD
             C headers (`compiler-include-root`), preserving `#include_next`.
          2. Staged port headers (`stage/usr/local/include`) come before base
             OpenBSD headers, while `-include guest_identity.h` and `-idirafter
             <clang-resource-include>` stay at the end.
          3. `-femulated-tls` and `-U__ENVIRONMENT_*_VERSION_MIN_REQUIRED__`
             enforce zero Mach-O `__thread_*` TLV sections and zero host
             `<mach-o/dyld.h>` header pulls.
        """
        raw = self.raw_boundary_flags()
        prefix: List[str] = []
        boundary_incs: List[str] = []
        trailing_includes: List[str] = []
        idirafter_flags: List[str] = []

        i = 0
        while i < len(raw):
            tok = raw[i]
            if tok == "-I" and i + 1 < len(raw):
                boundary_incs.extend(["-isystem" if is_cxx else "-I", raw[i + 1]])
                i += 2
                continue
            if tok.startswith("-I") and len(tok) > 2:
                boundary_incs.extend(["-isystem" if is_cxx else "-I", tok[2:]])
                i += 1
                continue
            if tok == "-include" and i + 1 < len(raw):
                inc_hdr = raw[i + 1]
                # Skip `-include stdlib.h` in ports (breaks gnulib `./stdlib.h` before `config.h` and libc++ `#include_next <stdlib.h>`)
                if is_asm or preprocess_only or inc_hdr == "stdlib.h":
                    i += 2
                    continue
                trailing_includes.extend(["-include", inc_hdr])
                i += 2
                continue
            if tok == "-idirafter" and i + 1 < len(raw):
                idirafter_flags.extend(["-idirafter", raw[i + 1]])
                i += 2
                continue
            if is_cxx and tok in ("-Wno-implicit-int", "-Wno-implicit-function-declaration"):
                i += 1
                continue
            if tok == "-g":
                # Omit debug DWARF by default in port TUs for fast builds & compact binaries
                i += 1
                continue
            prefix.append(tok)
            i += 1

        prefix.extend(
            [
                "-fno-omit-frame-pointer",
                "-femulated-tls",
                "-U__EMSCRIPTEN__",
                "-U__linux__",
                "-U__gnu_linux__",
                "-Ulinux",
                "-D__unix__=1",
                "-D__LP64__=1",
                "-D_LP64=1",
                *DARWIN_ENV_UNDEFS,
            ]
        )
        if is_cxx:
            prefix.extend(
                [
                    "-nostdinc++",
                    "-D_LIBCPP_DISABLE_VISIBILITY_ANNOTATIONS",
                    "-D_LIBCXXABI_DISABLE_VISIBILITY_ANNOTATIONS",
                ]
            )

        suffix: List[str] = []
        if is_cxx:
            cxx_cfg = ensure_cxx_config_dir(self.cache_dir, self.openbsd_version)
            suffix.extend(
                [
                    "-isystem",
                    str(cxx_cfg),
                    "-isystem",
                    str(self.em_dir / "system/lib/libcxx/include"),
                    "-isystem",
                    str(self.em_dir / "system/lib/libcxxabi/include"),
                ]
            )

        stage_inc = self.stage_dir / "usr/local/include"
        if stage_inc.is_dir():
            suffix.extend(["-isystem", str(stage_inc)])

        suffix.extend(boundary_incs)
        suffix.extend(trailing_includes)
        suffix.extend(idirafter_flags)
        return prefix, suffix

    def clang_rt_archive(self) -> Optional[pathlib.Path]:
        key = hashlib.sha1(f"clangrt:{self.sdk}".encode()).hexdigest()[:12]
        cache_f = self.cache_dir / f"darwin-clangrt-{self.sdk}-{key}.txt"
        if cache_f.is_file():
            val = cache_f.read_text(encoding="utf-8").strip()
            return pathlib.Path(val) if val and os.path.isfile(val) else None
        res_dir = subprocess.check_output(
            [*self.cc_cmd, "-print-resource-dir"], text=True, env=self.sanitized_env()
        ).strip()
        rt_name = {
            "macosx": "libclang_rt.osx.a",
            "iphonesimulator": "libclang_rt.iossim.a",
            "iphoneos": "libclang_rt.ios.a",
        }[self.sdk]
        cand = pathlib.Path(res_dir) / "lib/darwin" / rt_name
        cache_f.write_text((str(cand) if cand.is_file() else "") + "\n", encoding="utf-8")
        return cand if cand.is_file() else None

    def ensure_guest_libm_archive(self) -> pathlib.Path:
        """
        Build & cache OpenBSD's vendored `src/lib/libm` (`libobsd_port_libm.a`)
        for Darwin `translate` and `emulate` lanes (plus OpenBSD `libc/regex` and
        POSIX `creat`/`killpg`/`getdtablesize` guest wrappers on `translate`) so
        all math/regex/POSIX calls resolve statically inside the `-ffixed-x18`
        OpenBSD guest domain with zero un-allowlisted `libSystem` imports.
        """
        libm_dir = self.obsd_root / f"vendor/openbsd/versions/{self.openbsd_version}/src/lib/libm"
        regex_dir = self.obsd_root / f"vendor/openbsd/versions/{self.openbsd_version}/src/lib/libc/regex"
        mk_file = libm_dir / "Makefile"
        if not mk_file.is_file():
            die(f"missing vendored OpenBSD libm Makefile: {mk_file}")

        darwin_math_builtins_src = (
            "#include <math.h>\n"
            "#ifndef M_PI\n"
            "#define M_PI 3.14159265358979323846\n"
            "#endif\n"
            "struct __obsd_sincos_d { double __sinval; double __cosval; };\n"
            "struct __obsd_sincos_f { float __sinval; float __cosval; };\n"
            "double __exp10(double x) { return pow(10.0, x); }\n"
            "float __exp10f(float x) { return powf(10.0f, x); }\n"
            "double __sinpi(double x) { return sin(M_PI * x); }\n"
            "float __sinpif(float x) { return sinf((float)M_PI * x); }\n"
            "double __cospi(double x) { return cos(M_PI * x); }\n"
            "float __cospif(float x) { return cosf((float)M_PI * x); }\n"
            "double __tanpi(double x) { return tan(M_PI * x); }\n"
            "float __tanpif(float x) { return tanf((float)M_PI * x); }\n"
            "struct __obsd_sincos_d __sincos_stret(double x) { struct __obsd_sincos_d r; r.__sinval = sin(x); r.__cosval = cos(x); return r; }\n"
            "struct __obsd_sincos_f __sincosf_stret(float x) { struct __obsd_sincos_f r; r.__sinval = sinf(x); r.__cosval = cosf(x); return r; }\n"
            "struct __obsd_sincos_d __sincospi_stret(double x) { struct __obsd_sincos_d r; r.__sinval = sin(M_PI * x); r.__cosval = cos(M_PI * x); return r; }\n"
            "struct __obsd_sincos_f __sincospif_stret(float x) { struct __obsd_sincos_f r; r.__sinval = sinf((float)M_PI * x); r.__cosval = cosf((float)M_PI * x); return r; }\n"
        )
        dso_handle_src = "__attribute__((visibility(\"default\"), weak)) void *__dso_handle = (void *)0;\n"
        posix_sup_src = (
            "#include <fcntl.h>\n"
            "#include <signal.h>\n"
            "#include <unistd.h>\n"
            "int creat(const char *path, mode_t mode) { return open(path, O_WRONLY | O_CREAT | O_TRUNC, mode); }\n"
            "int killpg(pid_t pgrp, int sig) { if (pgrp == 1) return -1; return kill(pgrp == 0 ? -getpgrp() : -pgrp, sig); }\n"
            "int getdtablesize(void) { long n = sysconf(_SC_OPEN_MAX); return n < 0 ? 256 : (int)n; }\n"
        )

        sig = hashlib.sha256(
            f"guest-libm-v6:{self.openbsd_version}:{self.backend}:{self.sdk}:{self.guest_bank_digest}:{mk_file.stat().st_mtime_ns}:{' '.join(self.raw_boundary_flags())}:{DARWIN_LIBM_MACHO_SHIM_H}:{darwin_math_builtins_src}:{dso_handle_src}:{posix_sup_src}".encode()
        ).hexdigest()[:16]
        out_dir = self.cache_dir / f"darwin-libm-{self.openbsd_version}-{self.backend}-{self.sdk}-{sig}"
        ar_path = out_dir / "libobsd_port_libm.a"
        if ar_path.is_file():
            return ar_path

        out_dir.mkdir(parents=True, exist_ok=True)
        lock_p = self.cache_dir / f"darwin-libm-{self.openbsd_version}-{self.backend}-{self.sdk}.lock"
        with lock_p.open("w") as lfp:
            fcntl.flock(lfp.fileno(), fcntl.LOCK_EX)
            if ar_path.is_file():
                return ar_path

            mk_joined = re.sub(r"\\\n", " ", mk_file.read_text(encoding="utf-8", errors="replace"))
            m_common = re.search(r"COMMON_SRCS\s*=\s*(.+)", mk_joined)
            m_pure = re.search(r"PURE_SRCS\s*=\s*(.+)", mk_joined)
            if not m_common or not m_pure:
                die(f"could not parse COMMON_SRCS/PURE_SRCS in {mk_file}")

            srcs: List[pathlib.Path] = []
            for fn in m_common.group(1).split() + m_pure.group(1).split():
                cand = (
                    (libm_dir / "arch/aarch64" / fn)
                    if (libm_dir / "arch/aarch64" / fn).is_file()
                    else (libm_dir / "src" / fn)
                )
                if not cand.is_file():
                    die(f"missing OpenBSD libm source {fn} under {libm_dir}")
                srcs.append(cand)

            c_pref, c_suf = self.split_compile_flags(is_cxx=False, preprocess_only=False, is_asm=True)
            std_pref, std_suf = self.split_compile_flags(is_cxx=False, preprocess_only=False, is_asm=False)
            sp = self.obsd_root / "src/personalities/openbsd/runtime/backends/translate/boundary"
            senv = self.sanitized_env()

            with tempfile.TemporaryDirectory(prefix=f"obsd-libm-{self.openbsd_version}-{self.sdk}-") as td:
                tp = pathlib.Path(td)
                shim_h = tp / "libm_macho_shim.h"
                shim_h.write_text(DARWIN_LIBM_MACHO_SHIM_H, encoding="utf-8")

                def _compile_src(src_p: pathlib.Path) -> Tuple[str, int, str, pathlib.Path]:
                    obj_p = tp / f"libm_{src_p.stem}.o"
                    cmd = [
                        *self.cc_compile_cmd,
                        "-c",
                        *c_pref,
                        "-fno-builtin",
                        "-fno-stack-protector",
                        "-I",
                        str(libm_dir / "hidden"),
                        "-I",
                        str(libm_dir / "src"),
                        *c_suf,
                        "-include",
                        str(libm_dir / "hidden/namespace.h"),
                        "-include",
                        str(shim_h),
                        "-include",
                        str(sp / "guest_identity.h"),
                        "-Wno-ignored-attributes",
                        "-Wno-unsupported-visibility",
                        "-Wno-parentheses",
                        "-Wno-literal-range",
                        str(src_p),
                        "-o",
                        str(obj_p),
                    ]
                    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=senv)
                    return src_p.name, p.returncode, p.stderr, obj_p

                objs: List[pathlib.Path] = []
                with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count() or 8) as pool:
                    for nm, rc, err, obj_p in pool.map(_compile_src, srcs):
                        if rc != 0:
                            die(f"failed building OpenBSD guest libm ({nm}):\n{err}")
                        objs.append(obj_p)

                mbi_c = tp / "obsd_darwin_math_builtins.c"
                mbi_o = tp / "obsd_darwin_math_builtins.o"
                mbi_c.write_text(darwin_math_builtins_src, encoding="utf-8")
                subprocess.run(
                    [
                        *self.cc_compile_cmd,
                        "-c",
                        *std_pref,
                        "-fno-builtin",
                        "-fno-stack-protector",
                        str(mbi_c),
                        *std_suf,
                        "-o",
                        str(mbi_o),
                    ],
                    env=senv,
                    check=True,
                )
                objs.append(mbi_o)

                dso_c = tp / "obsd_dso_handle.c"
                dso_o = tp / "obsd_dso_handle.o"
                dso_c.write_text(dso_handle_src, encoding="utf-8")
                subprocess.run(
                    [*self.cc_compile_cmd, "-c", *std_pref, "-fno-stack-protector", str(dso_c), *std_suf, "-o", str(dso_o)],
                    env=senv,
                    check=True,
                )
                objs.append(dso_o)

                # Compile 128-bit integer builtins (`__udivti3`, `__umodti3`, `__divti3`, `__modti3`, `__multi3`, shifts)
                # directly from checked-out LLVM compiler-rt with `-ffixed-x18` (zero host `libclang_rt.*.a` dependency)
                crt_bdir = self.em_dir / "system/lib/compiler-rt/lib/builtins"
                for bfn in (
                    "udivmodti4.c",
                    "udivti3.c",
                    "umodti3.c",
                    "divmodti4.c",
                    "divti3.c",
                    "modti3.c",
                    "multi3.c",
                    "ashlti3.c",
                    "lshrti3.c",
                    "ashrti3.c",
                ):
                    bsrc = crt_bdir / bfn
                    bobj = tp / f"obsd_crt_{bsrc.stem}.o"
                    subprocess.run(
                        [
                            *self.cc_compile_cmd,
                            "-c",
                            *std_pref,
                            "-fno-builtin",
                            "-fno-stack-protector",
                            "-I",
                            str(crt_bdir),
                            str(bsrc),
                            *std_suf,
                            "-D__UEFI__=1",
                            "-o",
                            str(bobj),
                        ],
                        env=senv,
                        check=True,
                    )
                    objs.append(bobj)

                if self.backend == "translate":
                    sup_c = tp / "obsd_port_posix_sup.c"
                    sup_o = tp / "obsd_port_posix_sup.o"
                    sup_c.write_text(posix_sup_src, encoding="utf-8")
                    subprocess.run(
                        [*self.cc_cmd, "-c", *std_pref, "-fno-stack-protector", str(sup_c), *std_suf, "-o", str(sup_o)],
                        env=senv,
                        check=True,
                    )
                    objs.append(sup_o)
                    for rfn in ("regcomp.c", "regerror.c", "regexec.c", "regfree.c"):
                        rsrc = regex_dir / rfn
                        robj = tp / f"obsd_regex_{rsrc.stem}.o"
                        subprocess.run(
                            [
                                *self.cc_cmd,
                                "-c",
                                *std_pref,
                                "-fno-stack-protector",
                                "-DDEF_WEAK(x)=",
                                "-I",
                                str(regex_dir),
                                str(rsrc),
                                *std_suf,
                                "-o",
                                str(robj),
                            ],
                            env=senv,
                            check=True,
                        )
                        objs.append(robj)

                tmp_a = tp / "libobsd_port_libm.a"
                subprocess.run([*self.ar_cmd, "-rcs", str(tmp_a), *[str(x) for x in objs]], env=senv, check=True)
                shutil.copy2(tmp_a, ar_path)
        return ar_path

    ensure_emulate_libm_archive = ensure_guest_libm_archive

    def guest_sup_defined_symbols(self) -> Set[str]:
        ar_p = self.ensure_guest_libm_archive()
        st = ar_p.stat()
        key = hashlib.sha256(f"gsup-syms:{ar_p}:{st.st_mtime_ns}:{st.st_size}".encode()).hexdigest()[:16]
        cache_f = self.cache_dir / f"darwin-libm-syms-{self.openbsd_version}-{self.backend}-{self.sdk}-{key}.json"
        if cache_f.is_file():
            return set(json.loads(cache_f.read_text(encoding="utf-8")))
        nm_out = subprocess.check_output(
            [*self.nm_cmd, "-g", str(ar_p)], text=True, stderr=subprocess.DEVNULL, env=self.sanitized_env()
        )
        syms: Set[str] = set()
        for ln in nm_out.splitlines():
            ps = ln.strip().split()
            if len(ps) >= 3 and ps[1] in ("T", "D", "S", "C", "B") and not ln.strip().endswith(":"):
                syms.add(ps[2])
        tmp = cache_f.with_suffix(f".{os.getpid()}.tmp")
        tmp.write_text(json.dumps(sorted(syms)), encoding="utf-8")
        tmp.replace(cache_f)
        return syms

    def ensure_emutls_archive(self) -> pathlib.Path:
        sig = hashlib.sha256(
            f"emutls-v3:{self.openbsd_version}:{self.backend}:{self.sdk}:{self.guest_bank_digest}:{' '.join(self.raw_boundary_flags())}:{DARWIN_EMUTLS_C}".encode()
        ).hexdigest()[:16]
        out_dir = self.cache_dir / f"darwin-emutls-{self.openbsd_version}-{self.backend}-{self.sdk}-{sig}"
        ar_path = out_dir / "libobsd_emutls.a"
        if ar_path.is_file():
            return ar_path

        out_dir.mkdir(parents=True, exist_ok=True)
        lock_p = self.cache_dir / f"darwin-emutls-{self.openbsd_version}-{self.backend}-{self.sdk}.lock"
        with lock_p.open("w") as lfp:
            fcntl.flock(lfp.fileno(), fcntl.LOCK_EX)
            if ar_path.is_file():
                return ar_path
            prefix_cf, suffix_cf = self.split_compile_flags(is_cxx=False, preprocess_only=False)
            with tempfile.TemporaryDirectory(prefix="obsd-emutls-") as td:
                tp = pathlib.Path(td)
                src = tp / "obsd_emutls.c"
                obj = tp / "obsd_emutls.o"
                tmp_a = tp / "libobsd_emutls.a"
                src.write_text(DARWIN_EMUTLS_C, encoding="utf-8")
                subprocess.run(
                    [
                        *self.cc_compile_cmd,
                        "-c",
                        *prefix_cf,
                        "-fno-stack-protector",
                        "-O2",
                        str(src),
                        *suffix_cf,
                        "-o",
                        str(obj),
                    ],
                    env=self.sanitized_env(),
                    check=True,
                )
                subprocess.run([*self.ar_cmd, "-rcs", str(tmp_a), str(obj)], env=self.sanitized_env(), check=True)
                shutil.copy2(tmp_a, ar_path)
        return ar_path

    def ensure_darwin_cxx_runtime(self) -> Tuple[pathlib.Path, pathlib.Path, pathlib.Path, pathlib.Path]:
        """
        Build & cache `(libc++.a, libc++abi.a, libunwind.a, libobsd_emutls.a)`
        for `(openbsd_version, backend, sdk)` with:
          - `x18`-free `UnwindRegistersSave.S` / `UnwindRegistersRestore.S`,
          - dyld-free `AddressSpace.hpp` Mach-O header unwind section discovery,
          - zero `__DATA,__mod_init_func` sections (`iostream.cpp.o` retyped via
            `retype_guest_initializers.py` to `__GUEST,__obsd_gi0098`).
        """
        if not (self.em_dir / "system/lib/libcxx").is_dir():
            die(f"missing LLVM libcxx sources under {self.em_dir / 'system/lib/libcxx'}")

        emutls_a = self.ensure_emutls_archive()
        sig = hashlib.sha256(
            (
                f"darwin-cxx-rt-v4:{self.openbsd_version}:{self.backend}:{self.sdk}:{self.guest_bank_digest}:"
                f"{self.base_archive.stat().st_mtime_ns if self.base_archive.is_file() else 0}:"
                f"{' '.join(self.raw_boundary_flags())}:{LIBCPP_CONFIG_SITE_TEXT}:"
                f"{OBSD_CXX_SUPPORT_C}:{DARWIN_UNWIND_FIND_REPL}"
            ).encode()
        ).hexdigest()[:16]

        rt_dir = self.cache_dir / f"darwin-cxx-rt-{self.openbsd_version}-{self.backend}-{self.sdk}-{sig}"
        libcxx_a = rt_dir / "libc++.a"
        libcxxabi_a = rt_dir / "libc++abi.a"
        libunwind_a = rt_dir / "libunwind.a"
        stamp_file = rt_dir / "cxx-rt.stamp"

        if stamp_file.is_file() and libcxx_a.is_file() and libcxxabi_a.is_file() and libunwind_a.is_file():
            return libcxx_a, libcxxabi_a, libunwind_a, emutls_a

        rt_dir.mkdir(parents=True, exist_ok=True)
        lock_p = self.cache_dir / f"darwin-cxx-rt-{self.openbsd_version}-{self.backend}-{self.sdk}.lock"
        with lock_p.open("w") as lfp:
            fcntl.flock(lfp.fileno(), fcntl.LOCK_EX)
            if stamp_file.is_file() and libcxx_a.is_file() and libcxxabi_a.is_file() and libunwind_a.is_file():
                return libcxx_a, libcxxabi_a, libunwind_a, emutls_a

            retype_dir = self.obsd_root / "tools/build/personalities/openbsd/backends/translate"
            retype_py = retype_dir / "retype_guest_initializers.py"
            if str(retype_dir) not in sys.path:
                sys.path.insert(0, str(retype_dir))
            import retype_guest_initializers as rgi  # type: ignore

            c_pref, c_suf = self.split_compile_flags(is_cxx=False, preprocess_only=False)
            cxx_pref, cxx_suf = self.split_compile_flags(is_cxx=True, preprocess_only=False)
            asm_pref, asm_suf = self.split_compile_flags(is_cxx=False, preprocess_only=False, is_asm=True)

            warn_suppress = [
                "-Wno-invalid-noreturn",
                "-Wno-unsupported-visibility",
                "-Wno-ignored-attributes",
                "-Wno-macro-redefined",
                "-Wno-unused-but-set-variable",
                "-Wno-unqualified-std-cast-call",
                "-Wno-unknown-warning-option",
                "-Wno-user-defined-literals",
                "-fno-stack-protector",
            ]

            with tempfile.TemporaryDirectory(prefix=f"obsd-darwin-cxx-{self.openbsd_version}-{self.sdk}-") as td:
                tp = pathlib.Path(td)

                # Stage patched copy of libunwind (x18-clean + Mach-O without __APPLE__ / dyld)
                uw_stage = tp / "libunwind"
                shutil.copytree(self.em_dir / "system/lib/libunwind", uw_stage)

                save_s = uw_stage / "src/UnwindRegistersSave.S"
                save_txt = save_s.read_text(encoding="utf-8")
                if "stp    x18,x19, [x0, #0x090]" not in save_txt:
                    die("unexpected UnwindRegistersSave.S layout: could not patch x18")
                save_s.write_text(
                    save_txt.replace("stp    x18,x19, [x0, #0x090]", "str    x19,     [x0, #0x098]"),
                    encoding="utf-8",
                )

                rest_s = uw_stage / "src/UnwindRegistersRestore.S"
                rest_txt = rest_s.read_text(encoding="utf-8")
                if "ldp    x18,x19, [x0, #0x090]" not in rest_txt:
                    die("unexpected UnwindRegistersRestore.S layout: could not patch x18")
                rest_s.write_text(
                    rest_txt.replace("ldp    x18,x19, [x0, #0x090]", "ldr    x19,     [x0, #0x098]"),
                    encoding="utf-8",
                )

                for hdr_rel in ("src/assembly.h", "src/config.h"):
                    hp = uw_stage / hdr_rel
                    ht = hp.read_text(encoding="utf-8")
                    ht = ht.replace("defined(__APPLE__)", "(defined(__APPLE__) || defined(LIBOBSDCOMPAT_OBJECT_FORMAT_MACHO))")
                    ht = ht.replace("#ifdef __APPLE__", "#if defined(__APPLE__) || defined(LIBOBSDCOMPAT_OBJECT_FORMAT_MACHO)")
                    hp.write_text(ht, encoding="utf-8")

                as_hpp = uw_stage / "src/AddressSpace.hpp"
                as_txt = as_hpp.read_text(encoding="utf-8")
                marker = "#elif defined(_LIBUNWIND_SUPPORT_DWARF_UNWIND) && defined(_LIBUNWIND_IS_BAREMETAL)\n  info.dso_base = 0;"
                if marker not in as_txt:
                    die("unexpected libunwind AddressSpace.hpp layout")
                as_hpp.write_text(as_txt.replace(marker, DARWIN_UNWIND_FIND_REPL + "\n" + marker, 1), encoding="utf-8")

                tasks: List[Tuple[str, List[str]]] = []

                sup_c = tp / "obsd_cxx_support.c"
                sup_o = tp / "obsd_cxx_support.o"
                sup_c.write_text(OBSD_CXX_SUPPORT_C, encoding="utf-8")
                tasks.append(
                    ("support", [*self.cc_compile_cmd, "-c", *c_pref, *warn_suppress, str(sup_c), *c_suf, "-o", str(sup_o)])
                )

                uw_objs: List[pathlib.Path] = []
                uw_common_defs = [
                    "-DNDEBUG",
                    "-D_LIBUNWIND_IS_NATIVE_ONLY=1",
                    "-D_LIBUNWIND_USE_DLADDR=0",
                    "-D_LIBUNWIND_HIDE_SYMBOLS=1",
                    "-I",
                    str(uw_stage / "include"),
                    "-I",
                    str(uw_stage / "src"),
                ]
                for uw_asm in ("UnwindRegistersSave.S", "UnwindRegistersRestore.S"):
                    o = tp / f"uw_{uw_asm}.o"
                    uw_objs.append(o)
                    tasks.append(
                        (
                            f"unwind:{uw_asm}",
                            [*self.cc_cmd, "-c", *asm_pref, *uw_common_defs, str(uw_stage / "src" / uw_asm), *asm_suf, "-o", str(o)],
                        )
                    )
                for uw_c in ("UnwindLevel1.c", "UnwindLevel1-gcc-ext.c"):
                    o = tp / f"uw_{uw_c}.o"
                    uw_objs.append(o)
                    tasks.append(
                        (
                            f"unwind:{uw_c}",
                            [
                                *self.cc_compile_cmd,
                                "-c",
                                "-std=c99",
                                *c_pref,
                                *warn_suppress,
                                *uw_common_defs,
                                str(uw_stage / "src" / uw_c),
                                *c_suf,
                                "-o",
                                str(o),
                            ],
                        )
                    )
                uw_cpp_o = tp / "uw_libunwind.cpp.o"
                uw_objs.append(uw_cpp_o)
                tasks.append(
                    (
                        "unwind:libunwind.cpp",
                        [
                            *self.cxx_compile_cmd,
                            "-c",
                            "-std=c++17",
                            "-fno-exceptions",
                            "-fno-rtti",
                            *cxx_pref,
                            *warn_suppress,
                            *uw_common_defs,
                            str(uw_stage / "src/libunwind.cpp"),
                            *cxx_suf,
                            "-o",
                            str(uw_cpp_o),
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
                    abi_src = self.em_dir / "system/lib/libcxxabi/src" / fn
                    if fn == "cxa_exception_storage.cpp":
                        # Force pthread_key_t (`std::__libcpp_tls_key`) storage instead of `thread_local`
                        # so `key_` and `flag_` bank natively via `ObsdGuestBankPass` with zero `__DATA`!
                        patched_ces = tp / "cxa_exception_storage.cpp"
                        ces_txt = abi_src.read_text(encoding="utf-8")
                        patched_ces.write_text(
                            ces_txt.replace("#elif __has_feature(cxx_thread_local)", "#elif 0"),
                            encoding="utf-8",
                        )
                        abi_src = patched_ces
                    tasks.append(
                        (
                            f"cxxabi:{fn}",
                            [
                                *self.cxx_compile_cmd,
                                "-c",
                                "-std=c++23",
                                "-I",
                                str(self.em_dir / "system/lib/libcxxabi/src"),
                                *cxx_pref,
                                *warn_suppress,
                                "-DNDEBUG",
                                "-D_LIBCPP_BUILDING_LIBRARY",
                                "-D_LIBCXXABI_BUILDING_LIBRARY",
                                "-DLIBCXXABI_NON_DEMANGLING_TERMINATE",
                                "-I",
                                str(self.em_dir / "system/lib/libcxx/src"),
                                "-I",
                                str(uw_stage / "include"),
                                str(abi_src),
                                *cxx_suf,
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
                cxx_src_root = self.em_dir / "system/lib/libcxx/src"
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
                                *self.cxx_compile_cmd,
                                "-c",
                                "-std=c++23",
                                *cxx_pref,
                                *warn_suppress,
                                "-DNDEBUG",
                                "-DLIBCXX_BUILDING_LIBCXXABI=1",
                                "-D_LIBCPP_BUILDING_LIBRARY",
                                "-D_LIBCPP_AVAILABILITY_MINIMUM_HEADER_VERSION=23",
                                "-D_LIBCPP_HAS_NO_PRAGMA_SYSTEM_HEADER",
                                "-DLIBC_NAMESPACE=__llvm_libc",
                                "-I",
                                str(cxx_src_root),
                                "-I",
                                str(self.em_dir / "system/lib/llvm-libc"),
                                str(src),
                                *cxx_suf,
                                "-o",
                                str(o),
                            ],
                        )
                    )

                senv = self.sanitized_env()

                def _compile_one(item: Tuple[str, List[str]]) -> Tuple[str, int, str]:
                    lbl, cmd_vec = item
                    p = subprocess.run(cmd_vec, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=senv)
                    return lbl, p.returncode, p.stderr

                with concurrent.futures.ThreadPoolExecutor(max_workers=os.cpu_count() or 8) as pool:
                    for lbl, rc, err_txt in pool.map(_compile_one, tasks):
                        if rc != 0:
                            die(f"failed building Darwin C++ runtime ({lbl}):\n{err_txt}")

                # Retype any __DATA,__mod_init_func in libc++ / libc++abi / libunwind objects
                # (e.g. iostream.cpp.o) to __GUEST,__obsd_gi0098 so ZERO __mod_init_func
                # sections exist inside the cached C++ runtime archives!
                for idx_o, cand_o in enumerate([*cxx_objs, *abi_objs, *uw_objs, sup_o]):
                    mobj = rgi.read_object(str(cand_o), cand_o.name)
                    if mobj.terminator_sections():
                        die(f"Darwin C++ runtime object {cand_o.name} emitted forbidden __mod_term_func")
                    if mobj.initializer_sections():
                        valid_syms = [s for s in sorted(mobj.defined) if re.fullmatch(r"_[A-Za-z0-9_$.]+", s)]
                        if not valid_syms:
                            die(f"Darwin C++ runtime object {cand_o.name} has initializer but no Mach-O defined symbol")
                        pol = tp / f"rt_init_{idx_o}.policy"
                        pol.write_text(
                            f"guest-retyped 0098 {cand_o.name} {valid_syms[0]} sdk/lib/obsd_toolchain.py:1#cxxrt\n",
                            encoding="utf-8",
                        )
                        subprocess.run(
                            ["/usr/bin/python3", "-I", "-B", str(retype_py), "--apply", "--policy", str(pol), "--member", cand_o.name, str(cand_o)],
                            env=senv,
                            check=True,
                        )

                tmp_cxx = tp / "libc++.a"
                tmp_abi = tp / "libc++abi.a"
                tmp_uw = tp / "libunwind.a"
                subprocess.run([*self.ar_cmd, "-rcs", str(tmp_cxx), *[str(x) for x in cxx_objs]], env=senv, check=True)
                subprocess.run([*self.ar_cmd, "-rcs", str(tmp_abi), *[str(x) for x in abi_objs], str(sup_o)], env=senv, check=True)
                subprocess.run([*self.ar_cmd, "-rcs", str(tmp_uw), *[str(x) for x in uw_objs]], env=senv, check=True)

                shutil.copy2(tmp_cxx, libcxx_a)
                shutil.copy2(tmp_abi, libcxxabi_a)
                shutil.copy2(tmp_uw, libunwind_a)
                shutil.copy2(tmp_cxx, rt_dir / "libc++-noexcept.a")
                shutil.copy2(tmp_abi, rt_dir / "libc++abi-noexcept.a")
                stamp_file.write_text(sig + "\n", encoding="utf-8")

        return libcxx_a, libcxxabi_a, libunwind_a, emutls_a

    def darwin_cxx_rt_defined_symbols(self) -> Set[str]:
        libcxx_a, libcxxabi_a, libunwind_a, emutls_a = self.ensure_darwin_cxx_runtime()
        ars = (libcxx_a, libcxxabi_a, libunwind_a, emutls_a)
        key_src = "|".join(f"{p}:{p.stat().st_mtime_ns}:{p.stat().st_size}" for p in ars)
        key = hashlib.sha256(f"cxxrt-syms-v1:{key_src}".encode()).hexdigest()[:16]
        cache_f = self.cache_dir / f"darwin-cxx-rt-syms-{self.openbsd_version}-{self.backend}-{self.sdk}-{key}.json"
        if cache_f.is_file():
            return set(json.loads(cache_f.read_text(encoding="utf-8")))
        syms: Set[str] = {"___obsd_cxx_rt_init"}
        senv = self.sanitized_env()
        for ar_p in ars:
            nm_out = subprocess.check_output(
                [*self.nm_cmd, "-g", str(ar_p)], text=True, stderr=subprocess.DEVNULL, env=senv
            )
            for ln in nm_out.splitlines():
                ps = ln.strip().split()
                if len(ps) >= 3 and ps[1] in ("T", "D", "S", "C", "B") and not ln.strip().endswith(":"):
                    syms.add(ps[2])
        tmp = cache_f.with_suffix(f".{os.getpid()}.tmp")
        tmp.write_text(json.dumps(sorted(syms)), encoding="utf-8")
        tmp.replace(cache_f)
        return syms

    def allowed_guest_undefined_symbols(self) -> Set[str]:
        if not self.base_archive.is_file():
            die(f"missing Darwin guest archive: {self.base_archive}")
        allowlist_txt = (
            self.obsd_root / "tools/audit/personalities/openbsd/backends/emulate/guest_import_allowlist.txt"
        )
        domains_txt = pathlib.Path(str(self.base_archive) + ".domains")
        st_a = self.base_archive.stat()
        sig = hashlib.sha256(
            f"guest-undefs-v2:{self.openbsd_version}:{self.backend}:{self.sdk}:{st_a.st_mtime_ns}:{st_a.st_size}".encode()
        ).hexdigest()[:16]
        cache_f = self.cache_dir / f"darwin-guest-undefs-{self.openbsd_version}-{self.backend}-{self.sdk}-{sig}.json"
        if cache_f.is_file():
            return set(json.loads(cache_f.read_text(encoding="utf-8")))

        senv = self.sanitized_env()
        guest_members: Optional[Set[str]] = None
        if domains_txt.is_file():
            guest_members = set()
            for ln in domains_txt.read_text(encoding="utf-8").splitlines():
                cols = ln.split("\t")
                if len(cols) == 4 and (
                    cols[2] == "guest"
                    or (self.backend == "translate" and cols[1] in ("kvm_pal.o", "nlist_pal.o", "tmux_proc_host.o"))
                ):
                    guest_members.add(cols[1])

        nm_out = subprocess.check_output(
            [*self.nm_cmd, "-g", str(self.base_archive)],
            text=True,
            stderr=subprocess.DEVNULL,
            env=senv,
        )
        allowed: Set[str] = {
            "__obsd_gate",
            "__cerror",
            "___obsd_guest_tcb",
            "___obsd_guest_bank_tsd_off",
            "_end",
            "___executable_start",
            "_abort",
        }
        cur_member = ""
        for ln in nm_out.splitlines():
            s = ln.strip()
            if s.endswith(":"):
                cur_member = s[:-1].rsplit("(", 1)[-1].rstrip(")").rsplit("/", 1)[-1]
                continue
            if guest_members is not None and cur_member and cur_member not in guest_members:
                continue
            ps = s.split()
            if len(ps) >= 3 and ps[1] in ("T", "D", "S", "C", "B"):
                # Exclude `_dlopen` from configure link-probe allow-list on Darwin
                # so Autoconf AC_CHECK_FUNC(dlopen) never enables runtime plugin loaders!
                if ps[2] in ("_dlopen", "_dlsym", "_dlclose", "_dlerror"):
                    continue
                allowed.add(ps[2])

        if allowlist_txt.is_file():
            for ln in allowlist_txt.read_text(encoding="utf-8").splitlines():
                if not ln.strip() or ln.startswith("#"):
                    continue
                cols = ln.split("\t")
                if cols:
                    allowed.add(cols[0].strip())

        tmp = cache_f.with_suffix(f".{os.getpid()}.tmp")
        tmp.write_text(json.dumps(sorted(allowed)), encoding="utf-8")
        tmp.replace(cache_f)
        return allowed

    allowed_emulate_undefined_symbols = allowed_guest_undefined_symbols


def resolve_darwin_library(
    tc: DarwinToolchain,
    name: str,
    lib_dirs: Sequence[str],
    stage_lib_dir: pathlib.Path,
) -> Tuple[List[str], bool]:
    """
    Resolve `-l<name>` on Darwin:
      - Returns `([archive_paths...], True)` for staged port `.a` or SDK C++ runtime archives.
      - Returns `([], True)` for base OpenBSD libraries in `libobsdc-<ver>.a`.
      - Refuses `-ldl` (`([], False)`) so `AC_CHECK_LIB(dl, dlopen)` always fails cleanly.
    """
    if name == "dl":
        return [], False

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
                return [str(cand)], True
        return [], False

    for d in search_dirs:
        dp = pathlib.Path(d)
        cand_a = dp / f"lib{name}.a"
        if cand_a.is_file():
            return [str(cand_a)], True
        cand_la = dp / f"lib{name}.la"
        if cand_la.is_file():
            try:
                for ln in cand_la.read_text(encoding="utf-8", errors="replace").splitlines():
                    if ln.startswith("old_library="):
                        old_lib = ln.split("=", 1)[1].strip().strip("'\"")
                        if old_lib:
                            for sub in (dp / old_lib, dp / ".libs" / old_lib):
                                if sub.is_file():
                                    return [str(sub)], True
            except OSError:
                pass

    if name in ("c++", "stdc++", "c++-noexcept"):
        libcxx_a, libcxxabi_a, libunwind_a, emutls_a = tc.ensure_darwin_cxx_runtime()
        return [str(libcxx_a), str(libcxxabi_a), str(libunwind_a), str(emutls_a), str(tc.ensure_guest_libm_archive())], True
    if name in ("c++abi", "supc++", "c++abi-noexcept"):
        _, libcxxabi_a, libunwind_a, emutls_a = tc.ensure_darwin_cxx_runtime()
        return [str(libcxxabi_a), str(libunwind_a), str(emutls_a)], True
    if name == "unwind":
        _, _, libunwind_a, _ = tc.ensure_darwin_cxx_runtime()
        return [str(libunwind_a)], True
    if name == "m":
        return [str(tc.ensure_guest_libm_archive())], True
    if name in ("gcc", "gcc_s"):
        return [], True
    if name in BASE_OPENBSD_LIBS:
        return [], True
    return [], False


def macho_undefined_and_defined(tc: DarwinToolchain, obj_path: pathlib.Path) -> Tuple[Set[str], Set[str]]:
    senv = tc.sanitized_env()
    out = subprocess.check_output([*tc.nm_cmd, "-m", str(obj_path)], text=True, stderr=subprocess.DEVNULL, env=senv)
    undefs: Set[str] = set()
    defs: Set[str] = set()
    for ln in out.splitlines():
        s = ln.strip()
        if not s or s.endswith(":"):
            continue
        sym = s.split()[-1]
        if " (undefined) " in f" {s} ":
            undefs.add(sym)
        elif " external " in f" {s} " and "non-external" not in s:
            # Matches both `external` and `private external` (e.g. `-fvisibility=hidden` `_main`)
            defs.add(sym)
    return undefs, defs


def promote_macho_symbol_external(obj_path: pathlib.Path, sym_name: str) -> bool:
    """Clear `N_PEXT` (0x10) and set `N_EXT` (0x01) on `sym_name` in a 64-bit Mach-O `MH_OBJECT`."""
    import struct as _st

    data = bytearray(obj_path.read_bytes())
    if len(data) < 32:
        return False
    magic, _cpu, _sub, filetype, ncmds, _sz, _fl, _res = _st.unpack_from("<IIIIIIII", data, 0)
    if magic != 0xFEEDFACF or filetype != 1:
        return False
    off = 32
    symtab_off: Optional[int] = None
    for _ in range(ncmds):
        cmd, cmdsize = _st.unpack_from("<II", data, off)
        if cmd == 0x2:
            symtab_off = off
            break
        off += cmdsize
    if symtab_off is None:
        return False
    symoff, nsyms, stroff, strsize = _st.unpack_from("<IIII", data, symtab_off + 8)
    want = sym_name.encode("ascii")
    changed = False
    for idx in range(nsyms):
        rec = symoff + 16 * idx
        n_strx, n_type, n_sect, n_desc, n_val = _st.unpack_from("<IBBhQ", data, rec)
        if (n_type & 0xE0) != 0 or (n_type & 0x0E) != 0x0E or n_strx >= strsize:
            continue
        end = data.find(b"\x00", stroff + n_strx, stroff + strsize)
        if end < 0:
            continue
        if data[stroff + n_strx : end] == want:
            new_type = (n_type | 0x01) & ~0x10
            if new_type != n_type:
                _st.pack_into("<IBBhQ", data, rec, n_strx, new_type, n_sect, n_desc, n_val)
                changed = True
    if changed:
        obj_path.write_bytes(data)
    return changed


def retype_macho_init_section(
    tc: DarwinToolchain,
    obj_path: pathlib.Path,
    tmp_dir: pathlib.Path,
    slot: str = "0099",
) -> None:
    retype_dir = tc.obsd_root / "tools/build/personalities/openbsd/backends/translate"
    retype_py = retype_dir / "retype_guest_initializers.py"
    if str(retype_dir) not in sys.path:
        sys.path.insert(0, str(retype_dir))
    import retype_guest_initializers as rgi  # type: ignore

    senv = tc.sanitized_env()
    mobj = rgi.read_object(str(obj_path), obj_path.name)
    if mobj.terminator_sections():
        die(f"{obj_path}: holds forbidden Mach-O __mod_term_func section")
    if not mobj.initializer_sections():
        return
    valid_syms = [s for s in sorted(mobj.defined) if re.fullmatch(r"_[A-Za-z0-9_$.]+", s)]
    if not valid_syms:
        die(f"{obj_path}: has Mach-O initializer section but no defined symbol")
    pol = tmp_dir / f"init_{slot}.policy"
    pol.write_text(
        f"guest-retyped {slot} {obj_path.name} {valid_syms[0]} sdk/lib/obsd_toolchain.py:1#portinit\n",
        encoding="utf-8",
    )
    subprocess.run(
        [
            "/usr/bin/python3",
            "-I",
            "-B",
            str(retype_py),
            "--apply",
            "--policy",
            str(pol),
            "--member",
            obj_path.name,
            str(obj_path),
        ],
        env=senv,
        check=True,
    )


def extract_and_expose_retyped_ctors(
    obj_path: pathlib.Path,
    objcopy: pathlib.Path,
    senv: Dict[str, str],
) -> List[str]:
    """
    Inspect `__GUEST,__obsd_gi0098` (`libc++`) and `__GUEST,__obsd_gi0099` (port TUs)
    in `MH_OBJECT` `obj_path`, expose each referenced constructor function under a
    unique external symbol `___obsd_ctor_fn_<k>`, remove the `__GUEST,__obsd_gi009*`
    sections via `llvm-objcopy --remove-section`, and return the ordered C names
    `["__obsd_ctor_fn_0", ...]`.
    """
    import struct as _st

    data = bytearray(obj_path.read_bytes())
    magic, _cpu, _sub, filetype, ncmds, _szcmds, _hdrflags, _res = _st.unpack_from("<IIIIIIII", data, 0)
    if magic != 0xFEEDFACF or filetype != 1:
        die(f"{obj_path}: expected 64-bit Mach-O MH_OBJECT")

    gi_secs: Dict[str, Tuple[int, int, int, int]] = {}  # sectname -> (sect_idx_1based, offset, reloff, nreloc)
    symtab_off: Optional[int] = None
    sec_counter = 0
    off = 32
    for _ in range(ncmds):
        cmd, cmdsize = _st.unpack_from("<II", data, off)
        if cmd == 0x19:  # LC_SEGMENT_64
            nsects = _st.unpack_from("<I", data, off + 64)[0]
            soff = off + 72
            for _ in range(nsects):
                sec_counter += 1
                sectname = data[soff : soff + 16].rstrip(b"\x00").decode("ascii", "replace")
                segname = data[soff + 16 : soff + 32].rstrip(b"\x00").decode("ascii", "replace")
                size = _st.unpack_from("<Q", data, soff + 40)[0]
                file_offset, _align, reloff, nreloc = _st.unpack_from("<IIII", data, soff + 48)
                if segname == "__GUEST" and sectname in ("__obsd_gi0098", "__obsd_gi0099") and size > 0:
                    gi_secs[sectname] = (sec_counter, file_offset, reloff, nreloc)
                soff += 80
        elif cmd == 0x2:  # LC_SYMTAB
            symtab_off = off
        off += cmdsize

    if not gi_secs:
        return []
    if symtab_off is None:
        die(f"{obj_path}: missing LC_SYMTAB")

    symoff, nsyms, stroff, strsize = _st.unpack_from("<IIII", data, symtab_off + 8)
    trailing = data[stroff + strsize :]
    if any(b != 0 for b in trailing):
        die(f"{obj_path}: unexpected data after LC_SYMTAB string table")
    # Trim any trailing zero padding so appended strings start right at stroff + strsize
    del data[stroff + strsize :]

    sym_index_by_sect_addr: Dict[Tuple[int, int], int] = {}
    for sidx in range(nsyms):
        n_strx, n_type, n_sect, _n_desc, n_val = _st.unpack_from("<IBBhQ", data, symoff + 16 * sidx)
        if (n_type & 0xE0) == 0 and (n_type & 0x0E) == 0x0E:
            sym_index_by_sect_addr.setdefault((n_sect, n_val), sidx)

    ctor_c_names: List[str] = []
    symidx_to_cname: Dict[int, str] = {}

    for slot_sec in ("__obsd_gi0098", "__obsd_gi0099"):
        if slot_sec not in gi_secs:
            continue
        _sidx1, file_offset, reloff, nreloc = gi_secs[slot_sec]
        relocs: List[Tuple[int, int, int]] = []
        for r in range(nreloc):
            r_addr, word1 = _st.unpack_from("<iI", data, reloff + 8 * r)
            r_symnum = word1 & 0xFFFFFF
            r_extern = (word1 >> 27) & 1
            relocs.append((r_addr, r_extern, r_symnum))
        relocs.sort(key=lambda x: x[0])

        for r_addr, r_extern, r_symnum in relocs:
            if r_extern == 1:
                target_sidx = r_symnum
            else:
                inline_val = _st.unpack_from("<Q", data, file_offset + r_addr)[0]
                target_sidx = sym_index_by_sect_addr.get((r_symnum, inline_val), -1)
                if target_sidx < 0:
                    die(f"{obj_path}: non-extern initializer relocation at +{r_addr} has no matching symbol")

            if target_sidx not in symidx_to_cname:
                cname = f"__obsd_ctor_fn_{len(symidx_to_cname)}"
                macho_bytes = f"_{cname}\x00".encode("ascii")
                new_strx = len(data) - stroff
                data.extend(macho_bytes)
                rec_pos = symoff + 16 * target_sidx
                _old_strx, n_type, n_sect, n_desc, n_val = _st.unpack_from("<IBBhQ", data, rec_pos)
                # Export as external N_SECT (clear N_PEXT 0x10, set N_EXT 0x01)
                new_ntype = (n_type | 0x01) & ~0x10
                _st.pack_into("<IBBhQ", data, rec_pos, new_strx, new_ntype, n_sect, n_desc, n_val)
                symidx_to_cname[target_sidx] = cname
            ctor_c_names.append(symidx_to_cname[target_sidx])

    new_strsize = len(data) - stroff
    while len(data) % 8 != 0:
        data.append(0)
        new_strsize += 1
    _st.pack_into("<IIII", data, symtab_off + 8, symoff, nsyms, stroff, new_strsize)
    obj_path.write_bytes(data)

    rm_args = [f"--remove-section=__GUEST,{sec}" for sec in gi_secs]
    subprocess.run([str(objcopy), *rm_args, str(obj_path)], env=senv, check=True)
    return ctor_c_names


def retype_and_wrap_macho_ctors(
    tc: DarwinToolchain,
    partial_obj: pathlib.Path,
    tmp_dir: pathlib.Path,
    target_flags: Sequence[str],
    prepend_cxx_rt_init: bool = False,
) -> None:
    """
    Ensure `partial_obj` contains ZERO `__DATA,__mod_init_func` or `__GUEST,__obsd_gi*`
    sections by retyping via `retype_guest_initializers.py` and converting every
    constructor entry (`libc++` 0098 first, port TUs 0099 second) into direct
    function calls inside `main` AFTER guest TIB/VFS/heap startup.
    """
    retype_dir = tc.obsd_root / "tools/build/personalities/openbsd/backends/translate"
    if str(retype_dir) not in sys.path:
        sys.path.insert(0, str(retype_dir))
    import retype_guest_initializers as rgi  # type: ignore

    senv = tc.sanitized_env()
    mobj = rgi.read_object(str(partial_obj), partial_obj.name)
    if mobj.terminator_sections():
        die(f"{partial_obj}: holds forbidden Mach-O __mod_term_func section")
    if mobj.initializer_sections():
        retype_macho_init_section(tc, partial_obj, tmp_dir, slot="0099")
        mobj = rgi.read_object(str(partial_obj), partial_obj.name)

    present_gi = [
        s.sectname
        for s in mobj.sections
        if s.segname == "__GUEST" and s.sectname in ("__obsd_gi0098", "__obsd_gi0099") and s.size > 0
    ]
    if not present_gi and not prepend_cxx_rt_init:
        return

    _, defs = macho_undefined_and_defined(tc, partial_obj)
    entry_sym: Optional[str] = None
    for cand in ("_obsd_tool_main", "_main"):
        if cand in defs:
            entry_sym = cand
            break
    if entry_sym is None:
        return

    objcopy = tc.find_llvm_objcopy()
    ctor_c_names = extract_and_expose_retyped_ctors(partial_obj, objcopy, senv) if present_gi else []
    if not ctor_c_names and not prepend_cxx_rt_init:
        return

    real_main_macho = "___obsd_port_ctor_real_main"
    subprocess.run([str(objcopy), "--redefine-sym", f"{entry_sym}={real_main_macho}", str(partial_obj)], env=senv, check=True)

    unique_ctors = list(dict.fromkeys(ctor_c_names))
    entry_c = entry_sym[1:]
    wrap_c = tmp_dir / "gi_wrap.c"
    wrap_o = tmp_dir / "gi_wrap.o"
    wrap_c.write_text(
        "\n".join(
            [
                *(["extern void __obsd_cxx_rt_init(void);"] if prepend_cxx_rt_init else []),
                *[f"extern void {cn}(void);" for cn in unique_ctors],
                "extern int __obsd_port_ctor_real_main(int, char **, char **);",
                f"int {entry_c}(int argc, char **argv, char **envp);",
                f"int {entry_c}(int argc, char **argv, char **envp) {{",
                *(["\t__obsd_cxx_rt_init();"] if prepend_cxx_rt_init else []),
                *[f"\t{cn}();" for cn in ctor_c_names],
                "\treturn __obsd_port_ctor_real_main(argc, argv, envp);",
                "}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    subprocess.run(
        [*tc.cc_compile_cmd, *target_flags, "-arch", "arm64", "-ffixed-x18", "-fno-omit-frame-pointer", "-fno-stack-protector", "-fno-common", "-O2", "-c", str(wrap_c), "-o", str(wrap_o)],
        env=senv,
        check=True,
    )

    wrapped_o = tmp_dir / "gi_wrapped.o"
    subprocess.run(
        [
            *tc.cc_cmd,
            *target_flags,
            "-arch",
            "arm64",
            "-nostdlib",
            "-Wl,-r,-S",
            str(wrap_o),
            str(partial_obj),
            "-o",
            str(wrapped_o),
        ],
        env=senv,
        check=True,
    )
    loc_args = ["--localize-symbol=___obsd_port_ctor_real_main", *[f"--localize-symbol=_{cn}" for cn in unique_ctors]]
    subprocess.run([str(objcopy), *loc_args, str(wrapped_o)], env=senv, stderr=subprocess.DEVNULL, check=False)
    wrapped_o.replace(partial_obj)


def macho_has_nonempty_data_section(obj_path: pathlib.Path) -> bool:
    """Fast pure-Python check whether a 64-bit Mach-O `.o` has a non-empty `__DATA,__data` section."""
    try:
        with obj_path.open("rb") as fp:
            buf = fp.read(16384)
    except OSError:
        return False
    if len(buf) < 32:
        return False
    magic, _cpu, _sub, _ft, ncmds, _szcmds, _fl, _res = struct.unpack_from("<8I", buf, 0)
    if magic != 0xFEEDFACF:
        return False
    off = 32
    for _ in range(ncmds):
        if off + 8 > len(buf):
            break
        cmd, cmdsize = struct.unpack_from("<2I", buf, off)
        if cmdsize < 8 or off + cmdsize > len(buf):
            break
        if cmd == 0x19 and cmdsize >= 72:
            nsects = struct.unpack_from("<2I16s4Q4I", buf, off)[9]
            soff = off + 72
            for _s in range(nsects):
                if soff + 80 > off + cmdsize:
                    break
                sect_b, seg_b, _addr, sz = struct.unpack_from("<16s16s2Q", buf, soff)
                if seg_b.rstrip(b"\x00") == b"__DATA" and sect_b.rstrip(b"\x00") == b"__data" and sz > 0:
                    return True
                soff += 80
        off += cmdsize
    return False


def relocate_emulate_emutls_data(
    tc: DarwinToolchain, obj_path: pathlib.Path, target_flags: List[str], senv: Dict[str, str]
) -> None:
    """
    When `-femulated-tls` lowers a `static __thread` variable in Stage 3 codegen,
    its read-only `___emutls_v.*` descriptor lands in `__DATA,__data` (`libobsd_emutls.a`
    never mutates `*ctrl`). Move `__DATA,__data` -> `__GUEST_INIT,__data` ONLY when
    100% of symbols in `(__DATA,__data)` are `___emutls_v.*` (or assembler temp `ltmp*`).
    """
    if tc.backend != "emulate" or not macho_has_nonempty_data_section(obj_path):
        return
    nm_out = subprocess.check_output([*tc.nm_cmd, "-m", str(obj_path)], text=True, env=senv)
    data_syms = [
        ln.strip().split()[-1]
        for ln in nm_out.splitlines()
        if "(__DATA,__data)" in ln and "(undefined)" not in ln
    ]
    if not data_syms or not all(s.startswith(("___emutls_v.", "ltmp")) for s in data_syms):
        return
    tmp_o = obj_path.parent / f".{obj_path.name}.{os.getpid()}.emutls.o"
    subprocess.run(
        [
            *tc.cc_cmd,
            *target_flags,
            "-arch",
            "arm64",
            "-nostdlib",
            "-Wl,-r,-S,-keep_private_externs,-rename_section,__DATA,__data,__GUEST_INIT,__data",
            str(obj_path),
            "-o",
            str(tmp_o),
        ],
        env=senv,
        check=True,
    )
    tmp_o.replace(obj_path)


def run_darwin_cc_driver(argv: List[str], is_cxx: bool) -> int:
    tc = DarwinToolchain()
    senv = tc.sanitized_env()
    compiler_cmd = tc.cxx_cmd if is_cxx else tc.cc_cmd

    if not argv:
        return subprocess.run(compiler_cmd, env=senv).returncode

    if len(argv) == 1 and argv[0] == "-dumpmachine":
        print(f"aarch64-unknown-openbsd{tc.openbsd_version}")
        return 0

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
        elif a in ("-shared", "-dynamiclib"):
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
        elif a in ("-I", "-isystem", "-iquote", "-idirafter", "-include", "-L", "-l", "-MF", "-MT", "-MQ", "-D", "-U", "-arch", "-target", "-isysroot") and i + 1 < len(argv):
            i += 2
            continue
        elif a == "-" and explicit_lang is not None:
            has_inputs = True
        elif not a.startswith("-"):
            has_inputs = True
        i += 1

    if not has_inputs:
        target_flags = shlex.split(tc.emulate_info["target_flags"]) if tc.backend == "emulate" else ["-arch", "arm64"]
        # Autoconf probes `$CC -V` / `$CC -qversion` expecting failure
        if any(x in argv for x in ("-V", "-qversion")):
            return subprocess.run([*compiler_cmd, *argv], env=senv).returncode
        return subprocess.run([*compiler_cmd, *target_flags, *argv], env=senv).returncode

    compile_user_args: List[str] = []
    non_src_compile_args: List[str] = []
    lib_dirs: List[str] = []
    link_items: List[Tuple[str, str]] = []
    dep_args: List[str] = []
    cur_lang: Optional[str] = None
    all_inputs_asm = True
    saw_source_input = False

    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "-o" and i + 1 < len(argv):
            i += 2
            continue
        if a.startswith("-o") and len(a) > 2:
            i += 1
            continue
        if a in (
            "-fPIC",
            "-fpic",
            "-fPIE",
            "-fpie",
            "-pie",
            "-no-pie",
            "-rdynamic",
            "-static",
            "-shared",
            "-dynamiclib",
            "-s",
            "-fomit-frame-pointer",
        ):
            i += 1
            continue
        if a in ("-pthread", "-pthreads"):
            i += 1
            continue
        # Strip any host `-D__APPLE__` or `-arch` duplicates passed by upstream build systems
        if a == "-arch" and i + 1 < len(argv):
            i += 2
            continue
        if a in ("-I", "-isystem", "-iquote", "-idirafter") and i + 1 < len(argv):
            remapped = tc.remap_include_dir(argv[i + 1])
            if remapped:
                compile_user_args.extend([a, remapped])
                non_src_compile_args.extend([a, remapped])
            i += 2
            continue
        if a.startswith("-I") and len(a) > 2:
            remapped = tc.remap_include_dir(a[2:])
            if remapped:
                compile_user_args.extend(["-I", remapped])
                non_src_compile_args.extend(["-I", remapped])
            i += 1
            continue
        if a.startswith("-isystem") and len(a) > len("-isystem"):
            remapped = tc.remap_include_dir(a[len("-isystem") :])
            if remapped:
                compile_user_args.extend(["-isystem", remapped])
                non_src_compile_args.extend(["-isystem", remapped])
            i += 1
            continue
        if a in ("-include", "-imacros", "-D", "-U", "-Xclang", "-mllvm", "-isysroot", "-target") and i + 1 < len(argv):
            compile_user_args.extend([a, argv[i + 1]])
            non_src_compile_args.extend([a, argv[i + 1]])
            i += 2
            continue
        if a == "-L" and i + 1 < len(argv):
            remapped_l = tc.remap_lib_dir(argv[i + 1])
            if remapped_l:
                lib_dirs.append(remapped_l)
            i += 2
            continue
        if a.startswith("-L") and len(a) > 2:
            remapped_l = tc.remap_lib_dir(a[2:])
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
                    rl = tc.remap_lib_dir(tok[2:])
                    if rl:
                        lib_dirs.append(rl)
                    idx_w += 1
                    continue
                if tok.startswith("-l") and len(tok) > 2:
                    link_items.append(("lib", tok[2:]))
                    idx_w += 1
                    continue
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
            non_src_compile_args.extend([a, cur_lang])
            i += 2
            continue
        if a.startswith("-x") and len(a) > 2:
            cur_lang = a[2:]
            compile_user_args.append(a)
            non_src_compile_args.append(a)
            i += 1
            continue
        if (a == "-" and cur_lang is not None) or (
            cur_lang in ("c", "c++", "assembler", "assembler-with-cpp") and not a.startswith("-")
        ):
            saw_source_input = True
            if cur_lang not in ("assembler", "assembler-with-cpp"):
                all_inputs_asm = False
            link_items.append(("src", a))
            compile_user_args.append(a)
            i += 1
            continue
        if is_source_file(a):
            saw_source_input = True
            if not is_asm_source(a):
                all_inputs_asm = False
            link_items.append(("src", a))
            compile_user_args.append(a)
            i += 1
            continue
        if is_object_or_archive(a):
            link_items.append(("obj", resolve_lo_file(a)))
            i += 1
            continue
        compile_user_args.append(a)
        if a not in ("-c", "-S"):
            non_src_compile_args.append(a)
        i += 1

    asm_mode = saw_source_input and all_inputs_asm
    prefix_cf, suffix_cf = tc.split_compile_flags(
        is_cxx=is_cxx, preprocess_only=mode_preprocess, is_asm=asm_mode
    )
    target_flags = shlex.split(tc.emulate_info["target_flags"]) if tc.backend == "emulate" else []

    # Mode 1: Preprocess / Compile-only (`-E`, `-M`, `-MM`, `-c`, `-S`)
    compile_driver_cmd = tc.cxx_compile_cmd if is_cxx else tc.cc_compile_cmd
    if mode_preprocess or mode_compile_only:
        if mode_preprocess or asm_mode or "-S" in argv or not saw_source_input:
            cmd = [*compiler_cmd, *prefix_cf, *compile_user_args, *dep_args, *suffix_cf]
            if mode_compile_only and "-c" not in compile_user_args and "-S" not in compile_user_args:
                cmd.append("-S" if "-S" in argv else "-c")
            if output_path is not None:
                cmd.extend(["-o", output_path])
            return subprocess.run(cmd, env=senv).returncode

        # Compile each C/C++ source TU individually with explicit `-c` and `-o <out_o>`
        # so `compile_guest_banked_darwin.sh` NEVER falls back to unbanked passthrough
        # when a port's Makefile omits `-o` (`cc -c foo.c`) or passes multiple sources!
        src_inputs = [val for kind, val in link_items if kind == "src"]
        for src in src_inputs:
            out_o = (
                output_path
                if (output_path is not None and len(src_inputs) == 1)
                else ((os.path.splitext(os.path.basename(src))[0] + ".o") if src != "-" else "stdin.o")
            )
            tu_is_asm = is_asm_source(src) or cur_lang in ("assembler", "assembler-with-cpp")
            tu_pref, tu_suf = (
                tc.split_compile_flags(is_cxx=False, preprocess_only=False, is_asm=True)
                if tu_is_asm
                else (prefix_cf, suffix_cf)
            )
            c_cmd = [
                *(tc.cc_cmd if tu_is_asm else compile_driver_cmd),
                "-c",
                *tu_pref,
                *non_src_compile_args,
                *(dep_args if len(src_inputs) == 1 else []),
                src,
                *tu_suf,
                "-o",
                out_o,
            ]
            rc = subprocess.run(c_cmd, env=senv).returncode
            if rc != 0:
                return rc
            if tc.backend == "emulate" and not tu_is_asm and out_o != "/dev/null":
                relocate_emulate_emutls_data(tc, pathlib.Path(out_o), target_flags, senv)
        return 0

    # Mode 2: Link mode (`translate` standalone Mach-O binary OR `emulate` relocatable `.o`)
    out_file = pathlib.Path(output_path or "a.out")
    compile_only_flags = non_src_compile_args

    with tempfile.TemporaryDirectory(prefix="obsd-darwin-cc-") as tmpdir:
        tmp_p = pathlib.Path(tmpdir)
        ld_inputs: List[str] = []
        ld_extra_flags: List[str] = []
        src_idx = 0

        for kind, val in link_items:
            if kind == "src":
                tmp_obj = tmp_p / f"tu_{src_idx:03d}.o"
                src_idx += 1
                tu_is_asm = is_asm_source(val) or cur_lang in ("assembler", "assembler-with-cpp")
                tu_pref, tu_suf = (
                    tc.split_compile_flags(is_cxx=False, preprocess_only=False, is_asm=True)
                    if tu_is_asm
                    else (prefix_cf, suffix_cf)
                )
                c_cmd = [
                    *(tc.cc_cmd if tu_is_asm else compile_driver_cmd),
                    "-c",
                    *tu_pref,
                    *compile_only_flags,
                    *(dep_args if len([k for k, _ in link_items if k == "src"]) == 1 else []),
                    val,
                    *tu_suf,
                    "-o",
                    str(tmp_obj),
                ]
                rc = subprocess.run(c_cmd, env=senv).returncode
                if rc != 0:
                    return rc
                if tc.backend == "emulate" and not tu_is_asm:
                    relocate_emulate_emutls_data(tc, tmp_obj, target_flags, senv)
                ld_inputs.append(str(tmp_obj))
            elif kind == "obj":
                ld_inputs.append(val)
            elif kind == "lib":
                resolved_ars, ok = resolve_darwin_library(tc, val, lib_dirs, tc.stage_dir / "usr/local/lib")
                if not ok:
                    sys.stderr.write(f"obsd-ld: error: unable to find library -l{val}\n")
                    return 1
                for ar_p in resolved_ars:
                    if ar_p not in ld_inputs:
                        ld_inputs.append(ar_p)
            elif kind == "ldflag":
                ld_extra_flags.append(val)

        if not ld_inputs:
            sys.stderr.write("obsd-ld: error: no input files\n")
            return 1

        no_default_cxx = any(f in argv for f in ("-nostdlib", "-nostdlib++", "-nodefaultlibs"))
        cxx_rt_archives: List[str] = []
        extra_em_m = [str(tc.ensure_emulate_libm_archive())] if tc.backend == "emulate" else []
        if is_cxx and not no_default_cxx:
            libcxx_a, libcxxabi_a, libunwind_a, emutls_a = tc.ensure_darwin_cxx_runtime()
            cxx_rt_archives = [str(libcxx_a), str(libcxxabi_a), str(libunwind_a), str(emutls_a), *extra_em_m]
        elif any(os.path.basename(x).startswith(("libc++.", "libc++-")) for x in ld_inputs):
            _, libcxxabi_a, libunwind_a, emutls_a = tc.ensure_darwin_cxx_runtime()
            cxx_rt_archives = [str(libcxxabi_a), str(libunwind_a), str(emutls_a), *extra_em_m]

        # Separate any explicit SDK C++ archives out of `ld_inputs` so user-TU
        # `__DATA,__mod_init_func` is retyped to slot 0099 BEFORE merging `libc++.a` (slot 0098).
        sdk_cache_prefix = str(tc.cache_dir) + "/"
        user_ld_inputs: List[str] = []
        deferred_rt_inputs: List[str] = []
        for inp in ld_inputs:
            if inp.startswith(sdk_cache_prefix):
                if inp not in deferred_rt_inputs:
                    deferred_rt_inputs.append(inp)
            else:
                user_ld_inputs.append(inp)
        for ar_p in cxx_rt_archives:
            if ar_p not in deferred_rt_inputs:
                deferred_rt_inputs.append(ar_p)

        # Step A1: Partial-link user/port objects & archives (`ld -r -S -keep_private_externs`)
        # `-keep_private_externs` preserves `_main` when a port builds with `-fvisibility=hidden`!
        user_partial = tmp_p / "user_partial.o"
        wl_extra = [f"-Wl,{fl}" for fl in ld_extra_flags]
        p_cmd = [
            *tc.cc_cmd,
            *target_flags,
            "-arch",
            "arm64",
            "-nostdlib",
            "-Wl,-r,-S,-keep_private_externs",
            *wl_extra,
            *user_ld_inputs,
            "-o",
            str(user_partial),
        ]
        p_proc = subprocess.run(p_cmd, env=senv)
        if p_proc.returncode != 0:
            return p_proc.returncode

        if not is_shared:
            retype_macho_init_section(tc, user_partial, tmp_p, slot="0099")

        # Step A2: On `translate`, merge SDK C++ runtime archives directly into each standalone binary.
        # On `emulate`, defer `(libc++.a, libc++abi.a, libunwind.a)` to the lane-wide `shared/darwin_cxx_rt.o`
        # so all C++ applets share a single `___gxx_personality_v0` inside `SonvoriBSD_<ver>.framework`!
        need_shared_cxx_rt = bool(deferred_rt_inputs) and tc.backend == "emulate"
        if deferred_rt_inputs and tc.backend != "emulate":
            user_with_rt = tmp_p / "user_with_rt.o"
            prt = subprocess.run(
                [
                    *tc.cc_cmd,
                    *target_flags,
                    "-arch",
                    "arm64",
                    "-nostdlib",
                    "-Wl,-r,-S,-keep_private_externs",
                    str(user_partial),
                    *deferred_rt_inputs,
                    "-o",
                    str(user_with_rt),
                ],
                env=senv,
            )
            if prt.returncode != 0:
                return prt.returncode
            user_with_rt.replace(user_partial)

        # Pull in guest libm/regex/POSIX/int128 support and (for non-C++ partials) libobsd_emutls.a
        undefs, defs = macho_undefined_and_defined(tc, user_partial)
        supplemental_ars: List[str] = []
        if (undefs & tc.guest_sup_defined_symbols()) - defs:
            supplemental_ars.append(str(tc.ensure_guest_libm_archive()))
        if not need_shared_cxx_rt and "___emutls_get_address" in undefs and "___emutls_get_address" not in defs:
            supplemental_ars.append(str(tc.ensure_emutls_archive()))
        if supplemental_ars:
            user_partial2 = tmp_p / "user_partial2.o"
            p2 = subprocess.run(
                [
                    *tc.cc_cmd,
                    *target_flags,
                    "-arch",
                    "arm64",
                    "-nostdlib",
                    "-Wl,-r,-S,-keep_private_externs",
                    str(user_partial),
                    *supplemental_ars,
                    "-o",
                    str(user_partial2),
                ],
                env=senv,
            )
            if p2.returncode != 0:
                return p2.returncode
            user_partial2.replace(user_partial)

        if not is_shared:
            retype_and_wrap_macho_ctors(
                tc,
                user_partial,
                tmp_p,
                target_flags,
                prepend_cxx_rt_init=need_shared_cxx_rt,
            )
            # Ensure `_main` / `_obsd_tool_main` is promoted from `private external` to `external`
            for msym in ("_obsd_tool_main", "_main"):
                promote_macho_symbol_external(user_partial, msym)

        out_file.parent.mkdir(parents=True, exist_ok=True)
        tmp_out = out_file.parent / f".{out_file.name}.{os.getpid()}.macho.tmp"

        if not is_shared:
            undefs, defs = macho_undefined_and_defined(tc, user_partial)
            if "_dlopen" in undefs and "_dlopen" not in defs:
                sys.stderr.write("obsd-ld: error: undefined symbol: _dlopen (disabled by guest policy)\n")
                return 1
            if not ({"_main", "_obsd_tool_main"} & defs):
                sys.stderr.write("obsd-ld: error: undefined symbol: _main\n")
                return 1
            allowed = tc.allowed_guest_undefined_symbols()
            if need_shared_cxx_rt:
                allowed = allowed | tc.darwin_cxx_rt_defined_symbols()
            missing = sorted(s for s in (undefs - defs) if s not in allowed)
            if missing:
                for sym in missing[:25]:
                    sys.stderr.write(f"obsd-ld: error: undefined symbol: {sym}\n")
                if len(missing) > 25:
                    sys.stderr.write(f"obsd-ld: error: ... and {len(missing) - 25} more undefined symbols\n")
                return 1

        if tc.backend == "emulate" or is_shared:
            shutil.copy2(user_partial, tmp_out)
            tmp_out.chmod(0o755)
            tmp_out.replace(out_file)
            return 0

        if "_main" in defs and "_obsd_tool_main" not in defs:
            objcopy = tc.find_llvm_objcopy()
            subprocess.run(
                [str(objcopy), "--redefine-sym", "_main=_obsd_tool_main", str(user_partial)],
                env=senv,
                check=True,
            )

        rodata_toks = shlex.split(tc.translate_info.get("rodata_ldflags", ""))
        final_cmd = [
            *tc.cc_cmd,
            "-arch",
            "arm64",
            "-ffixed-x18",
            str(user_partial),
            *tc.translate_info["link_flags"],
            *rodata_toks,
            str(tc.base_archive),
            str(tc.ensure_guest_libm_archive()),
            "-Wl,-dead_strip",
            "-Wl,-S",
            "-o",
            str(tmp_out),
        ]
        f_proc = subprocess.run(final_cmd, env=senv)
        if f_proc.returncode != 0:
            tmp_out.unlink(missing_ok=True)
            return f_proc.returncode

        otool_out = subprocess.check_output(
            ["/usr/bin/xcrun", "--sdk", tc.sdk, "otool", "-L", str(tmp_out)],
            text=True,
            env=senv,
        )
        for ln in otool_out.splitlines()[1:]:
            dep = ln.strip().split(" (", 1)[0]
            if dep and ("libc++" in dep or not (dep.startswith("/usr/lib/libSystem") or dep.startswith("/System/Library/Frameworks/"))):
                tmp_out.unlink(missing_ok=True)
                die(f"linked binary imported forbidden host library '{dep}'")

        tmp_out.chmod(0o755)
        subprocess.run(
            ["/usr/bin/codesign", "--force", "--sign", "-", str(tmp_out)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=senv,
            check=True,
        )
        tmp_out.replace(out_file)
        return 0


# ============================================================================
# Shared SDK Utilities (`pkg-config`, `strip`, `install`, `ar`, `ranlib`, `nm`, `ld`)
# ============================================================================


def ensure_base_pkgconfig_dir(cache_dir: pathlib.Path, openbsd_version: str) -> pathlib.Path:
    pc_dir = cache_dir / f"base-pkgconfig-{openbsd_version}"
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


def current_stage_and_cache() -> Tuple[str, pathlib.Path, pathlib.Path]:
    ver = obsd_versions.env_or_default_version()
    backend = os.environ.get("COMPAT_BACKEND", "emulate").strip() or "emulate"
    pal = os.environ.get("COMPAT_PAL", "emscripten").strip() or "emscripten"
    sdk = default_sdk_for(pal, backend)
    lane_leaf = f"darwin-{sdk}" if pal == "darwin" else pal
    stage_env = os.environ.get("OBSD_STAGE_DIR", "").strip()
    stage_dir = (
        pathlib.Path(stage_env).resolve()
        if stage_env
        else (REPO_ROOT / "build/openbsd" / ver / backend / lane_leaf / "stage").resolve()
    )
    cache_dir = REPO_ROOT / ".cache/sdk"
    cache_dir.mkdir(parents=True, exist_ok=True)
    return ver, stage_dir, cache_dir


def run_pkg_config(argv: List[str]) -> int:
    host_pc = shutil.which("pkg-config")
    if not host_pc:
        die("host pkg-config executable not found")
    ver, stage_dir, cache_dir = current_stage_and_cache()
    backend = os.environ.get("COMPAT_BACKEND", "emulate").strip() or "emulate"
    pal = os.environ.get("COMPAT_PAL", "emscripten").strip() or "emscripten"
    x11_dir = resolve_active_x11_build_dir(ver, backend, pal)
    base_pc_dir = ensure_base_pkgconfig_dir(cache_dir, ver)
    search_dirs = [
        str(stage_dir / "usr/local/lib/pkgconfig"),
        str(stage_dir / "usr/local/share/pkgconfig"),
    ]
    if x11_dir is not None:
        search_dirs.extend(
            [
                str(x11_dir / "sdk/usr/X11R6/lib/pkgconfig"),
                str(x11_dir / "sdk/usr/X11R6/share/pkgconfig"),
            ]
        )
    search_dirs.append(str(base_pc_dir))
    env = dict(os.environ)
    env.pop("PKG_CONFIG_PATH", None)
    env["PKG_CONFIG_LIBDIR"] = ":".join(search_dirs)
    cmd = [host_pc]
    if "--static" not in argv:
        cmd.append("--static")
    cmd.extend(argv)
    return subprocess.run(cmd, env=env).returncode


def run_strip(argv: List[str]) -> int:
    """No-op strip preserving relocatable sections & ad-hoc signatures during port install;
    final packaging (`package_darwin.py` / `package_wasm.py`) strips & signs cleanly."""
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
    """Wrap `/usr/bin/install`, dropping `-s` / `--strip` so relocatable objects & ad-hoc signatures stay intact."""
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
            if a[1] not in ("m", "o", "g", "S", "t", "D"):
                stripped_flag = "-" + a[1:].replace("s", "")
                if stripped_flag != "-":
                    cleaned.append(stripped_flag)
                i += 1
                continue
        cleaned.append(a)
        i += 1
    return subprocess.run([real_install, *cleaned]).returncode


def unpack_ar_macho_objects(ar_path: pathlib.Path, dest_dir: pathlib.Path, prefix: str) -> List[str]:
    """Extract all Mach-O `.o` members from a static `!<arch>` archive into `dest_dir`."""
    data = ar_path.read_bytes()
    if not data.startswith(b"!<arch>\n"):
        return []
    out_objs: List[str] = []
    pos = 8
    idx = 0
    n = len(data)
    while pos + 60 <= n:
        if pos % 2 == 1:
            pos += 1
            if pos + 60 > n:
                break
        hdr = data[pos : pos + 60]
        if hdr[58:60] != b"`\n":
            break
        name_raw = hdr[0:16].decode("latin1")
        try:
            size = int(hdr[48:58].decode("ascii").strip())
        except ValueError:
            break
        payload_start = pos + 60
        payload_end = payload_start + size
        if payload_end > n:
            break
        if name_raw.startswith("#1/"):
            try:
                ext_len = int(name_raw[3:].strip())
            except ValueError:
                ext_len = 0
            member_name = data[payload_start : payload_start + ext_len].rstrip(b"\x00 ").decode("latin1", "replace")
            obj_bytes = data[payload_start + ext_len : payload_end]
        else:
            member_name = name_raw.rstrip(" /")
            obj_bytes = data[payload_start:payload_end]

        if len(obj_bytes) >= 4 and obj_bytes[:4] in MACHO_MAGICS:
            safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", os.path.basename(member_name) or "obj.o")
            if not safe.endswith(".o"):
                safe += ".o"
            out_p = dest_dir / f"{prefix}_{idx:04d}_{safe}"
            out_p.write_bytes(obj_bytes)
            out_objs.append(str(out_p))
            idx += 1
        elif obj_bytes.startswith(b"!<arch>\n"):
            sub_ar = dest_dir / f"{prefix}_{idx:04d}_nested.a"
            sub_ar.write_bytes(obj_bytes)
            out_objs.extend(unpack_ar_macho_objects(sub_ar, dest_dir, f"{prefix}_{idx:04d}"))
            idx += 1

        pos = payload_end
    return out_objs


def run_darwin_ar(tc: DarwinToolchain, rest: List[str]) -> int:
    """
    Wrap Apple `xcrun ar` so GNU `ar` flags (`--plugin`, `D`/`U`) and GNU `libtool`
    nested `.a` convenience-library members (e.g. `obsd-ar cr libfoo.a libbar.a x.o`)
    flatten cleanly into pure Mach-O `.o` archive members.
    """
    senv = tc.sanitized_env()
    args: List[str] = []
    i = 0
    while i < len(rest):
        a = rest[i]
        if a == "--plugin" and i + 1 < len(rest):
            i += 2
            continue
        if a.startswith("--plugin="):
            i += 1
            continue
        args.append(a)
        i += 1

    if not args:
        return subprocess.run(tc.ar_cmd, env=senv).returncode

    mode = args[0]
    lead_dash = "-" if mode.startswith("-") else ""
    mode_chars = mode.lstrip("-")
    # Strip GNU deterministic/non-deterministic `D`/`U` modifiers rejected by BSD `ar`
    if any(op in mode_chars for op in ("r", "q", "c", "s", "d", "t", "x", "p", "m")):
        cleaned_chars = "".join(ch for ch in mode_chars if ch not in ("D", "U"))
        if cleaned_chars:
            mode = lead_dash + cleaned_chars
            mode_chars = cleaned_chars
            args[0] = mode

    ar_idx = 2 if any(ch in mode_chars for ch in ("a", "b", "i")) else 1
    is_insert = any(ch in mode_chars for ch in ("r", "q")) and not any(
        ch in mode_chars for ch in ("d", "t", "x", "p", "m")
    )
    if not is_insert or len(args) <= ar_idx + 1:
        return subprocess.run([*tc.ar_cmd, *args], env=senv).returncode

    prefix_args = args[: ar_idx + 1]
    raw_members = args[ar_idx + 1 :]
    has_nested_ar = False
    resolved_members: List[str] = []
    for m in raw_members:
        rm = resolve_lo_file(m)
        resolved_members.append(rm)
        mp = pathlib.Path(rm)
        if mp.is_file():
            try:
                with mp.open("rb") as fp:
                    if fp.read(8) == b"!<arch>\n":
                        has_nested_ar = True
            except OSError:
                pass

    if not has_nested_ar:
        return subprocess.run([*tc.ar_cmd, *prefix_args, *resolved_members], env=senv).returncode

    with tempfile.TemporaryDirectory(prefix="obsd-darwin-ar-") as td:
        tp = pathlib.Path(td)
        flat_members: List[str] = []
        for idx_m, rm in enumerate(resolved_members):
            mp = pathlib.Path(rm)
            is_ar = False
            if mp.is_file():
                try:
                    with mp.open("rb") as fp:
                        is_ar = fp.read(8) == b"!<arch>\n"
                except OSError:
                    is_ar = False
            if is_ar:
                flat_members.extend(unpack_ar_macho_objects(mp, tp, f"ar{idx_m}"))
            else:
                flat_members.append(rm)
        if not flat_members:
            # Create valid empty BSD archive if all nested `.a` inputs were empty
            pathlib.Path(args[ar_idx]).write_bytes(b"!<arch>\n")
            return 0
        return subprocess.run([*tc.ar_cmd, *prefix_args, *flat_members], env=senv).returncode


def run_cc_driver(argv: List[str], is_cxx: bool) -> int:
    pal = os.environ.get("COMPAT_PAL", "emscripten").strip() or "emscripten"
    if pal == "darwin":
        return run_darwin_cc_driver(argv, is_cxx=is_cxx)
    return run_emscripten_cc_driver(argv, is_cxx=is_cxx)


def main() -> int:
    if len(sys.argv) < 2:
        die("usage: obsd_toolchain.py <tool> [args...]")
    tool = sys.argv[1]
    rest = sys.argv[2:]
    pal = os.environ.get("COMPAT_PAL", "emscripten").strip() or "emscripten"

    if tool == "cc":
        return run_cc_driver(rest, is_cxx=False)
    if tool == "cxx":
        return run_cc_driver(rest, is_cxx=True)
    if tool == "strip":
        return run_strip(rest)
    if tool == "pkg-config":
        return run_pkg_config(rest)
    if tool == "install":
        return run_install_wrapper(rest)

    if pal == "darwin":
        tc = DarwinToolchain()
        senv = tc.sanitized_env()
        if tool == "ar":
            return run_darwin_ar(tc, rest)
        if tool == "ranlib":
            filtered = [a for a in rest if a != "-t"]
            if not filtered:
                return 0
            return subprocess.run([*tc.ranlib_cmd, *filtered], env=senv).returncode
        if tool == "nm":
            return subprocess.run([*tc.nm_cmd, *rest], env=senv).returncode
        if tool == "ld":
            cmd = list(tc.ld_cmd)
            if "-arch" not in rest:
                cmd.extend(["-arch", "arm64"])
            if "-r" in rest and "-S" not in rest:
                cmd.append("-S")
            cmd.extend(rest)
            return subprocess.run(cmd, env=senv).returncode
        die(f"unknown SDK tool mode: {tool}")

    ctx = EmscriptenToolchain()
    if tool == "ar":
        return subprocess.run([str(ctx.emar), *rest]).returncode
    if tool == "ranlib":
        filtered = [a for a in rest if a != "-t"]
        if not filtered:
            return 0
        return subprocess.run([str(ctx.emranlib), *filtered]).returncode
    if tool == "nm":
        return subprocess.run([str(ctx.llvm_nm), *rest]).returncode
    if tool == "ld":
        cmd = [str(ctx.wasm_ld)]
        if "-m" not in rest:
            cmd.extend(["-m", "wasm64"])
        cmd.extend(rest)
        return subprocess.run(cmd).returncode

    die(f"unknown SDK tool mode: {tool}")


if __name__ == "__main__":
    raise SystemExit(main())
