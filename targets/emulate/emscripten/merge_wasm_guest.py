#!/usr/bin/env python3
"""
merge_wasm_guest.py -- Reusable WASM64 guest merger & standalone test harness
builder for `obsd-ports` (`emulate/emscripten`).

Links localized port applets (`ports-applets.tsv` + `applets/*.o`) alongside
`libobsdcompat`'s prebuilt base OpenBSD applets (`applet-partials/*.o`) and
`libobsdc-wasm-<ver>.a` WITHOUT modifying `libobsdcompat/`!

Modes:
  1. `merge-guest`: Emits merged `guest-partial.o`, `wasm_applet_table.c`, and
     `applet-table.tsv` into `--out-dir` (supporting `--base-mode full|minimal`
     and optional `--extra-applet sym:path:entry:src.c` such as `sonvori_init`).
  2. `run-guest`: Links a fast cached Node.js WASM64 OpenBSD kernel + VFS +
     optional `SVNP/1` network bridge containing base OpenBSD userland (`ksh`,
     `uname`, `cat`, `ls`, `rm`, `cp`, `sha256`, `grep`, etc.) + ALL built port
     applets + staged `sysroot/usr/local/...` + `/etc/ssl/cert.pem`, and runs an
     arbitrary guest shell command or script!
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import shutil
import struct
import subprocess
import sys
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO_ROOT / "tools/config"))
import obsd_versions  # noqa: E402  (release axis from config/versions/index.tsv)
import obsd_env  # noqa: E402  (EMSDK_PYTHON pinning)

MINIMAL_BASE_SYMS = {
    "ksh",
    "echo",
    "cat",
    "ls",
    "cp",
    "mv",
    "rm",
    "mkdir",
    "rmdir",
    "chmod",
    "ln",
    "pwd",
    "sleep",
    "test",
    "md5",
    "uname",
    "head",
    "tail",
    "wc",
    "cmp",
    "printf",
    "env",
    "id",
    "grep",
    "sed",
    "sort",
    "find",
    "tr",
    "stat",
    "mktemp",
    "which",
    "pwd_mkdb",
    "chroot",
    "ftp",
    "nc",
    "sysctl",
    "awk",
    "ps",
    "df",
    "cut",
    "date",
    "hostname",
    "expr",
    "stty",
    "tty",
    "tput",
}

HOST_RUNNER_C = r'''
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <emscripten/emscripten.h>

#include "obsd_emulate_embed.h"

void vfs_device_init_all(void) {}

extern int __real_posix_memalign(void **memptr, size_t alignment, size_t size);
int
__wrap_posix_memalign(void **memptr, size_t alignment, size_t size)
{
	size_t padded = (alignment == 4096U && size >= (16U << 20)) ? (size + 4096U) : size;
	return __real_posix_memalign(memptr, alignment, padded);
}

extern int obsd_wasm_host_pipe(int fds[2], int nonblock);
extern int obsd_wasm_host_dup(int host_fd);
extern int obsd_wasm_host_close(int host_fd);
extern ssize_t obsd_wasm_host_read(int host_fd, void *buf, size_t len);
__attribute__((weak)) uintptr_t obsd_wasm_svnp_shm_addr(void);

static int g_out_pipe[2] = { -1, -1 };
static int g_err_fd = -1;
static int g_in_pipe[2] = { -1, -1 };
static volatile int g_done = 0;
static volatile int g_wait_status = -1;
static volatile uint32_t g_embed_error = 0;
static volatile uint32_t g_embed_stage = 0;
static uint8_t g_io_buf[32768];

static void *
ports_runner_thread(void *arg)
{
	(void)arg;
	const struct obsd_emulate_embed_builtin *builtin = obsd_emulate_embed_builtin();
	char arg0[] = "ksh";
	char arg1[] = "/tmp/__obsd_ports_cmd.sh";
	char *argv_vec[] = { arg0, arg1, NULL };
	char env0[] = "PATH=/usr/local/bin:/usr/local/sbin:/bin:/sbin:/usr/bin:/usr/sbin";
	char env1[] = "HOME=/root";
	char env2[] = "TERM=xterm-256color";
	char env3[] = "USER=root";
	char env4[] = "LOGNAME=root";
	char env5[] = "LC_CTYPE=en_US.UTF-8";
	char *env_vec[] = { env0, env1, env2, env3, env4, env5, NULL };

	struct obsd_emulate_embed_request req;
	struct obsd_emulate_embed_status st;
	memset(&req, 0, sizeof(req));
	memset(&st, 0, sizeof(st));

	req.abi_version = OBSD_EMULATE_EMBED_ABI_VERSION_NAMES;
	req.struct_size = (uint32_t)sizeof(req);
	req.argc = 2;
	req.flags = OBSD_EMULATE_EMBED_OWN_HOST_SIGNALS |
	    OBSD_EMULATE_EMBED_PREEMPT_STALLED |
	    OBSD_EMULATE_EMBED_BANKED_GUEST;
	req.image = "/bin/ksh";
	req.argv = argv_vec;
	req.envp = env_vec;
	req.host_stdin = g_in_pipe[0];
	req.host_stdout = g_out_pipe[1];
	req.host_stderr = g_err_fd;
	req.max_processes = 64;
	req.applets = builtin ? builtin->applets : NULL;
	req.allocate = malloc;
	req.release = free;
	req.hostname = "obsd-ports-test";
	req.osversion = "WASM64#0";

	(void)chdir("/bsd/sysroot");
	int rc = obsd_emulate_embed_run(&req, &st);
	if (st.stage == 0) {
		if (g_in_pipe[0] >= 0)
			(void)obsd_wasm_host_close(g_in_pipe[0]);
		if (g_out_pipe[1] >= 0)
			(void)obsd_wasm_host_close(g_out_pipe[1]);
		if (g_err_fd >= 0)
			(void)obsd_wasm_host_close(g_err_fd);
	}
	g_wait_status = rc;
	g_embed_error = st.error;
	g_embed_stage = st.stage;
	__atomic_store_n(&g_done, 1, __ATOMIC_SEQ_CST);
	return NULL;
}

EMSCRIPTEN_KEEPALIVE uint32_t
ports_svnp_shm_lo(void)
{
	uintptr_t p = obsd_wasm_svnp_shm_addr ? obsd_wasm_svnp_shm_addr() : 0U;
	return (uint32_t)(p & 0xffffffffu);
}

EMSCRIPTEN_KEEPALIVE uint32_t
ports_svnp_shm_hi(void)
{
	uint64_t p = (uint64_t)(obsd_wasm_svnp_shm_addr ? obsd_wasm_svnp_shm_addr() : 0U);
	return (uint32_t)(p >> 32);
}

EMSCRIPTEN_KEEPALIVE uint32_t
ports_io_buf_addr(void)
{
	return (uint32_t)(uintptr_t)g_io_buf;
}

EMSCRIPTEN_KEEPALIVE int
ports_start(int enable_svnp)
{
	(void)enable_svnp;
	(void)setenv("LIBOBSDCOMPAT_VFS_PROFILE", "/bsd/vfs.profile", 1);
	(void)setenv("LIBOBSDCOMPAT_FAKEROOT_DB", "/bsd/persist/fakeroot.db", 1);
	(void)setenv("LIBOBSDCOMPAT_QUIET_NOOP_CAPS", "1", 1);
	(void)chdir("/bsd/sysroot");

	if (obsd_wasm_host_pipe(g_in_pipe, 1) != 0)
		return -1;
	if (obsd_wasm_host_pipe(g_out_pipe, 1) != 0)
		return -2;
	g_err_fd = obsd_wasm_host_dup(g_out_pipe[1]);
	if (g_err_fd < 0)
		return -4;
	(void)obsd_wasm_host_close(g_in_pipe[1]);
	g_in_pipe[1] = -1;

	pthread_t t;
	if (pthread_create(&t, NULL, ports_runner_thread, NULL) != 0)
		return -3;
	pthread_detach(t);
	return 0;
}

EMSCRIPTEN_KEEPALIVE int
ports_read_output(void)
{
	if (g_out_pipe[0] < 0)
		return 0;
	ssize_t n = obsd_wasm_host_read(g_out_pipe[0], g_io_buf, sizeof(g_io_buf));
	return (n > 0) ? (int)n : 0;
}

EMSCRIPTEN_KEEPALIVE int
ports_is_done(void)
{
	return __atomic_load_n(&g_done, __ATOMIC_SEQ_CST);
}

EMSCRIPTEN_KEEPALIVE int
ports_wait_status(void)
{
	return g_wait_status;
}

EMSCRIPTEN_KEEPALIVE uint32_t
ports_embed_error(void)
{
	return g_embed_error;
}
'''


def find_node(obsd_root: pathlib.Path) -> str:
    env_node = os.environ.get("EMSDK_NODE", "").strip()
    if env_node and os.path.isfile(env_node):
        return env_node
    emsdk_nodes = sorted((obsd_root / "deps/emsdk/node").rglob("bin/node"))
    if emsdk_nodes:
        return str(emsdk_nodes[-1])
    w = shutil.which("node")
    if w:
        return w
    raise SystemExit("merge_wasm_guest: node executable not found in emsdk or PATH")


def resolve_active_x11_build_dir(openbsd_version: str) -> Optional[pathlib.Path]:
    raw = os.environ.get("OBSD_X11_BUILD_DIR", "").strip() or os.environ.get("XENOCARA_BUILD_DIR", "").strip()
    if raw.lower() in ("none", "off", "0", "false"):
        return None
    if raw:
        p = pathlib.Path(raw).resolve()
        ar = p / f"libobsdx11-wasm-{openbsd_version}.a"
        if not ar.is_file():
            raise SystemExit(f"merge_wasm_guest: missing {ar} in OBSD_X11_BUILD_DIR={p}")
        return p
    default_p = pathlib.Path("/var/tmp/sonvori-xenocara/build") / openbsd_version
    if (default_p / "libobsdx11-libs.json").is_file() and (default_p / f"libobsdx11-wasm-{openbsd_version}.a").is_file():
        return default_p.resolve()
    return None


def parse_ports_applets_tsv(ports_lane_dir: pathlib.Path) -> List[Tuple[str, str, str, pathlib.Path]]:
    tsv_path = ports_lane_dir / "ports-applets.tsv"
    if not tsv_path.is_file():
        return []
    out: List[Tuple[str, str, str, pathlib.Path]] = []
    for raw in tsv_path.read_text(encoding="utf-8").splitlines():
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        cols = s.split("\t")
        if len(cols) < 4:
            continue
        sym, gpath, entry_sym, obj_rel = cols[0], cols[1], cols[2], cols[3]
        obj_p = pathlib.Path(obj_rel) if os.path.isabs(obj_rel) else (ports_lane_dir / obj_rel)
        out.append((sym, gpath, entry_sym, obj_p.resolve()))
    return out


def merge_guest_objects(
    obsd_root: pathlib.Path,
    openbsd_version: str,
    ports_lane_dir: pathlib.Path,
    out_dir: pathlib.Path,
    base_mode: str = "full",
) -> Tuple[pathlib.Path, pathlib.Path, pathlib.Path]:
    emulate_tools = obsd_root / "tools/build/personalities/openbsd/backends/emulate"
    if str(emulate_tools) not in sys.path:
        sys.path.insert(0, str(emulate_tools))
    import build_wasm_guest as bwg  # type: ignore

    wasm_build_dir = obsd_root / f"build/wasm-{openbsd_version}"
    base_table_tsv = wasm_build_dir / "applet-table.tsv"
    base_part_dir = wasm_build_dir / "applet-partials"
    archive_path = wasm_build_dir / f"libobsdc-wasm-{openbsd_version}.a"
    x11_dir = resolve_active_x11_build_dir(openbsd_version)
    x11_archive = (x11_dir / f"libobsdx11-wasm-{openbsd_version}.a") if x11_dir is not None else None
    ports_shared_cand = ports_lane_dir / f"libobsdports-shared-wasm-{openbsd_version}.a"
    ports_shared_archive = ports_shared_cand if ports_shared_cand.is_file() else None
    tail_pad_o = wasm_build_dir / "wasm_guest_tail_pad.o"
    include_root = wasm_build_dir / f"include-root-{openbsd_version}"
    emulate_prod = obsd_root / "src/personalities/openbsd/runtime/backends/emulate/product"
    sp = obsd_root / "src/personalities/openbsd/runtime/backends/translate/boundary"
    wasm_obj_tool = emulate_tools / "wasm_object_tool.py"

    emsdk = obsd_root / "deps/emsdk"
    emcc = emsdk / "upstream/emscripten/emcc"
    wasm_ld = emsdk / "upstream/bin/wasm-ld"
    res_dir = subprocess.check_output([str(emcc), "-print-resource-dir"], text=True).strip()
    clang_res_inc = str(pathlib.Path(res_dir) / "include")

    out_dir.mkdir(parents=True, exist_ok=True)

    # 1. Collect base applets (`full` or `minimal`)
    closures: Dict[str, Dict[str, Any]] = {}
    for raw in base_table_tsv.read_text(encoding="utf-8").splitlines():
        if not raw.strip():
            continue
        gpath, bname, sym, _entry_fn = raw.split("\t")
        if base_mode == "minimal" and bname not in MINIMAL_BASE_SYMS and sym not in MINIMAL_BASE_SYMS:
            continue
        loc_o = base_part_dir / f"{sym}.o"
        meta_p = base_part_dir / f"{sym}.meta.json"
        if not loc_o.is_file():
            continue
        if sym not in closures:
            if meta_p.is_file():
                m = json.loads(meta_p.read_text(encoding="utf-8"))
                arity, ret_void, has_malloc = m["arity"], m.get("ret_void", False), m["has_malloc"]
            else:
                arity, ret_void, has_malloc = bwg.inspect_wasm_applet_signature(
                    loc_o, f"obsd_applet_{sym}_main", f"obsd_applet_{sym}_malloc_options"
                )
            closures[sym] = {
                "sym": sym,
                "obj": loc_o,
                "arity": arity,
                "ret_void": ret_void,
                "has_malloc": has_malloc,
                "names": [],
            }
        closures[sym]["names"].append((bname, gpath))

    # 2. Add port applets from `ports-applets.tsv`
    for sym, gpath, entry_sym, obj_p in parse_ports_applets_tsv(ports_lane_dir):
        port_sym = f"port_{sym}" if sym in closures and closures[sym]["obj"] != obj_p else sym
        if port_sym != sym:
            raise SystemExit(f"port applet symbol '{sym}' collides with base applet symbol; prefix with p_ or rename")
        meta_p = obj_p.with_suffix(".meta.json")
        if sym not in closures:
            if meta_p.is_file():
                m = json.loads(meta_p.read_text(encoding="utf-8"))
                arity, ret_void, has_malloc = m["arity"], m.get("ret_void", False), m["has_malloc"]
            else:
                arity, ret_void, has_malloc = bwg.inspect_wasm_applet_signature(
                    obj_p, entry_sym, f"obsd_applet_{sym}_malloc_options"
                )
            closures[sym] = {
                "sym": sym,
                "obj": obj_p,
                "arity": arity,
                "ret_void": ret_void,
                "has_malloc": has_malloc,
                "names": [],
            }
        bname = gpath.rsplit("/", 1)[-1]
        if (bname, gpath) not in closures[sym]["names"]:
            closures[sym]["names"].append((bname, gpath))

    # 3. Generate `wasm_applet_entries.c` + `wasm_applet_table.c` + `applet-table.tsv`
    ctor_extra_decl: List[str] = []
    ctor_extra_calls: List[str] = []
    if x11_archive is not None:
        ctor_extra_decl.append("extern void obsd_xenocara_run_ctors(void);")
        ctor_extra_calls.append("obsd_xenocara_run_ctors();")
    if ports_shared_archive is not None:
        ctor_extra_decl.append("extern void obsd_ports_shared_run_ctors(void);")
        ctor_extra_calls.append("obsd_ports_shared_run_ctors();")
    ctor_extra_call = (" " + " ".join(ctor_extra_calls)) if ctor_extra_calls else ""
    el = [
        "/* AUTO-GENERATED by merge_wasm_guest.py */",
        "#include <stddef.h>",
        "#include <stdint.h>",
        '#include "emulate_product.h"',
        "",
        "extern void openssl_init_crypto_constructor(void);",
        *ctor_extra_decl,
        "static void obsd_wasm_ctor_openssl_init_crypto(int argc, char **argv, char **envp, void *aux)",
        f"{{ (void)argc; (void)argv; (void)envp; (void)aux; openssl_init_crypto_constructor();{ctor_extra_call} }}",
        "static const obsd_emulate_guest_init_fn obsd_wasm_guest_inits[1] = { obsd_wasm_ctor_openssl_init_crypto };",
        "static const struct obsd_emulate_guest_init_range obsd_wasm_guest_init_ranges[1] = {",
        "\t{ &obsd_wasm_guest_inits[0], &obsd_wasm_guest_inits[1] },",
        "};",
        "",
    ]
    keep_globals = ["__obsd_guest_curbrk", "__obsd_guest_minbrk", "__obsd_guest_touch_tail_pad"]
    ordered_specs = [closures[k] for k in sorted(closures.keys())]

    for spec in ordered_specs:
        sym = spec["sym"]
        arity, ret_void, has_malloc = spec["arity"], spec["ret_void"], spec["has_malloc"]
        main_sym = f"obsd_applet_{sym}_main"
        malloc_sym = f"obsd_applet_{sym}_malloc_options"
        entry_fn = f"obsd_emulate_applet_{sym}_entry"
        keep_globals.append(entry_fn)
        rtype = "void" if ret_void else "int"

        if arity == 0:
            el.append(f"extern {rtype} {main_sym}(void);")
            body = f"{main_sym}(); return 0;" if ret_void else f"return {main_sym}();"
            el.append(f"static int {main_sym}_3(int a, char **v, char **e) {{ (void)a; (void)v; (void)e; {body} }}")
            target_fn = f"{main_sym}_3"
        elif arity == 1:
            el.append(f"extern {rtype} {main_sym}(int);")
            body = f"{main_sym}(a); return 0;" if ret_void else f"return {main_sym}(a);"
            el.append(f"static int {main_sym}_3(int a, char **v, char **e) {{ (void)v; (void)e; {body} }}")
            target_fn = f"{main_sym}_3"
        elif arity == 2:
            el.append(f"extern {rtype} {main_sym}(int, char **);")
            body = f"{main_sym}(a, v); return 0;" if ret_void else f"return {main_sym}(a, v);"
            el.append(f"static int {main_sym}_3(int a, char **v, char **e) {{ (void)e; {body} }}")
            target_fn = f"{main_sym}_3"
        else:
            el.append(f"extern {rtype} {main_sym}(int, char **, char **);")
            if ret_void:
                el.append(f"static int {main_sym}_3(int a, char **v, char **e) {{ {main_sym}(a, v, e); return 0; }}")
                target_fn = f"{main_sym}_3"
            else:
                target_fn = main_sym

        if has_malloc:
            el.append(f"extern const char *{malloc_sym};")
            m_expr = f"&{malloc_sym}"
        else:
            m_expr = "NULL"

        el.extend(
            [
                f"static const struct obsd_emulate_applet_startup {sym}_startup = {{",
                "\t.abi_version = OBSD_EMULATE_APPLET_STARTUP_ABI_VERSION,",
                "\t.struct_size = sizeof(struct obsd_emulate_applet_startup),",
                f"\t.main = {target_fn},",
                "\t.inits = obsd_wasm_guest_init_ranges,",
                "\t.ninits = 1U,",
                f"\t.malloc_options = {m_expr},",
                "};",
                f"int {entry_fn}(int argc, char **argv, char **envp) {{",
                f"\treturn obsd_emulate_guest_startup(argc, argv, envp, &{sym}_startup);",
                "}",
                "",
            ]
        )

    entries_c = out_dir / "wasm_applet_entries.c"
    entries_o = out_dir / "wasm_applet_entries.o"
    entries_c.write_text("\n".join(el), encoding="utf-8")

    subprocess.run(
        [
            str(emcc),
            "-c",
            "-m64",
            "-pthread",
            "-O2",
            "-fno-common",
            "-femulated-tls",
            "-fno-stack-protector",
            "-sSUPPORT_LONGJMP=0",
            "-U__APPLE__",
            "-U__MACH__",
            "-U__EMSCRIPTEN__",
            "-U__linux__",
            "-D__OpenBSD__=1",
            "-DLIBOBSDCOMPAT_OBJECT_FORMAT_WASM=1",
            "-DLIBOBSDCOMPAT_KERN_GATE=1",
            "-DLIBOBSDCOMPAT_BOUNDARY_BACKEND_EMULATE=1",
            "-nostdinc",
            "-I",
            str(sp / "wasm-gate-shadow"),
            "-I",
            str(sp),
            "-I",
            str(wasm_build_dir / "gen"),
            "-I",
            str(include_root),
            "-I",
            str(emulate_prod),
            "-include",
            str(sp / "formats/wasm_compat.h"),
            "-idirafter",
            clang_res_inc,
            str(entries_c),
            "-o",
            str(entries_o),
        ],
        check=True,
    )

    tl = [
        "/* AUTO-GENERATED by merge_wasm_guest.py */",
        "#include <stddef.h>",
        "#include <stdint.h>",
        '#include "emulate_product.h"',
        "",
        "struct obsd_emulate_applet { const char *key; int (*entry)(int, char *const *, char *const *); };",
        "extern char __start_obsd_guest_data[];",
        "extern char __stop_obsd_guest_data[];",
        "char *const __obsd_guest_data_start_ptr = __start_obsd_guest_data;",
        "char *const __obsd_guest_data_end_ptr = __stop_obsd_guest_data;",
        "extern int __obsd_guest_touch_tail_pad(void);",
        "__attribute__((used)) static void *const __obsd_keep_tail_ref = (void *)&__obsd_guest_touch_tail_pad;",
        "",
    ]

    path_rows = []
    name_rows = []
    tsv_rows = []
    seen_names: Set[str] = set()
    for spec in ordered_specs:
        sym = spec["sym"]
        entry_fn = f"obsd_emulate_applet_{sym}_entry"
        tl.append(f"extern int {entry_fn}(int, char *const *, char *const *);")
        for bname, gpath in spec["names"]:
            path_rows.append((gpath, bname, sym, entry_fn))
            tsv_rows.append(f"{gpath}\t{bname}\t{sym}\t{entry_fn}")
            if bname not in seen_names:
                seen_names.add(bname)
                name_rows.append((bname, gpath))

    path_rows.sort(key=lambda r: r[0])
    name_rows.sort(key=lambda r: r[0])
    tsv_rows.sort()
    tsv_txt = "\n".join(tsv_rows) + "\n"
    tsv_digest = hashlib.sha256(tsv_txt.encode("utf-8")).hexdigest()

    tl.append("const struct obsd_emulate_applet obsd_emulate_product_applets[] = {")
    for gpath, _bn, _s, efn in path_rows:
        tl.append(f'\t{{ "{gpath}", {efn} }},')
    tl.append("\t{ NULL, NULL }\n};")
    tl.append("const struct obsd_emulate_applet *const obsd_emulate_product_applet_ptrs[] = {")
    for idx in range(len(path_rows)):
        tl.append(f"\t&obsd_emulate_product_applets[{idx}],")
    tl.append("\tNULL\n};")
    tl.append(f"const uint32_t obsd_emulate_product_applet_count = {len(path_rows)}U;")
    tl.append("const struct obsd_emulate_product_name obsd_emulate_product_names[] = {")
    for bname, gpath in name_rows:
        tl.append(f'\t{{ "{bname}", "{gpath}" }},')
    tl.append("\t{ NULL, NULL }\n};")
    tl.append(f"const uint32_t obsd_emulate_product_name_count = {len(name_rows)}U;")
    tl.append(f'const char obsd_emulate_product_table_digest[] = "{tsv_digest}";\n')

    table_c = out_dir / "wasm_applet_table.c"
    table_tsv = out_dir / "applet-table.tsv"
    table_c.write_text("\n".join(tl), encoding="utf-8")
    table_tsv.write_text(tsv_txt, encoding="utf-8")

    keep_file = out_dir / "guest-keep-globals.txt"
    keep_file.write_text("\n".join(sorted(keep_globals)) + "\n", encoding="utf-8")

    raw_guest = out_dir / "guest-partial.raw.o"
    out_guest = out_dir / "guest-partial.o"
    archive_inputs: List[str] = [str(archive_path)]
    if ports_shared_archive is not None:
        archive_inputs.extend([str(ports_shared_archive), str(ports_shared_archive)])
    if x11_archive is not None:
        archive_inputs.append(str(x11_archive))
    if ports_shared_archive is not None or x11_archive is not None:
        archive_inputs.append(str(archive_path))
    subprocess.run(
        [
            str(wasm_ld),
            "-m",
            "wasm64",
            "--fatal-warnings",
            "-r",
            str(entries_o),
            *[str(s["obj"]) for s in ordered_specs],
            *archive_inputs,
            str(tail_pad_o),
            "-o",
            str(raw_guest),
        ],
        check=True,
    )
    subprocess.run(
        [
            sys.executable,
            "-I",
            str(wasm_obj_tool),
            "window-guest",
            "--window-section",
            "obsd_guest_data",
            "--keep-global-file",
            str(keep_file),
            "-i",
            str(raw_guest),
            "-o",
            str(out_guest),
        ],
        check=True,
    )
    raw_guest.unlink(missing_ok=True)
    return out_guest, table_c, table_tsv


def build_and_cache_test_runtime(
    obsd_root: pathlib.Path,
    openbsd_version: str,
    ports_lane_dir: pathlib.Path,
) -> Tuple[pathlib.Path, pathlib.Path, str]:
    test_dir = ports_lane_dir / "test-runtime"
    test_dir.mkdir(parents=True, exist_ok=True)

    # Signature of all port applets + base archive
    wasm_build_dir = obsd_root / f"build/wasm-{openbsd_version}"
    host_ar = wasm_build_dir / f"libobsd-wasm-host-{openbsd_version}.a"
    base_ar = wasm_build_dir / f"libobsdc-wasm-{openbsd_version}.a"
    x11_dir = resolve_active_x11_build_dir(openbsd_version)
    x11_ar = (x11_dir / f"libobsdx11-wasm-{openbsd_version}.a") if x11_dir is not None else None
    ports_shared_cand = ports_lane_dir / f"libobsdports-shared-wasm-{openbsd_version}.a"
    ports_shared_ar = ports_shared_cand if ports_shared_cand.is_file() else None
    port_rows = parse_ports_applets_tsv(ports_lane_dir)

    bank_cpp = obsd_root / "tools/build/wasm-guest-bank/wasm_bank_guest.cpp"
    wot_py = obsd_root / "tools/build/personalities/openbsd/backends/emulate/wasm_object_tool.py"
    h = hashlib.sha256()
    h.update(b"pthread_pool=64:init_mem=536870912:banked_v1")
    h.update(f"{base_ar.stat().st_mtime_ns}:{host_ar.stat().st_mtime_ns}".encode())
    if x11_ar is not None and x11_ar.is_file():
        xst = x11_ar.stat()
        h.update(f":x11:{xst.st_size}:{xst.st_mtime_ns}".encode())
    if ports_shared_ar is not None and ports_shared_ar.is_file():
        pst = ports_shared_ar.stat()
        h.update(f":ports_shared:{pst.st_size}:{pst.st_mtime_ns}".encode())
    if bank_cpp.is_file():
        h.update(hashlib.sha256(bank_cpp.read_bytes()).digest())
    if wot_py.is_file():
        h.update(hashlib.sha256(wot_py.read_bytes()).digest())
    h.update(",".join(sorted(MINIMAL_BASE_SYMS)).encode())
    h.update(HOST_RUNNER_C.encode())
    for sym, gp, ent, obj_p in port_rows:
        st = obj_p.stat()
        h.update(f"{sym}:{gp}:{ent}:{st.st_size}:{st.st_mtime_ns}".encode())
    sig = h.hexdigest()

    runtime_mjs = test_dir / "ports-test-runtime.mjs"
    table_tsv = test_dir / "applet-table.tsv"
    stamp_file = test_dir / "runtime.stamp"

    if runtime_mjs.is_file() and table_tsv.is_file() and stamp_file.is_file() and stamp_file.read_text().strip() == sig:
        return runtime_mjs, table_tsv, find_node(obsd_root)

    guest_o, table_c, table_tsv = merge_guest_objects(
        obsd_root=obsd_root,
        openbsd_version=openbsd_version,
        ports_lane_dir=ports_lane_dir,
        out_dir=test_dir,
        base_mode="minimal",
    )

    emcc = obsd_root / "deps/emsdk/upstream/emscripten/emcc"
    emulate_prod = obsd_root / "src/personalities/openbsd/runtime/backends/emulate/product"
    emulate_pal = obsd_root / "src/personalities/openbsd/runtime/backends/emulate/pals/emscripten"

    table_o = test_dir / "wasm_applet_table.o"
    subprocess.run(
        [str(emcc), "-c", "-m64", "-pthread", "-O2", "-sSUPPORT_LONGJMP=0", "-I", str(emulate_prod), str(table_c), "-o", str(table_o)],
        check=True,
    )

    host_c = test_dir / "ports_test_host.c"
    host_o = test_dir / "ports_test_host.o"
    host_c.write_text(HOST_RUNNER_C, encoding="utf-8")
    subprocess.run(
        [
            str(emcc),
            "-c",
            "-m64",
            "-pthread",
            "-O2",
            "-sSUPPORT_LONGJMP=0",
            "-I",
            str(emulate_pal),
            str(host_c),
            "-o",
            str(host_o),
        ],
        check=True,
    )

    extra_ldflags = []
    ldflags_txt = wasm_build_dir / "host-ldflags.txt"
    if ldflags_txt.is_file():
        for ln in ldflags_txt.read_text(encoding="utf-8").splitlines():
            s = ln.strip()
            if s and not s.startswith("#"):
                extra_ldflags.append(s)

    exported_fns = (
        '["_ports_svnp_shm_lo","_ports_svnp_shm_hi","_ports_io_buf_addr",'
        '"_ports_start","_ports_read_output","_ports_is_done",'
        '"_ports_wait_status","_ports_embed_error"]'
    )
    exported_rt = '["FS","HEAPU8","wasmMemory"]'
    link_opt = os.environ.get("SONVORI_WASM_LINK_OPT", "-Oz").strip() or "-Oz"
    link_env = dict(os.environ)
    if not link_env.get("BINARYEN_CORES"):
        link_env["BINARYEN_CORES"] = str(os.cpu_count() or 8)
    subprocess.run(
        [
            str(emcc),
            "-m64",
            "-pthread",
            link_opt,
            "--profiling-funcs",
            "-Wno-pthreads-mem-growth",
            "-Wl,--wrap=posix_memalign",
            "-sMODULARIZE=1",
            "-sEXPORT_ES6=1",
            "-sENVIRONMENT=node",
            "-sALLOW_MEMORY_GROWTH=1",
            "-sINITIAL_MEMORY=536870912",
            "-sMAXIMUM_MEMORY=4294967296",
            "-sSTACK_SIZE=1048576",
            "-sPTHREAD_POOL_SIZE=64",
            "-sEXIT_RUNTIME=0",
            f"-sEXPORTED_FUNCTIONS={exported_fns}",
            f"-sEXPORTED_RUNTIME_METHODS={exported_rt}",
            *extra_ldflags,
            str(host_o),
            str(table_o),
            str(guest_o),
            str(host_ar),
            "-o",
            str(runtime_mjs),
        ],
        env=link_env,
        check=True,
    )
    stamp_file.write_text(sig + "\n", encoding="utf-8")
    return runtime_mjs, table_tsv, find_node(obsd_root)


NODE_EXEC_MJS = r'''
import fs from 'node:fs';
import net from 'node:net';
import dgram from 'node:dgram';
import dns from 'node:dns/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const [runtimePath, configPath] = process.argv.slice(2);
const cfg = JSON.parse(fs.readFileSync(configPath, 'utf8'));
const enc = new TextEncoder();
const dec = new TextDecoder('utf-8', { fatal: false });

const createRuntime = (await import(pathToFileURL(path.resolve(runtimePath)).href)).default;
const Module = await createRuntime({
  preRun: [
    (m) => {
      if (process.env.LIBOBSDCOMPAT_EMULATE_NCPU && m.ENV) {
        m.ENV.LIBOBSDCOMPAT_EMULATE_NCPU = process.env.LIBOBSDCOMPAT_EMULATE_NCPU;
      }
    },
  ],
});
const { FS } = Module;

function mkdirp(p, mode = 0o755) {
  const parts = p.split('/').filter(Boolean);
  let cur = '';
  for (const seg of parts) {
    cur += '/' + seg;
    try { FS.mkdir(cur, mode); } catch {}
  }
}

for (const d of [
  '/bsd/sysroot/bin', '/bsd/sysroot/sbin', '/bsd/sysroot/usr/bin', '/bsd/sysroot/usr/sbin',
  '/bsd/sysroot/usr/local/bin', '/bsd/sysroot/usr/local/sbin', '/bsd/sysroot/usr/local/share',
  '/bsd/sysroot/usr/share/terminfo', '/bsd/sysroot/etc/ssl', '/bsd/sysroot/root',
  '/bsd/persist/etc/ssl', '/bsd/tmp', '/bsd/sysroot/tmp',
]) {
  mkdirp(d, d.endsWith('tmp') ? 0o1777 : 0o755);
}

const stubBytes = enc.encode(`Sonvori BSD applet stub.\ntable ${cfg.tableDigest}\n`);
for (const gp of cfg.appletPaths) {
  const full = `/bsd/sysroot${gp}`;
  mkdirp(path.posix.dirname(full), 0o755);
  FS.writeFile(full, stubBytes);
  FS.chmod(full, 0o555);
}

function copyHostTreeToMemfs(hostDir, memfsBase) {
  if (!fs.existsSync(hostDir)) return;
  for (const ent of fs.readdirSync(hostDir, { withFileTypes: true })) {
    const hp = path.join(hostDir, ent.name);
    const mp = path.posix.join(memfsBase, ent.name);
    if (ent.isSymbolicLink()) {
      const target = fs.readlinkSync(hp);
      try { FS.unlink(mp); } catch {}
      FS.symlink(target, mp);
    } else if (ent.isDirectory()) {
      mkdirp(mp, 0o755);
      copyHostTreeToMemfs(hp, mp);
    } else if (ent.isFile()) {
      mkdirp(path.posix.dirname(mp), 0o755);
      FS.writeFile(mp, fs.readFileSync(hp));
      const mode = fs.statSync(hp).mode & 0o777;
      FS.chmod(mp, mode || 0o644);
    }
  }
}

copyHostTreeToMemfs(cfg.sysrootUsrLocal, '/bsd/sysroot/usr/local');

for (const [gp, hp, mode] of cfg.stagedFiles) {
  const dest = gp.startsWith('/etc/') ? `/bsd/persist${gp}` : (gp.startsWith('/tmp/') ? `/bsd${gp}` : `/bsd/sysroot${gp}`);
  mkdirp(path.posix.dirname(dest), 0o755);
  FS.writeFile(dest, fs.readFileSync(hp));
  FS.chmod(dest, mode);
}

FS.writeFile('/bsd/tmp/__obsd_ports_cmd.sh', enc.encode(cfg.scriptText));
FS.chmod('/bsd/tmp/__obsd_ports_cmd.sh', 0o755);
FS.writeFile('/bsd/persist/fakeroot.db', new Uint8Array(0));
FS.writeFile(
  '/bsd/vfs.profile',
  enc.encode('version 1\nbind /etc /bsd/persist/etc\nbind /tmp /bsd/tmp\nremap / /bsd/sysroot\nsynth proc /proc\nidentity root\n'),
);

// Self-contained standalone SVNP/1 shared-memory socket & DNS driver (zero external deps)
if (cfg.enableSvnp) {
  const SVNP_MAGIC = 0x53564e50;
  const SVNP_SHM_MAGIC = 0x53564e31;
  const SOCKS_BASE_OFF = 64;
  const SOCK_STRIDE = 16;
  const SLOTS_BASE_OFF = 16448;
  const SLOT_STRIDE = 65696;
  const MAX_SLOTS = 32;
  const SLOT_BUF_OFF = 32;

  const lo = Module._ports_svnp_shm_lo() >>> 0;
  const hi = Module._ports_svnp_shm_hi() >>> 0;
  const shmOff = hi * 0x100000000 + lo;

  const getViews = () => {
    const b = Module.wasmMemory.buffer;
    return { u8: new Uint8Array(b), i32: new Int32Array(b), u32: new Uint32Array(b) };
  };

  {
    const { i32, u32 } = getViews();
    Atomics.store(u32, (shmOff + 4) >> 2, 1);
    Atomics.store(u32, shmOff >> 2, SVNP_SHM_MAGIC);
    Atomics.store(i32, (shmOff + 8) >> 2, 1); // WS_STATE = connected
    Atomics.notify(i32, (shmOff + 8) >> 2, 64);
  }

  let nextSockId = 1;
  const socks = new Map();

  function encodeAddr(ip, port, family = 4) {
    const out = Buffer.alloc(28, 0);
    out.writeUInt8(family, 0);
    out.writeUInt16LE((port || 0) & 0xffff, 2);
    const normIp = (!ip || ip === '::ffff:127.0.0.1' || ip === '::1') ? '127.0.0.1' : ip.replace(/^::ffff:/, '');
    if (family === 4 && normIp.includes('.')) {
      const ps = normIp.split('.').map(Number);
      out[8] = ps[0]; out[9] = ps[1]; out[10] = ps[2]; out[11] = ps[3];
    }
    return out;
  }

  function decodeAddr(buf, off = 0) {
    const family = buf.readUInt8(off);
    const port = buf.readUInt16LE(off + 2);
    const ip = family === 4 ? `${buf[off+8]}.${buf[off+9]}.${buf[off+10]}.${buf[off+11]}` : '127.0.0.1';
    return { family, port, ip };
  }

  function updateSockState(sockId, s) {
    const { i32, u32 } = getViews();
    let mask = 0;
    let avail = 0;
    for (const c of s.rxQueue) avail += c.data.length;
    if (s.listening) {
      if (s.acceptQueue.length > 0) mask |= 1; // POLLIN on listening socket
    } else {
      if (avail > 0 || s.eof) mask |= 1; // POLLIN
      if (s.connected && !s.connecting) mask |= 4; // POLLOUT
      if (s.err) mask |= 8; // POLLERR
      if (s.eof) mask |= 16; // POLLHUP
    }
    const off = shmOff + SOCKS_BASE_OFF + sockId * SOCK_STRIDE;
    Atomics.store(i32, off >> 2, mask);
    Atomics.store(u32, (off + 4) >> 2, avail >>> 0);
    Atomics.store(i32, (off + 8) >> 2, s.err | 0);
    Atomics.add(i32, (off + 12) >> 2, 1);
    Atomics.notify(i32, (off + 12) >> 2, 64);
    Atomics.add(i32, (shmOff + 20) >> 2, 1);
    Atomics.notify(i32, (shmOff + 20) >> 2, 64);
    while (s.waiters.length > 0 && (avail > 0 || s.eof || s.err || s.acceptQueue.length > 0)) {
      const w = s.waiters.shift();
      w();
    }
  }

  function finishSlot(slotIdx, reqId, sockId, err, bodyBuf = Buffer.alloc(0)) {
    const { u8, i32, u32 } = getViews();
    const slotBase = shmOff + SLOTS_BASE_OFF + slotIdx * SLOT_STRIDE;
    const stateIdx = slotBase >> 2;
    if (Atomics.load(i32, stateIdx) !== 2) {
      Atomics.store(i32, stateIdx, 0);
      return false;
    }
    const resp = Buffer.alloc(20 + bodyBuf.length);
    resp.writeUInt32LE(SVNP_MAGIC, 0);
    resp.writeUInt8(0x80, 4);
    resp.writeUInt32LE(reqId >>> 0, 8);
    resp.writeUInt32LE(sockId >>> 0, 12);
    resp.writeInt32LE(err | 0, 16);
    bodyBuf.copy(resp, 20);
    u8.set(resp, slotBase + SLOT_BUF_OFF);
    Atomics.store(u32, (slotBase + 12) >> 2, resp.length);
    Atomics.store(i32, (slotBase + 16) >> 2, 0);
    Atomics.store(i32, stateIdx, 3);
    Atomics.notify(i32, stateIdx, 1);
    return true;
  }

  function attachTcpSocket(id, s, sock) {
    s.tcp = sock;
    sock.on('data', (chunk) => {
      s.rxQueue.push({ data: Buffer.from(chunk), addr: null });
      updateSockState(id, s);
    });
    sock.on('end', () => { s.eof = true; updateSockState(id, s); });
    sock.on('close', () => { s.eof = true; updateSockState(id, s); });
    sock.on('error', () => { s.err = 54; updateSockState(id, s); });
  }

  async function handleReq(slotIdx, frame) {
    const op = frame.readUInt8(4);
    const reqId = frame.readUInt32LE(8);
    const sockId = frame.readUInt32LE(12);
    const body = frame.subarray(16);

    if (op === 0x02) { // SOCKET
      const domain = body.readUInt8(0);
      const type = body.readUInt8(1);
      if (domain !== 4 && domain !== 6) return finishSlot(slotIdx, reqId, 0, 47);
      if (type !== 1 && type !== 2) return finishSlot(slotIdx, reqId, 0, 44);
      const id = nextSockId++;
      const s = {
        id, domain, type, tcp: null, udp: null, srv: null,
        connected: type === 2, connecting: false, listening: false,
        eof: false, err: 0, rxQueue: [], acceptQueue: [], acceptWaiters: [], waiters: [],
        local: { ip: '127.0.0.1', port: 0 }, peer: null,
      };
      if (type === 2) {
        const u = dgram.createSocket(domain === 6 ? 'udp6' : 'udp4');
        s.udp = u;
        u.on('message', (msg, rinfo) => {
          s.rxQueue.push({ data: Buffer.from(msg), addr: encodeAddr(rinfo.address, rinfo.port, 4) });
          updateSockState(id, s);
        });
        u.on('error', () => { s.err = 54; updateSockState(id, s); });
      }
      socks.set(id, s);
      updateSockState(id, s);
      const b = Buffer.alloc(4); b.writeUInt32LE(id, 0);
      return finishSlot(slotIdx, reqId, id, 0, b);
    }

    if (op === 0x10) { // RESOLVE
      const mode = body.readUInt8(0);
      if (mode === 0) {
        const port = body.readUInt16LE(4);
        const hlen = body.readUInt16LE(6);
        const host = body.subarray(8, 8 + hlen).toString('utf8');
        try {
          const res = await dns.lookup(host, { family: 4, all: true });
          const out = Buffer.alloc(4 + res.length * 28);
          out.writeUInt16LE(res.length, 0);
          out.writeUInt16LE(0, 2);
          res.forEach((r, idx) => encodeAddr(r.address, port, 4).copy(out, 4 + idx * 28));
          return finishSlot(slotIdx, reqId, 0, 0, out);
        } catch {
          return finishSlot(slotIdx, reqId, 0, 2);
        }
      }
      return finishSlot(slotIdx, reqId, 0, 78);
    }

    const s = socks.get(sockId);
    if (!s) return finishSlot(slotIdx, reqId, sockId, 9);

    if (op === 0x03) { // BIND
      const reqAddr = decodeAddr(body, 0);
      const bindHost = (reqAddr.ip === '0.0.0.0' || !reqAddr.ip) ? '127.0.0.1' : reqAddr.ip;
      if (s.type === 2 && s.udp) {
        try {
          await new Promise((resolve, reject) => {
            s.udp.once('error', reject);
            s.udp.bind(reqAddr.port, bindHost, () => { s.udp.removeListener('error', reject); resolve(); });
          });
          const a = s.udp.address();
          s.local = { ip: a.address, port: a.port };
          return finishSlot(slotIdx, reqId, sockId, 0, encodeAddr(s.local.ip, s.local.port, 4));
        } catch {
          return finishSlot(slotIdx, reqId, sockId, 48 /* EADDRINUSE */);
        }
      }
      const srv = net.createServer({ allowHalfOpen: true });
      srv.on('connection', (connSock) => {
        if (!s.listening) {
          connSock.destroy();
          return;
        }
        s.acceptQueue.push(connSock);
        updateSockState(sockId, s);
        while (s.acceptWaiters.length > 0 && s.acceptQueue.length > 0) {
          const aw = s.acceptWaiters.shift();
          aw();
        }
      });
      srv.on('error', () => {});
      try {
        await new Promise((resolve, reject) => {
          const onErr = (e) => { srv.removeListener('listening', onListen); reject(e); };
          const onListen = () => { srv.removeListener('error', onErr); resolve(); };
          srv.once('error', onErr);
          srv.once('listening', onListen);
          srv.listen({ host: bindHost, port: reqAddr.port, exclusive: false });
        });
        s.srv = srv;
        const a = srv.address();
        s.local = { ip: (a && a.address) ? a.address : bindHost, port: (a && a.port) ? a.port : reqAddr.port };
        return finishSlot(slotIdx, reqId, sockId, 0, encodeAddr(s.local.ip, s.local.port, 4));
      } catch {
        try { srv.close(); } catch {}
        return finishSlot(slotIdx, reqId, sockId, 48 /* EADDRINUSE */);
      }
    }

    if (op === 0x05) { // LISTEN
      if (!s.srv) return finishSlot(slotIdx, reqId, sockId, 22 /* EINVAL */);
      s.listening = true;
      updateSockState(sockId, s);
      return finishSlot(slotIdx, reqId, sockId, 0);
    }

    if (op === 0x06) { // ACCEPT
      if (!s.srv || !s.listening) return finishSlot(slotIdx, reqId, sockId, 22 /* EINVAL */);
      const nonblock = body.length > 0 && body.readUInt8(0) !== 0;
      const tryAccept = () => {
        const { i32 } = getViews();
        const slotBase = shmOff + SLOTS_BASE_OFF + slotIdx * SLOT_STRIDE;
        if (Atomics.load(i32, slotBase >> 2) !== 2) {
          Atomics.store(i32, slotBase >> 2, 0);
          return true;
        }
        if (!s.srv || !s.listening) {
          finishSlot(slotIdx, reqId, sockId, 22 /* EINVAL */);
          return true;
        }
        if (s.acceptQueue.length === 0) return false;
        const connSock = s.acceptQueue.shift();
        updateSockState(sockId, s);
        const nid = nextSockId++;
        const peerIp = connSock.remoteAddress || '127.0.0.1';
        const peerPort = connSock.remotePort || 0;
        const ns = {
          id: nid, domain: s.domain, type: s.type, tcp: null, udp: null, srv: null,
          connected: true, connecting: false, listening: false,
          eof: false, err: 0, rxQueue: [], acceptQueue: [], acceptWaiters: [], waiters: [],
          local: { ip: connSock.localAddress || s.local.ip, port: connSock.localPort || s.local.port },
          peer: { ip: peerIp, port: peerPort, family: 4 },
        };
        socks.set(nid, ns);
        attachTcpSocket(nid, ns, connSock);
        updateSockState(nid, ns);
        const resp = Buffer.alloc(32, 0);
        resp.writeUInt32LE(nid, 0);
        encodeAddr(peerIp, peerPort, 4).copy(resp, 4);
        finishSlot(slotIdx, reqId, sockId, 0, resp);
        return true;
      };
      if (tryAccept()) return;
      if (nonblock) return finishSlot(slotIdx, reqId, sockId, 35 /* EAGAIN */);
      s.acceptWaiters.push(() => { tryAccept(); });
      return;
    }

    if (op === 0x04) { // CONNECT
      const dst = decodeAddr(body, 0);
      const nonblock = body.readUInt8(28) !== 0;
      s.peer = dst;
      if (s.type === 2) {
        updateSockState(sockId, s);
        return finishSlot(slotIdx, reqId, sockId, 0, encodeAddr('127.0.0.1', 0, 4));
      }
      s.connecting = true;
      const sock = net.createConnection({ host: dst.ip, port: dst.port, allowHalfOpen: true });
      s.tcp = sock;
      sock.on('data', (chunk) => {
        s.rxQueue.push({ data: Buffer.from(chunk), addr: null });
        updateSockState(sockId, s);
      });
      sock.on('end', () => { s.eof = true; updateSockState(sockId, s); });
      sock.on('close', () => { s.eof = true; updateSockState(sockId, s); });
      if (nonblock) {
        sock.once('connect', () => {
          s.connecting = false; s.connected = true;
          s.local = { ip: sock.localAddress || '127.0.0.1', port: sock.localPort || 0 };
          updateSockState(sockId, s);
        });
        sock.on('error', () => { s.connecting = false; s.err = 61; updateSockState(sockId, s); });
        return finishSlot(slotIdx, reqId, sockId, 36 /* EINPROGRESS */);
      }
      sock.once('connect', () => {
        s.connecting = false; s.connected = true;
        s.local = { ip: sock.localAddress || '127.0.0.1', port: sock.localPort || 0 };
        updateSockState(sockId, s);
        finishSlot(slotIdx, reqId, sockId, 0, encodeAddr(s.local.ip, s.local.port, 4));
      });
      sock.once('error', () => {
        s.connecting = false; s.err = 61; updateSockState(sockId, s);
        finishSlot(slotIdx, reqId, sockId, 61);
      });
      return;
    }

    if (op === 0x07) { // SEND
      const hasDst = body.readUInt8(4) !== 0;
      const dst = hasDst ? decodeAddr(body, 5) : s.peer;
      const payload = body.subarray(33);
      if (s.type === 2 && s.udp && dst) {
        s.udp.send(payload, dst.port, dst.ip, (err) => {
          if (err) return finishSlot(slotIdx, reqId, sockId, 51);
          const b = Buffer.alloc(4); b.writeUInt32LE(payload.length, 0);
          finishSlot(slotIdx, reqId, sockId, 0, b);
        });
        return;
      }
      if (!s.tcp) return finishSlot(slotIdx, reqId, sockId, 57);
      if (s.connecting && !s.connected) return finishSlot(slotIdx, reqId, sockId, 35 /* EAGAIN */);
      if (!s.connected || s.tcp.destroyed || !s.tcp.writable) {
        const b = Buffer.alloc(4); b.writeUInt32LE(payload.length, 0);
        return finishSlot(slotIdx, reqId, sockId, 0, b);
      }
      s.tcp.write(payload, (err) => {
        if (err) return finishSlot(slotIdx, reqId, sockId, 54 /* ECONNRESET */);
        const b = Buffer.alloc(4); b.writeUInt32LE(payload.length, 0);
        finishSlot(slotIdx, reqId, sockId, 0, b);
      });
      return;
    }

    if (op === 0x08) { // RECV
      const maxLen = body.readUInt32LE(0);
      const msgFlags = body.readUInt32LE(4);
      const timeoutMs = body.readInt32LE(8);
      const tryPop = () => {
        if (s.rxQueue.length > 0) {
          const head = s.rxQueue[0];
          const take = head.data.subarray(0, maxLen);
          if (!(msgFlags & 0x02)) {
            if (take.length === head.data.length) s.rxQueue.shift();
            else head.data = head.data.subarray(take.length);
            updateSockState(sockId, s);
          }
          const out = Buffer.alloc(36 + take.length, 0);
          if (head.addr) { out.writeUInt8(1, 4); head.addr.copy(out, 8); }
          out.writeInt16LE(-1, 6);
          take.copy(out, 36);
          finishSlot(slotIdx, reqId, sockId, 0, out);
          return true;
        }
        if (s.err) { const e = s.err; s.err = 0; finishSlot(slotIdx, reqId, sockId, e); return true; }
        if (s.eof) { finishSlot(slotIdx, reqId, sockId, 0, Buffer.alloc(36, 0)); return true; }
        return false;
      };
      if (tryPop()) return;
      if ((msgFlags & 0x40) || timeoutMs === 0) return finishSlot(slotIdx, reqId, sockId, 35);
      let done = false;
      const waiter = () => { if (!done) { done = true; clearTimeout(tm); tryPop(); } };
      const tm = setTimeout(() => {
        if (!done) {
          done = true;
          const idx = s.waiters.indexOf(waiter);
          if (idx >= 0) s.waiters.splice(idx, 1);
          finishSlot(slotIdx, reqId, sockId, 35);
        }
      }, timeoutMs > 0 ? timeoutMs : 15000);
      s.waiters.push(waiter);
      return;
    }

    if (op === 0x09) return finishSlot(slotIdx, reqId, sockId, 0); // SETSOCKOPT
    if (op === 0x0a) { // GETSOCKOPT
      const level = body.readUInt16LE(0);
      const opt = body.readUInt16LE(2);
      const b = Buffer.alloc(4, 0);
      if (level === 1 && opt === 9) { b.writeInt32LE(s.err, 0); s.err = 0; }
      else if (level === 1 && opt === 12) { b.writeInt32LE(s.type, 0); }
      return finishSlot(slotIdx, reqId, sockId, 0, b);
    }
    if (op === 0x0b) return finishSlot(slotIdx, reqId, sockId, 0, encodeAddr(s.local.ip, s.local.port, 4));
    if (op === 0x0c) return finishSlot(slotIdx, reqId, sockId, s.peer ? 0 : 57, s.peer ? encodeAddr(s.peer.ip, s.peer.port, 4) : Buffer.alloc(0));
    if (op === 0x0d) { // SHUTDOWN
      const how = body.length > 0 ? body.readUInt8(0) : 2;
      if (s.srv) {
        const srv = s.srv;
        s.srv = null;
        s.listening = false;
        s.eof = true;
        s.err = 22;
        for (const q of s.acceptQueue) { try { q.destroy(); } catch {} }
        s.acceptQueue.length = 0;
        updateSockState(sockId, s);
        while (s.acceptWaiters.length > 0) {
          const aw = s.acceptWaiters.shift();
          aw();
        }
        await new Promise((r) => srv.close(() => r()));
      } else if (s.tcp) {
        if (how === 1) {
          s.tcp.end();
        } else {
          s.eof = true;
          s.tcp.destroy();
          updateSockState(sockId, s);
          while (s.waiters.length > 0) {
            const w = s.waiters.shift();
            w();
          }
        }
      }
      return finishSlot(slotIdx, reqId, sockId, 0);
    }
    if (op === 0x0e) { // CLOSE
      s.eof = true;
      s.err = 9;
      s.listening = false;
      if (s.tcp) s.tcp.destroy();
      if (s.udp) try { s.udp.close(); } catch {}
      if (s.srv) {
        const srv = s.srv;
        s.srv = null;
        for (const q of s.acceptQueue) { try { q.destroy(); } catch {} }
        s.acceptQueue.length = 0;
        updateSockState(sockId, s);
        while (s.acceptWaiters.length > 0) {
          const aw = s.acceptWaiters.shift();
          aw();
        }
        await new Promise((r) => srv.close(() => r()));
      } else {
        updateSockState(sockId, s);
      }
      while (s.waiters.length > 0) {
        const w = s.waiters.shift();
        w();
      }
      socks.delete(sockId);
      return finishSlot(slotIdx, reqId, sockId, 0);
    }
    return finishSlot(slotIdx, reqId, sockId, 0);
  }

  setInterval(() => {
    const { u8, i32, u32 } = getViews();
    for (let s = 0; s < MAX_SLOTS; s++) {
      const slotBase = shmOff + SLOTS_BASE_OFF + s * SLOT_STRIDE;
      const stateIdx = slotBase >> 2;
      const st = Atomics.load(i32, stateIdx);
      if (st === 4) { Atomics.store(i32, stateIdx, 0); continue; }
      if (st === 1) {
        const reqLen = Atomics.load(u32, (slotBase + 8) >> 2);
        const frame = Buffer.from(u8.slice(slotBase + SLOT_BUF_OFF, slotBase + SLOT_BUF_OFF + reqLen));
        if (Atomics.compareExchange(i32, stateIdx, 1, 2) === 1) {
          void handleReq(s, frame);
        }
      }
    }
  }, 2).unref();
} else {
  const lo = Module._ports_svnp_shm_lo() >>> 0;
  const hi = Module._ports_svnp_shm_hi() >>> 0;
  const shmOff = hi * 0x100000000 + lo;
  const i32 = new Int32Array(Module.wasmMemory.buffer);
  Atomics.store(i32, (shmOff + 8) >> 2, -1); // WS_STATE = offline
}

const rc = Module._ports_start(cfg.enableSvnp ? 1 : 0);
if (rc !== 0) {
  console.error(`ports_start failed: ${rc}`);
  process.exit(1);
}

const outPtr = Module._ports_io_buf_addr() >>> 0;
function drain() {
  for (;;) {
    const n = Module._ports_read_output();
    if (n <= 0) break;
    const chunk = new Uint8Array(n);
    chunk.set(Module.HEAPU8.subarray(outPtr, outPtr + n));
    process.stdout.write(dec.decode(chunk));
  }
}

const deadline = Date.now() + (cfg.timeoutMs || 120000);
while (!Module._ports_is_done()) {
  drain();
  if (Date.now() > deadline) {
    console.error('Timed out waiting for WASM64 guest command');
    process.exit(124);
  }
  await new Promise((r) => setTimeout(r, 10));
}
drain();
const status = Module._ports_wait_status();
const err = Module._ports_embed_error() >>> 0;
if (err !== 0) {
  console.error(`embed error: ${err}`);
  process.exit(1);
}
const exitCode = (status & 0x7f) === 0 ? ((status >> 8) & 0xff) : 128 + (status & 0x7f);
process.exit(exitCode);
'''


def cmd_run_guest(args: argparse.Namespace) -> int:
    obsd_root = pathlib.Path(args.libobsdcompat_root).resolve()
    ver = args.openbsd_version
    ports_lane_dir = pathlib.Path(args.ports_lane_dir).resolve()
    runtime_mjs, table_tsv, node_bin = build_and_cache_test_runtime(obsd_root, ver, ports_lane_dir)

    raw_tsv = table_tsv.read_bytes()
    table_digest = hashlib.sha256(raw_tsv).hexdigest()
    applet_paths = sorted({ln.split("\t")[0] for ln in raw_tsv.decode("utf-8").splitlines() if ln.strip()})

    src_root = obsd_root / "vendor/openbsd/versions" / ver / "src"
    test_dir = ports_lane_dir / "test-runtime"
    etc_stage = test_dir / "etc-stage"
    etc_stage.mkdir(parents=True, exist_ok=True)

    mpw = src_root / "etc/master.passwd"
    pw_out = etc_stage / "passwd"
    pw_lines = []
    for ln in mpw.read_text(encoding="utf-8").splitlines():
        if ln and not ln.startswith("#") and len(ln.split(":")) >= 10:
            f = ln.split(":")
            pw_lines.append(":".join([f[0], "*", f[2], f[3], f[7], f[8], f[9]]))
    pw_out.write_text("\n".join(pw_lines) + "\n", encoding="utf-8")

    hosts_out = etc_stage / "hosts"
    hosts_out.write_text("127.0.0.1\tlocalhost\n::1\tlocalhost\n", encoding="utf-8")
    resolv_out = etc_stage / "resolv.conf"
    resolv_out.write_text("nameserver 1.1.1.1\nlookup file bind\n", encoding="utf-8")

    staged_files: List[Tuple[str, str, int]] = [
        ("/etc/master.passwd", str(mpw), 0o600),
        ("/etc/passwd", str(pw_out), 0o644),
        ("/etc/group", str(src_root / "etc/group"), 0o644),
        ("/etc/services", str(src_root / "etc/services"), 0o644),
        ("/etc/protocols", str(src_root / "etc/protocols"), 0o644),
        ("/etc/hosts", str(hosts_out), 0o644),
        ("/etc/resolv.conf", str(resolv_out), 0o644),
    ]

    # Stage /etc/ssl/cert.pem (from OpenBSD vendor src or host CA bundle)
    for cert_cand in (
        src_root / "lib/libcrypto/cert.pem",
        pathlib.Path("/etc/ssl/certs/ca-certificates.crt"),
        pathlib.Path("/etc/ssl/cert.pem"),
    ):
        if cert_cand.is_file():
            staged_files.append(("/etc/ssl/cert.pem", str(cert_cand), 0o444))
            break

    # Stage terminfo entries for curses/nano tests (Linux/BSD: x/xterm; macOS: 78/xterm)
    for rel_ti in ("d/dumb", "x/xterm", "x/xterm-256color", "v/vt100"):
        ti_name = rel_ti.split("/", 1)[1]
        hex_rel = f"{ord(ti_name[0]):02x}/{ti_name}"
        found_ti = False
        for base_ti in ("/usr/share/terminfo", "/lib/terminfo", "/opt/homebrew/share/terminfo"):
            for sub_rel in (rel_ti, hex_rel):
                cand = pathlib.Path(base_ti) / sub_rel
                if cand.is_file():
                    staged_files.append((f"/usr/share/terminfo/{rel_ti}", str(cand), 0o444))
                    found_ti = True
                    break
            if found_ti:
                break

    # Stage OpenBSD UTF-8 LC_CTYPE when available so widechar curses TUIs enable UTF-8 cleanly
    for lc_cand in (
        REPO_ROOT.parent.parent / f"build/wasm/.work-{ver}/rootfs/LC_CTYPE",
        REPO_ROOT.parent.parent / "runtime/overlay/usr/share/locale/UTF-8/LC_CTYPE",
        obsd_root.parent.parent / f"build/wasm/.work-{ver}/rootfs/LC_CTYPE",
        obsd_root.parent.parent / "runtime/overlay/usr/share/locale/UTF-8/LC_CTYPE",
        obsd_root / "vendor/openbsd/versions" / ver / "share/locale/UTF-8/LC_CTYPE",
    ):
        if lc_cand.is_file():
            staged_files.append(("/usr/share/locale/UTF-8/LC_CTYPE", str(lc_cand), 0o444))
            break

    script_body = args.script_file and pathlib.Path(args.script_file).read_text(encoding="utf-8") or args.cmd
    full_script = (
        "#!/bin/ksh\n"
        "set -e\n"
        "if [ ! -s /etc/pwd.db ]; then\n"
        "  cp /etc/master.passwd /etc/master.passwd.in\n"
        "  /usr/sbin/pwd_mkdb -p -d /etc /etc/master.passwd.in\n"
        "fi\n"
        + script_body
        + "\n"
    )

    runner_mjs = test_dir / "exec_guest.mjs"
    runner_mjs.write_text(NODE_EXEC_MJS, encoding="utf-8")
    cfg_json = test_dir / "exec_cfg.json"
    cfg_json.write_text(
        json.dumps(
            {
                "tableDigest": table_digest,
                "appletPaths": applet_paths,
                "sysrootUsrLocal": str(ports_lane_dir / "sysroot/usr/local"),
                "stagedFiles": staged_files,
                "scriptText": full_script,
                "enableSvnp": bool(args.enable_network),
                "timeoutMs": args.timeout_ms,
            }
        ),
        encoding="utf-8",
    )
    return subprocess.run([node_bin, str(runner_mjs), str(runtime_mjs), str(cfg_json)], cwd=str(test_dir)).returncode


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="mode", required=True)

    p_m = sub.add_parser("merge-guest")
    p_m.add_argument("--libobsdcompat-root", required=True)
    p_m.add_argument("--openbsd-version", required=True)
    p_m.add_argument("--ports-lane-dir", required=True)
    p_m.add_argument("--out-dir", required=True)
    p_m.add_argument("--base-mode", choices=("full", "minimal"), default="full")

    p_r = sub.add_parser("run-guest")
    p_r.add_argument("--libobsdcompat-root", required=True)
    p_r.add_argument("--openbsd-version", default=obsd_versions.default_version())
    p_r.add_argument("--ports-lane-dir", required=True)
    p_r.add_argument("--cmd", default="uname -a")
    p_r.add_argument("--script-file", default="")
    p_r.add_argument("--enable-network", action="store_true", help="Enable standalone SVNP/1 TCP/UDP/DNS bridge")
    p_r.add_argument("--timeout-ms", type=int, default=120000)

    args = ap.parse_args()
    obsd_env.ensure_emsdk_python(args.libobsdcompat_root)
    if args.mode == "merge-guest":
        merge_guest_objects(
            obsd_root=pathlib.Path(args.libobsdcompat_root).resolve(),
            openbsd_version=args.openbsd_version,
            ports_lane_dir=pathlib.Path(args.ports_lane_dir).resolve(),
            out_dir=pathlib.Path(args.out_dir).resolve(),
            base_mode=args.base_mode,
        )
        return 0
    if args.mode == "run-guest":
        return cmd_run_guest(args)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
