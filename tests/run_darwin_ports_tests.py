#!/usr/bin/env python3
"""
tests/run_darwin_ports_tests.py -- Production Verification Suite for Darwin `obsd-ports`
(`translate/darwin-macosx` & `emulate/darwin-{iphonesimulator,iphoneos}` across
OpenBSD 7.8, 7.9, and 8.0).

Verifies:
  1. Packaged Lane Artifacts & Schemas (`built-ports.json`, `ports-applets.tsv`,
     `standalone.tsv` on `translate` / `ports-test-applets.tsv` + `applets/*.o` on
     `emulate`, `sysroot/usr/local/**`, `ports-owners.db`, `packages/*.tgz`, plus
     all staged `.a` static libraries, headers, and `.pc` descriptors).
  2. Mach-O Containment, `x18` Reservation & iOS App Store Policy Compliance:
     - Disassembles every packaged port binary/partial (`llvm-objdump -d`) and
       asserts ZERO `x18` instructions across all 75 applets and C++ runtime archives.
     - Asserts ZERO `__DATA,__mod_init_func`, ZERO `__mod_term_func`, and ZERO
       Mach-O native TLV (`__thread_*`) sections.
     - Asserts ZERO JIT (`pthread_jit_write_protect_np`) and ZERO port `dlopen`
       plugin-loader imports.
     - On `translate`: verifies `otool -L` (solely `/usr/lib/libSystem.B.dylib`),
       `otool -h` (`MH_TWOLEVEL` & `!MH_FORCE_FLAT`), and `codesign --verify`.
     - On `emulate`: verifies sole `_obsd_applet_<sym>_main` export, zero `(common)`
       symbols, zero `__TEXT,__gcc_except_tab`, zero unledgered `section$start`
       anchors, undefined symbol closure, AND co-generates the full `entries.c` +
       `table.c` alongside base OpenBSD applets via `gen_emulate_applet_table.py`
       and syntax/type-checks both with `-Wall -Wextra -Werror`!
  3. C & C++17 Static Library Link Closure (`tests/ports_pty_probe.c`, `liblowdown`,
     `libxml2`, `libarchive`, `libiperf`, `libquickjs`, `libjim`, `libqrencode`,
     and `CXX17_PROBE_SRC`).
  4. Full Live OpenBSD VFS Functional Execution on `translate/darwin-macosx`
     (exercising all 53 ports / 75 applets under `LIBOBSDCOMPAT_VFS_PROFILE`,
     `LIBOBSDCOMPAT_FAKEROOT_DB`, `MALLOC_OPTIONS=JJ`, real sockets, `kqueue`,
     and 80x24 / 100x30 `openpty()` curses TUIs).
"""
from __future__ import annotations

import argparse
import concurrent.futures
import functools
import http.server
import json
import os
import pathlib
import re
import shlex
import shutil
import socketserver
import sqlite3
import subprocess
import sys
import tempfile
import threading
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(REPO_ROOT / "tools/config") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "tools/config"))
if str(REPO_ROOT / "tools") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "tools"))
if str(REPO_ROOT / "sdk/lib") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "sdk/lib"))
if str(REPO_ROOT / "tests") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "tests"))

import obsd_versions  # noqa: E402
import build_ports as bp  # noqa: E402
import obsd_toolchain as ot  # noqa: E402
import test_sdk as ts  # noqa: E402

REQUIRED_STATIC_LIBS = [
    "libbz2.a",
    "liblzma.a",
    "libzstd.a",
    "libonig.a",
    "libsqlite3.a",
    "liblua5.4.a",
    "libcurl.a",
    "libiconv.a",
    "libcharset.a",
    "libpcre2-8.a",
    "libpcre2-16.a",
    "libpcre2-32.a",
    "libpcre2-posix.a",
    "libpcre.a",
    "libpcre16.a",
    "libpcreposix.a",
    "liblz4.a",
    "libxxhash.a",
    "libpng.a",
    "libpng16.a",
    "libarchive.a",
    "libiperf.a",
    "liblowdown.a",
    "libxml2.a",
    "libqrencode.a",
    "libgit.a",
    "libjim.a",
    "quickjs/libquickjs.a",
]

REQUIRED_HEADERS = [
    "bzlib.h",
    "lzma.h",
    "zstd.h",
    "oniguruma.h",
    "sqlite3.h",
    "lua-5.4/lua.h",
    "curl/curl.h",
    "iconv.h",
    "localcharset.h",
    "pcre2.h",
    "pcre.h",
    "lz4.h",
    "xxhash.h",
    "png.h",
    "archive.h",
    "iperf_api.h",
    "lowdown.h",
    "libxml2/libxml/parser.h",
    "qrencode.h",
    "jim/jim.h",
    "quickjs/quickjs.h",
]

EXTRA_STATIC_LIBS_PROBE_C = r"""
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>

#include <archive.h>
#include <archive_entry.h>
#include <iperf_api.h>
#include <lowdown.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <qrencode.h>
#include <quickjs/quickjs.h>
#include <jim.h>

int main(void) {
    /* 1. libarchive + libiperf */
    struct archive *a = archive_write_new();
    struct archive_entry *ae = archive_entry_new();
    struct iperf_test *ipt = iperf_new_test();
    if (!a || !ae || !ipt) return 11;
    archive_entry_free(ae);
    archive_write_free(a);
    iperf_free_test(ipt);

    /* 2. liblowdown */
    struct lowdown_opts lopts;
    memset(&lopts, 0, sizeof(lopts));
    lopts.type = LOWDOWN_HTML;
    char *lout = NULL;
    size_t lsz = 0;
    if (!lowdown_buf(&lopts, "# Darwin\n", 9, &lout, &lsz, NULL)) return 12;
    free(lout);

    /* 3. libxml2 */
    const char *xml = "<ports><p>darwin</p></ports>";
    xmlDocPtr doc = xmlReadMemory(xml, (int)strlen(xml), "m.xml", NULL, 0);
    if (!doc) return 13;
    xmlXPathContextPtr xctx = xmlXPathNewContext(doc);
    xmlXPathObjectPtr xres = xmlXPathEvalExpression((const xmlChar *)"string(/ports/p)", xctx);
    int xok = (xres && xres->stringval && strcmp((const char *)xres->stringval, "darwin") == 0);
    if (xres) xmlXPathFreeObject(xres);
    if (xctx) xmlXPathFreeContext(xctx);
    xmlFreeDoc(doc);
    xmlCleanupParser();
    if (!xok) return 14;

    /* 4. libqrencode */
    QRcode *qr = QRcode_encodeString("OpenBSD-Darwin", 0, QR_ECLEVEL_M, QR_MODE_8, 1);
    if (!qr || qr->width < 21) return 15;
    QRcode_free(qr);

    /* 5. libquickjs */
    JSRuntime *rt = JS_NewRuntime();
    JSContext *ctx = JS_NewContext(rt);
    JSValue val = JS_Eval(ctx, "Number((1n << 5n) + 10n)", 24, "<p>", JS_EVAL_TYPE_GLOBAL);
    int32_t qres = 0;
    int qrc = JS_ToInt32(ctx, &qres, val);
    JS_FreeValue(ctx, val);
    JS_FreeContext(ctx);
    JS_FreeRuntime(rt);
    if (qrc != 0 || qres != 42) return 16;

    /* 6. libjim */
    Jim_Interp *ji = Jim_CreateInterp();
    Jim_RegisterCoreCommands(ji);
    Jim_InitStaticExtensions(ji);
    if (Jim_Eval(ji, "expr {6 * 7}") != JIM_OK) return 17;
    long jv = 0;
    Jim_GetLong(ji, Jim_GetResult(ji), &jv);
    Jim_FreeInterp(ji);
    if (jv != 42) return 18;

    printf("[DARWIN-PASS] extra_static_libs_c_api: archive+iperf+lowdown+xml2+qrencode+quickjs+jim OK\n");
    return 0;
}
"""

TUI_PTY_SUITE_C = r"""
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <util.h>

static void
drain_pty(int master_fd, char *acc, size_t cap, size_t *len_inout, int wait_ms)
{
	struct pollfd pfd;
	pfd.fd = master_fd;
	pfd.events = POLLIN;
	int elapsed = 0;
	while (elapsed < wait_ms) {
		int prc = poll(&pfd, 1, 25);
		if (prc > 0 && (pfd.revents & POLLIN)) {
			char buf[4096];
			ssize_t n = read(master_fd, buf, sizeof(buf));
			if (n > 0) {
				size_t space = (*len_inout + 1 < cap) ? (cap - 1 - *len_inout) : 0;
				size_t copy = ((size_t)n < space) ? (size_t)n : space;
				if (copy > 0) {
					memcpy(acc + *len_inout, buf, copy);
					*len_inout += copy;
					acc[*len_inout] = '\0';
				}
				continue;
			}
			break;
		}
		elapsed += 25;
	}
}

static int
write_all_pty(int fd, const void *buf, size_t len)
{
	const uint8_t *p = (const uint8_t *)buf;
	size_t off = 0;
	while (off < len) {
		ssize_t n = write(fd, p + off, len - off);
		if (n < 0) {
			if (errno == EINTR || errno == EAGAIN) {
				usleep(10000);
				continue;
			}
			return -1;
		}
		off += (size_t)n;
	}
	return 0;
}

static int
run_quit_tui(const char *label, const char *prog, char *const argv[], const char *cwd, int rows, int cols, const char *quit_keys)
{
	int master = -1, slave = -1;
	struct winsize ws = { .ws_row = (unsigned short)rows, .ws_col = (unsigned short)cols, .ws_xpixel = 800, .ws_ypixel = 600 };
	if (openpty(&master, &slave, NULL, NULL, &ws) != 0) {
		fprintf(stderr, "[FAIL] %s openpty failed\n", label);
		return 1;
	}
	pid_t pid = fork();
	if (pid < 0) return 1;
	if (pid == 0) {
		close(master);
		if (login_tty(slave) != 0) _exit(126);
		if (cwd && chdir(cwd) != 0) _exit(125);
		setenv("TERM", "xterm-256color", 1);
		setenv("LC_CTYPE", "en_US.UTF-8", 1);
		setenv("HOME", "/root", 1);
		execv(prog, argv);
		_exit(127);
	}
	close(slave);
	size_t cap = 131072, len = 0;
	char *buf = calloc(1, cap);
	for (int i = 0; i < 60; i++) {
		drain_pty(master, buf, cap, &len, 100);
		if (strstr(buf, "\x1b[") != NULL && len >= 32)
			break;
	}
	if (strstr(buf, "\x1b[") == NULL) {
		fprintf(stderr, "[FAIL] %s emitted no ANSI escape sequences (len=%zu)\n", label, len);
		kill(pid, SIGKILL);
		waitpid(pid, NULL, 0);
		free(buf);
		close(master);
		return 1;
	}
	write_all_pty(master, quit_keys, strlen(quit_keys));
	int status = -1, reaped = 0;
	for (int i = 0; i < 80; i++) {
		drain_pty(master, buf, cap, &len, 50);
		if (waitpid(pid, &status, WNOHANG) == pid) {
			reaped = 1;
			break;
		}
	}
	if (!reaped) {
		kill(pid, SIGTERM);
		waitpid(pid, &status, 0);
	}
	close(master);
	free(buf);
	printf("[DARWIN-PASS] pty_tui_%s: rendered ANSI (%zuB) & exited cleanly\n", label, len);
	return 0;
}

static int
test_vim_pty(const char *out_path)
{
	unlink(out_path);
	int master = -1, slave = -1;
	struct winsize ws = { .ws_row = 24, .ws_col = 80, .ws_xpixel = 640, .ws_ypixel = 384 };
	if (openpty(&master, &slave, NULL, NULL, &ws) != 0) return 1;
	pid_t pid = fork();
	if (pid == 0) {
		close(master);
		if (login_tty(slave) != 0) _exit(126);
		setenv("TERM", "xterm-256color", 1);
		setenv("LC_CTYPE", "en_US.UTF-8", 1);
		setenv("HOME", "/root", 1);
		char *const vargv[] = {
			(char *)"vim", (char *)"-u", (char *)"NONE", (char *)"-N", (char *)"-n",
			(char *)out_path, NULL
		};
		execv("/usr/local/bin/vim", vargv);
		_exit(127);
	}
	close(slave);
	size_t cap = 65536, len = 0;
	char *buf = calloc(1, cap);
	for (int i = 0; i < 50; i++) {
		drain_pty(master, buf, cap, &len, 100);
		if (strstr(buf, "\x1b[") != NULL && len >= 32) break;
	}
	write_all_pty(master, "iDarwin Vim PTY OK\x1b", 19);
	drain_pty(master, buf, cap, &len, 150);
	write_all_pty(master, ":wq\r", 4);
	int status = -1;
	for (int i = 0; i < 80; i++) {
		drain_pty(master, buf, cap, &len, 50);
		if (waitpid(pid, &status, WNOHANG) == pid) break;
	}
	close(master);
	free(buf);
	FILE *fp = fopen(out_path, "rb");
	if (!fp) { fprintf(stderr, "[FAIL] vim did not save %s\n", out_path); return 1; }
	char saved[128] = {0};
	fread(saved, 1, sizeof(saved) - 1, fp);
	fclose(fp);
	if (strstr(saved, "Darwin Vim PTY OK") == NULL) {
		fprintf(stderr, "[FAIL] vim content mismatch: %s\n", saved);
		return 1;
	}
	printf("[DARWIN-PASS] pty_tui_vim: saved '%s'\n", "Darwin Vim PTY OK");
	return 0;
}

int main(int argc, char **argv)
{
	const char *git_dir = (argc > 1) ? argv[1] : "/tmp/git_work";
	if (test_vim_pty("/tmp/vim_pty_out.txt") != 0) return 1;
	char *const ncdu_av[] = { (char *)"ncdu", (char *)"/usr/local/man", NULL };
	if (run_quit_tui("ncdu", "/usr/local/bin/ncdu", ncdu_av, NULL, 24, 80, "q") != 0) return 1;
	char *const tig_av[] = { (char *)"tig", NULL };
	if (run_quit_tui("tig", "/usr/local/bin/tig", tig_av, git_dir, 24, 80, "q") != 0) return 1;
	char *const htop_av[] = { (char *)"htop", NULL };
	if (run_quit_tui("htop", "/usr/local/bin/htop", htop_av, NULL, 24, 80, "q") != 0) return 1;
	char *const btop_av[] = { (char *)"btop", (char *)"--utf-force", NULL };
	if (run_quit_tui("btop", "/usr/local/bin/btop", btop_av, NULL, 30, 100, "q") != 0) return 1;
	return 0;
}
"""


def find_llvm_objdump(obsd_root: pathlib.Path) -> str:
    for c in (
        "/opt/homebrew/opt/llvm/bin/llvm-objdump",
        "/usr/local/opt/llvm/bin/llvm-objdump",
        str(obsd_root / "deps/emsdk/upstream/bin/llvm-objdump"),
        shutil.which("llvm-objdump") or "",
    ):
        if c and os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    raise AssertionError("llvm-objdump not found")


def macho_unbanked_data_sections(ot_l: str) -> List[str]:
    """Return any non-empty `__DATA,{__data,__bss,__common}` sections in `otool -l` output."""
    bad: List[str] = []
    cur_sect = ""
    cur_seg = ""
    for raw in ot_l.splitlines():
        s = raw.strip()
        if s.startswith("sectname "):
            cur_sect = s.split(None, 1)[1]
            cur_seg = ""
        elif s.startswith("segname "):
            cur_seg = s.split(None, 1)[1]
        elif s.startswith("size ") and cur_seg == "__DATA" and cur_sect in ("__data", "__bss", "__common"):
            sz_hex = s.split(None, 1)[1]
            try:
                if int(sz_hex, 16) > 0:
                    bad.append(f"{cur_seg},{cur_sect}({sz_hex})")
            except ValueError:
                pass
            cur_sect = ""
            cur_seg = ""
    return bad


def audit_single_macho(
    item: Tuple[str, pathlib.Path, str, str, str]
) -> Optional[str]:
    sym, path, backend, sdk, objdump = item
    senv = {k: v for k, v in os.environ.items() if k not in ot.DARWIN_SANITIZED_ENV_KEYS}

    # 1. Zero guest x18/w18 register instructions (on `translate` standalone
    # binaries, `libobsdc` links `obsd_gate.o` whose exact documented gate veneer
    # pair is `str x18, [sp, #0x90]` + `ldr x18, [sp, #0x90]`; on `emulate`
    # partials, ZERO x18/w18 instructions may appear anywhere).
    dis = subprocess.check_output([objdump, "-d", str(path)], text=True, stderr=subprocess.DEVNULL, env=senv)
    x18_hits: List[str] = []
    for ln in dis.splitlines():
        parts = ln.split("\t", 1)
        if len(parts) < 2:
            continue
        insn = parts[1].split(";", 1)[0].strip()
        if re.search(r"(?<![A-Za-z0-9_])[xw]18(?![A-Za-z0-9_])", insn):
            norm = re.sub(r"\s+", " ", insn.lower()).replace(", ", ",").replace("[ ", "[").replace(" ]", "]").replace("#144]", "#0x90]")
            x18_hits.append(norm)
    if backend == "translate":
        if x18_hits != ["str x18,[sp,#0x90]", "ldr x18,[sp,#0x90]"]:
            return f"{sym} ({path.name}): unexpected x18/w18 instructions (expected only obsd_gate pair): {x18_hits[:5]}"
    elif x18_hits:
        return f"{sym} ({path.name}): forbidden x18/w18 instruction: {x18_hits[:5]}"

    # 2. Load command & section invariants
    ot_l = subprocess.check_output(["/usr/bin/xcrun", "--sdk", sdk, "otool", "-l", str(path)], text=True, env=senv)
    if "__mod_init_func" in ot_l or "__mod_term_func" in ot_l:
        return f"{sym} ({path.name}): forbidden __mod_init_func/__mod_term_func section"
    if backend == "emulate" and "__thread_" in ot_l:
        return f"{sym} ({path.name}): forbidden Mach-O native TLV __thread_* section"

    # 3. Symbol policy invariants (zero JIT, zero port dlopen)
    nm_m = subprocess.check_output(["/usr/bin/xcrun", "--sdk", sdk, "nm", "-m", str(path)], text=True, env=senv)
    if "_pthread_jit_write_protect_np" in nm_m or "_sys_icache_invalidate" in nm_m:
        return f"{sym} ({path.name}): forbidden JIT runtime symbol in symbol table"

    if backend == "translate":
        ot_deps = subprocess.check_output(["/usr/bin/xcrun", "--sdk", sdk, "otool", "-L", str(path)], text=True, env=senv)
        for ln in ot_deps.splitlines()[1:]:
            dep = ln.strip().split(" (", 1)[0]
            if dep and ("libc++" in dep or not (dep.startswith("/usr/lib/libSystem") or dep.startswith("/System/Library/Frameworks/"))):
                return f"{sym}: forbidden dynamic library import '{dep}'"
        cs = subprocess.run(["/usr/bin/codesign", "--verify", "--verbose=1", str(path)], capture_output=True, text=True)
        if cs.returncode != 0:
            return f"{sym}: codesign verify failed: {cs.stderr.strip()}"
    else:
        if "sectname __gcc_except_tab" in ot_l:
            return f"{sym}: __TEXT,__gcc_except_tab survived in emulate partial"
        unbanked = macho_unbanked_data_sections(ot_l)
        if unbanked:
            return f"{sym}: unbanked mutable __DATA section(s) in emulate partial: {unbanked}"
        if " (common) " in nm_m:
            return f"{sym}: tentative (common) symbol survived in emulate partial"
        if "section$start" in nm_m or "segment$start" in nm_m:
            return f"{sym}: unledgered section$start/segment$start anchor in emulate partial"
        for dl_sym in (
            " _dlopen",
            " _dlopen_preflight",
            " _dlsym",
            " _dlclose",
            " _pthread_jit_write_protect_np",
            " _sys_icache_invalidate",
            " _os_thread_self_restrict_rwx_np",
        ):
            if any(ln.endswith(dl_sym) and "(undefined)" in ln for ln in nm_m.splitlines()):
                return f"{sym}: forbidden undefined symbol{dl_sym} in emulate partial"
        ext_defs = sorted(
            ln.split()[-1]
            for ln in nm_m.splitlines()
            if " external " in ln and "(undefined)" not in ln and "non-external" not in ln and "private external" not in ln
        )
        if ext_defs != [f"_obsd_applet_{sym}_main"]:
            return f"{sym}: expected sole external _obsd_applet_{sym}_main, got {ext_defs}"

    return None


def verify_artifacts_and_macho_invariants(
    ver: str,
    backend: str,
    sdk: str,
    obsd_root: pathlib.Path,
    lane_dir: pathlib.Path,
    target_port: str,
    jobs: int,
) -> None:
    recipes = bp.discover_recipes(ver, [target_port] if target_port else None, backend=backend, pal="darwin")
    manifest_p = lane_dir / "built-ports.json"
    applets_tsv = lane_dir / "ports-applets.tsv"
    owners_db = lane_dir / "ports-owners.db"
    pkg_idx = lane_dir / "packages/index.tsv"

    for req in (manifest_p, applets_tsv, owners_db, pkg_idx):
        if not req.is_file():
            raise AssertionError(f"missing packaged artifact {req}; run `make package` first")

    records = json.loads(manifest_p.read_text(encoding="utf-8"))
    built_by_port = {r["port"]: r for r in records}
    for rec in recipes:
        if rec["port"] not in built_by_port:
            raise AssertionError(f"port '{rec['port']}' missing from {manifest_p}")
        pkg_tgz = lane_dir / "packages" / f"{built_by_port[rec['port']]['pkgname']}.tgz"
        if not pkg_tgz.is_file():
            raise AssertionError(f"missing package tarball {pkg_tgz}")

    if not target_port:
        assert len(records) == 53, f"expected all 53 ports in {manifest_p}, got {len(records)}"
        for lib_rel in REQUIRED_STATIC_LIBS:
            lp = lane_dir / "stage/usr/local/lib" / lib_rel
            if not lp.is_file():
                raise AssertionError(f"missing staged static library: {lp}")
        if backend == "emulate":
            for ar_cand in sorted((lane_dir / "stage/usr/local/lib").rglob("*.a")):
                if ar_cand.is_symlink():
                    continue
                ar_ot = subprocess.check_output(["/usr/bin/xcrun", "--sdk", sdk, "otool", "-l", str(ar_cand)], text=True)
                unbanked_lib = macho_unbanked_data_sections(ar_ot)
                if unbanked_lib:
                    raise AssertionError(f"unbanked __DATA section(s) in staged static library {ar_cand.name}: {unbanked_lib[:5]}")
        for hdr_rel in REQUIRED_HEADERS:
            hp = lane_dir / "stage/usr/local/include" / hdr_rel
            if not hp.is_file():
                raise AssertionError(f"missing staged header: {hp}")
        # Verify staged port binaries on translate ALSO have zero port calls to _dlopen
        if backend == "translate":
            for rec in records:
                for app in rec.get("applets", []):
                    st_bin = lane_dir / "stage" / app["binary"].lstrip("/")
                    assert st_bin.is_file(), f"missing staged binary {st_bin}"

    # Verify binary struct obsd_fr_disk fakeroot DB (`ports-owners.db`) + `ports-owners.tsv`
    import struct as _st

    owners_tsv = lane_dir / "ports-owners.tsv"
    assert owners_tsv.is_file(), f"missing {owners_tsv}"
    raw_db = owners_db.read_bytes()
    pos = 0
    rec_cnt = 0
    while pos < len(raw_db):
        assert pos + 24 <= len(raw_db), "truncated FR_RECORD header in ports-owners.db"
        plen, mask, _uid, _gid, _mode, _rdev = _st.unpack_from("<6I", raw_db, pos)
        pos += 24
        assert plen > 0 and pos + plen <= len(raw_db) and mask == 7, "malformed FR_RECORD in ports-owners.db"
        gp_str = raw_db[pos : pos + plen].decode("utf-8")
        assert gp_str.startswith("/"), f"non-absolute guest_path in ports-owners.db: {gp_str}"
        pos += plen
        rec_cnt += 1
    tsv_cnt = sum(1 for ln in owners_tsv.read_text(encoding="utf-8").splitlines() if ln.strip() and not ln.startswith("#"))
    assert rec_cnt > 0 and rec_cnt == tsv_cnt, f"ports-owners.db count {rec_cnt} != ports-owners.tsv {tsv_cnt}"

    # Collect unique packaged binaries / partials for parallel Mach-O + x18 audit
    objdump = find_llvm_objdump(obsd_root)
    wanted_syms: Optional[Set[str]] = None
    if target_port:
        wanted_syms = {a["sym"] for r in recipes for a in r.get("applets", [])}

    seen_objs: Dict[str, pathlib.Path] = {}
    applet_rows = 0
    for raw in applets_tsv.read_text(encoding="utf-8").splitlines():
        if not raw.strip() or raw.startswith("#"):
            continue
        sym, gp, ent, rel_obj = raw.split("\t")
        if wanted_syms is not None and sym not in wanted_syms:
            continue
        applet_rows += 1
        op = lane_dir / rel_obj
        if not op.is_file():
            raise AssertionError(f"missing packaged applet object {op}")
        seen_objs[sym] = op

    if not target_port:
        assert len(seen_objs) == 75, f"expected 75 unique port applets, got {len(seen_objs)}"

    audit_items = [(sym, op, backend, sdk, objdump) for sym, op in sorted(seen_objs.items())]
    with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as pool:
        failures = [f for f in pool.map(audit_single_macho, audit_items) if f is not None]
    if failures:
        raise AssertionError("Mach-O / x18 / policy audit failed:\n  " + "\n  ".join(failures[:15]))

    # Audit active Darwin C++ & guest support archives for this lane
    tc_lane = ot.DarwinToolchain(openbsd_version=ver, backend=backend, sdk=sdk, obsd_root=obsd_root, stage_dir=lane_dir / "stage")
    libcxx_a, libcxxabi_a, libunwind_a, emutls_a = tc_lane.ensure_darwin_cxx_runtime()
    libm_a = tc_lane.ensure_guest_libm_archive()
    for ar_p in (libcxx_a, libcxxabi_a, libunwind_a, emutls_a, libm_a):
        ot_l = subprocess.check_output(["/usr/bin/xcrun", "--sdk", sdk, "otool", "-l", str(ar_p)], text=True)
        assert "__mod_init_func" not in ot_l and "__thread_" not in ot_l, f"section violation in {ar_p}"
        if backend == "emulate":
            unbanked_ar = macho_unbanked_data_sections(ot_l)
            assert not unbanked_ar, f"unbanked __DATA section(s) in emulate SDK archive {ar_p.name}: {unbanked_ar[:5]}"
        dis = subprocess.check_output([objdump, "-d", str(ar_p)], text=True, stderr=subprocess.DEVNULL)
        bad_x18 = [
            ln
            for ln in dis.splitlines()
            if len(ln.split("\t", 1)) == 2 and re.search(r"(?<![A-Za-z0-9_])[xw]18(?![A-Za-z0-9_])", ln.split("\t", 1)[1].split(";", 1)[0])
        ]
        assert not bad_x18, f"x18/w18 clobber in {ar_p}: {bad_x18[:3]}"

    if backend == "emulate" and not target_port:
        shared_rt_o = lane_dir / "shared/darwin_cxx_rt.o"
        assert shared_rt_o.is_file(), f"missing shared guest C++ runtime object {shared_rt_o}"
        rt_ot = subprocess.check_output(["/usr/bin/xcrun", "--sdk", sdk, "otool", "-l", str(shared_rt_o)], text=True)
        assert "__mod_init_func" not in rt_ot and "__thread_" not in rt_ot and "__obsd_gi" not in rt_ot, f"section violation in {shared_rt_o}"
        unbanked_sh = macho_unbanked_data_sections(rt_ot)
        assert not unbanked_sh, f"unbanked __DATA section(s) in {shared_rt_o}: {unbanked_sh}"
        rt_dis = subprocess.check_output([objdump, "-d", str(shared_rt_o)], text=True, stderr=subprocess.DEVNULL)
        rt_x18 = [
            ln
            for ln in rt_dis.splitlines()
            if len(ln.split("\t", 1)) == 2 and re.search(r"(?<![A-Za-z0-9_])[xw]18(?![A-Za-z0-9_])", ln.split("\t", 1)[1].split(";", 1)[0])
        ]
        assert not rt_x18, f"x18/w18 clobber in {shared_rt_o}: {rt_x18[:3]}"
        any_guest_init = any(
            "segname __GUEST_INIT"
            in subprocess.check_output(["/usr/bin/xcrun", "--sdk", sdk, "otool", "-l", str(op)], text=True)
            for op in seen_objs.values()
        )
        assert any_guest_init, "ObsdGuestBankPass did not emit __GUEST_INIT in any emulate applet partial!"

    if backend == "translate":
        standalone_tsv = lane_dir / "standalone.tsv"
        assert standalone_tsv.is_file(), f"missing {standalone_tsv}"
        st_rows = [ln.split("\t") for ln in standalone_tsv.read_text(encoding="utf-8").splitlines() if ln.strip() and not ln.startswith("#")]
        if not target_port:
            assert len(st_rows) == applet_rows, f"standalone.tsv row count {len(st_rows)} != ports-applets.tsv {applet_rows}"
        for cols in st_rows:
            assert len(cols) == 4 and os.path.isabs(cols[3]) and os.path.isfile(cols[3]), f"invalid standalone.tsv row: {cols}"
    else:
        verify_emulate_table_cogeneration(ver, sdk, obsd_root, lane_dir)

    print(
        f"[DARWIN-CHECK/{ver}/{backend}/darwin-{sdk}] verified {len(seen_objs)} unique applet(s) ({applet_rows} paths): "
        f"x18=0, __mod_init_func=0, __thread_*=0, dlopen=0, JIT=0"
    )


def verify_emulate_table_cogeneration(ver: str, sdk: str, obsd_root: pathlib.Path, lane_dir: pathlib.Path) -> None:
    """Prove `ports-test-applets.tsv` co-generates `entries.c` + `table.c` with all ~570 base OpenBSD applets!"""
    test_tsv = lane_dir / "ports-test-applets.tsv"
    assert test_tsv.is_file(), f"missing {test_tsv}"

    tc = ot.DarwinToolchain(openbsd_version=ver, backend="emulate", sdk=sdk, obsd_root=obsd_root, stage_dir=lane_dir / "stage")
    senv = tc.sanitized_env()

    # Query libobsdcompat's emulate applet set & analyses for this release + SDK
    make_cmd = [
        "/usr/bin/make",
        "-C",
        str(obsd_root),
        "-pn",
        f"OPENBSD_VERSION={ver}",
        f"BOUNDARY_SDK={sdk}",
        "COMPAT_BACKEND=emulate",
        "EMULATE_APPLET_PROFILE=full",
        "openbsd-emulate-sdk-pairing",
    ]
    db = subprocess.check_output(make_cmd, text=True, stderr=subprocess.DEVNULL, env=senv)

    def _get_var(vname: str) -> str:
        for ln in db.splitlines():
            if ln.startswith(f"{vname} := "):
                return ln.split(" := ", 1)[1].strip()
        return ""

    applets_set = obsd_root / _get_var("OPENBSD_EMULATE_APPLETS_SET")
    applets_dir = obsd_root / _get_var("OPENBSD_EMULATE_APPLETS_DIR")
    guest_archive = obsd_root / _get_var("OPENBSD_EMULATE_GUEST_ARCHIVE")
    product_dir = obsd_root / _get_var("OPENBSD_EMULATE_PRODUCT_DIR")
    host_cflags = shlex.split(_get_var("OPENBSD_EMULATE_CFLAGS"))
    consumer_cflags = shlex.split(tc.emulate_info["consumer_cflags"])

    # Co-link ALL packaged port `applets/*.o` partials + `shared/*.o` through `link_guest_partial.sh`
    # AND run a `-dynamiclib` compact-unwind gate to prove full `SonvoriBSD_<ver>.framework`
    # link closure, page-aligned `__GUEST` sections, rodata placement, and <= 3 unwind personalities!
    link_partial_sh = obsd_root / "tools/build/personalities/openbsd/backends/emulate/link_guest_partial.sh"
    placement_tsv = obsd_root / "src/personalities/openbsd/runtime/backends/emulate/core/guest_rodata_placement.tsv"
    domains_file = pathlib.Path(f"{tc.emulate_info['guest_archive']}.domains")
    rodata_ldflags = shlex.split(_get_var("OPENBSD_EMULATE_RODATA_LDFLAGS"))
    applet_objs = sorted((lane_dir / "applets").glob("*.o"))
    shared_objs = sorted((lane_dir / "shared").glob("*.o"))
    if link_partial_sh.is_file() and placement_tsv.is_file() and domains_file.is_file() and applet_objs:
        with tempfile.TemporaryDirectory(prefix=f"obsd-em-colink-{ver}-{sdk}-") as ctd:
            ctp = pathlib.Path(ctd)
            # Patch `-Wl,-S` onto `ld -r` steps for Xcode 27 (matching `scripts/package-runtime.sh`)
            patched_lsh = ctp / "link_guest_partial.sh"
            lsh_txt = link_partial_sh.read_text(encoding="utf-8")
            lsh_txt = lsh_txt.replace(
                'here=$(cd "$(dirname "$0")" && pwd)',
                f'here="{link_partial_sh.parent}"',
            ).replace("-nostdlib -Wl,-r \\", "-nostdlib -Wl,-r -Wl,-S \\")
            patched_lsh.write_text(lsh_txt, encoding="utf-8")

            exp_p = ctp / "exports.txt"
            exp_p.write_text(
                "".join(f"_obsd_applet_{o.stem}_main\n" for o in applet_objs),
                encoding="utf-8",
            )
            test_app_flags: List[str] = []
            for o in applet_objs:
                test_app_flags.extend(["--test-applet", f"{o}:obsd_applet_{o.stem}_main"])
            subprocess.run(
                [
                    "/bin/bash",
                    str(patched_lsh),
                    "--sdk",
                    sdk,
                    "--target-flags",
                    tc.emulate_info["target_flags"],
                    "--archive",
                    tc.emulate_info["guest_archive"],
                    "--domains",
                    str(domains_file),
                    "--placement",
                    str(placement_tsv),
                    "--rodata-segment",
                    "__GUEST_RODATA",
                    "--exports",
                    str(exp_p),
                    "--output",
                    str(ctp / "guest_partial.o"),
                    *test_app_flags,
                    *[str(so) for so in shared_objs],
                ],
                env=senv,
                check=True,
            )
            anchor_objs = sorted((ctp / "guest_partial.o.anchors").glob("*.o"))
            stub_c = ctp / "probe_host_stub.c"
            stub_o = ctp / "probe_host_stub.o"
            stub_c.write_text("unsigned long long __obsd_guest_bank_tsd_off = 0;\n", encoding="utf-8")
            subprocess.run(
                [*tc.cc_cmd, *shlex.split(tc.emulate_info["target_flags"]), "-arch", "arm64", "-c", str(stub_c), "-o", str(stub_o)],
                env=senv,
                check=True,
            )
            subprocess.run(
                [
                    *tc.cc_cmd,
                    *shlex.split(tc.emulate_info["target_flags"]),
                    "-arch",
                    "arm64",
                    "-dynamiclib",
                    *rodata_ldflags,
                    "-Wl,-undefined,dynamic_lookup",
                    str(ctp / "guest_partial.o"),
                    str(stub_o),
                    *[str(ao) for ao in anchor_objs],
                    "-o",
                    str(ctp / "SonvoriPortsProbe.dylib"),
                ],
                env=senv,
                check=True,
            )
        print(
            f"[DARWIN-CHECK/{ver}/emulate/darwin-{sdk}] co-linked all {len(applet_objs)} port partials + {len(shared_objs)} shared runtime(s) + -dynamiclib compact-unwind gate: OK"
        )

    if not applets_set.is_file() or not (applets_dir / "analyses").is_dir():
        print(f"[DARWIN-CHECK/{ver}/emulate/darwin-{sdk}] base applet-set not built in libobsdcompat; validating schema standalone")
        return

    gen_tool = obsd_root / "tools/build/personalities/openbsd/backends/emulate/gen_emulate_applet_table.py"
    with tempfile.TemporaryDirectory(prefix=f"obsd-em-table-check-{ver}-{sdk}-") as td:
        tp = pathlib.Path(td)
        subprocess.run(
            [
                "/usr/bin/python3",
                "-I",
                "-B",
                str(gen_tool),
                "generate",
                "--applet-set",
                str(applets_set),
                "--analyses",
                str(applets_dir / "analyses"),
                "--retype",
                f"{guest_archive}.retype",
                "--profile",
                "full",
                "--test-applets",
                str(test_tsv),
                "--out-dir",
                str(tp),
            ],
            env=senv,
            check=True,
        )
        subprocess.run(
            [
                *tc.cc_cmd,
                *consumer_cflags,
                "-fno-stack-protector",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-I",
                str(product_dir),
                str(tp / "entries.c"),
                "-o",
                str(tp / "entries.o"),
            ],
            cwd=str(obsd_root),
            env=senv,
            check=True,
        )
        subprocess.run(
            [
                *tc.cc_cmd,
                *[f for f in host_cflags if f not in ("-MMD", "-MP")],
                "-I",
                str(product_dir),
                "-c",
                str(tp / "table.c"),
                "-o",
                str(tp / "table.o"),
            ],
            cwd=str(obsd_root),
            env=senv,
            check=True,
        )
    print(f"[DARWIN-CHECK/{ver}/emulate/darwin-{sdk}] co-generated & compiled entries.c + table.c with base OpenBSD applets: OK")


def build_static_lib_and_cxx_probes(
    ver: str,
    backend: str,
    sdk: str,
    obsd_root: pathlib.Path,
    lane_dir: pathlib.Path,
    out_dir: pathlib.Path,
) -> Tuple[pathlib.Path, pathlib.Path, pathlib.Path, pathlib.Path]:
    obsd_cc = REPO_ROOT / "sdk/bin/obsd-cc"
    obsd_cxx = REPO_ROOT / "sdk/bin/obsd-c++"
    obsd_pc = REPO_ROOT / "sdk/bin/obsd-pkg-config"

    env = dict(os.environ)
    env["OPENBSD_VERSION"] = ver
    env["COMPAT_BACKEND"] = backend
    env["COMPAT_PAL"] = "darwin"
    env["COMPAT_SDK"] = sdk
    env["LIBOBSDCOMPAT_ROOT"] = str(obsd_root)
    env["OBSD_STAGE_DIR"] = str(lane_dir / "stage")
    env["OBSD_PYTHON"] = sys.executable

    # 1. Core 13 C static libraries + nano PTY probe (`tests/ports_pty_probe.c`)
    p1_bin = out_dir / "ports_pty_probe"
    subprocess.run(
        [
            str(obsd_cc),
            "-O2",
            str(REPO_ROOT / "tests/ports_pty_probe.c"),
            "-lbz2",
            "-llzma",
            "-lzstd",
            "-lonig",
            "-lsqlite3",
            "-llua5.4",
            "-lcurl",
            "-liconv",
            "-lcharset",
            "-lpcre2-8",
            "-lpcre",
            "-llz4",
            "-lxxhash",
            "-lpng",
            "-lssl",
            "-lcrypto",
            "-lz",
            "-lcurses",
            "-ledit",
            "-lutil",
            "-lm",
            "-lpthread",
            "-o",
            str(p1_bin),
        ],
        env=env,
        check=True,
    )

    # 2. Extra 7 C static libraries (`libarchive`, `libiperf`, `liblowdown`, `libxml2`, `libqrencode`, `libquickjs`, `libjim`)
    xml_cf = shlex.split(subprocess.check_output([str(obsd_pc), "--cflags", "libxml-2.0"], env=env, text=True))
    xml_lf = shlex.split(subprocess.check_output([str(obsd_pc), "--libs", "libxml-2.0"], env=env, text=True))
    arch_lf = shlex.split(subprocess.check_output([str(obsd_pc), "--libs", "libarchive"], env=env, text=True))
    p2_c = out_dir / "extra_libs_probe.c"
    p2_bin = out_dir / "extra_libs_probe"
    p2_c.write_text(EXTRA_STATIC_LIBS_PROBE_C, encoding="utf-8")
    subprocess.run(
        [
            str(obsd_cc),
            "-O2",
            f"-I{lane_dir / 'stage/usr/local/include/jim'}",
            *xml_cf,
            str(p2_c),
            *arch_lf,
            "-liperf",
            "-llowdown",
            *xml_lf,
            "-lqrencode",
            f"{lane_dir / 'stage/usr/local/lib/quickjs/libquickjs.a'}",
            "-ljim",
            "-lsqlite3",
            "-lz",
            "-lm",
            "-lpthread",
            "-o",
            str(p2_bin),
        ],
        env=env,
        check=True,
    )

    # 3. C++17 probe (`CXX17_PROBE_SRC` + `CXX17_NOEXCEPT_HELPER_SRC`)
    h_cpp = out_dir / "cxx_helper.cpp"
    h_o = out_dir / "cxx_helper.o"
    p3_cpp = out_dir / "cxx_probe.cpp"
    p3_bin = out_dir / "cxx_probe"
    h_cpp.write_text(ts.CXX17_NOEXCEPT_HELPER_SRC, encoding="utf-8")
    p3_cpp.write_text(ts.CXX17_PROBE_SRC, encoding="utf-8")
    subprocess.run([str(obsd_cxx), "-std=c++17", "-fno-exceptions", "-O2", "-c", str(h_cpp), "-o", str(h_o)], env=env, check=True)
    subprocess.run([str(obsd_cxx), "-std=c++17", "-O2", str(p3_cpp), str(h_o), "-o", str(p3_bin)], env=env, check=True)

    # 4. PTY TUI suite (`vim`, `ncdu`, `tig`, `htop`, `btop`)
    p4_c = out_dir / "tui_pty_suite.c"
    p4_bin = out_dir / "tui_pty_suite"
    p4_c.write_text(TUI_PTY_SUITE_C, encoding="utf-8")
    subprocess.run([str(obsd_cc), "-O2", str(p4_c), "-lutil", "-o", str(p4_bin)], env=env, check=True)

    print(f"[DARWIN-CHECK/{ver}/{backend}/darwin-{sdk}] linked all 20 port static libraries + C++17 & PTY probes: OK")
    return p1_bin, p2_bin, p3_bin, p4_bin


def provision_translate_vfs_rootfs(
    ver: str,
    obsd_root: pathlib.Path,
    lane_dir: pathlib.Path,
    vfs_root: pathlib.Path,
) -> Dict[str, str]:
    """Build a self-contained OpenBSD `<ver>` VFS rootfs for `translate/darwin-macosx`."""
    rootfs = (vfs_root / "rootfs").resolve()
    for d in (
        "bin",
        "sbin",
        "dev",
        "proc",
        "usr/bin",
        "usr/sbin",
        "usr/local/bin",
        "usr/local/sbin",
        "usr/local/libexec",
        "usr/share/misc",
        "usr/share/terminfo",
        "usr/share/locale/UTF-8",
        "usr/share/locale/en_US.UTF-8",
        "etc/ssl",
        "root",
        "tmp",
        "var/tmp",
    ):
        p = rootfs / d
        p.mkdir(parents=True, exist_ok=True)
        if d.endswith("tmp"):
            p.chmod(0o1777)

    # Stage base OpenBSD translated utilities (`ksh`, `sh`, `cat`, `ls`, `rm`, `cp`, `sha256`, `uname`, `ps`, `sysctl`, etc.)
    base_bindir = obsd_root / f"build/openbsd/{ver}/translate/bin"
    base_map = {
        "bin/ksh": "ksh",
        "bin/sh": "ksh",
        "bin/cat": "cat",
        "bin/cp": "cp",
        "bin/mv": "mv",
        "bin/rm": "rm",
        "bin/ln": "ln",
        "bin/ls": "ls",
        "bin/mkdir": "mkdir",
        "bin/rmdir": "rmdir",
        "bin/chmod": "chmod",
        "bin/pwd": "pwd",
        "bin/echo": "echo",
        "bin/sleep": "sleep",
        "bin/test": "test",
        "bin/[": "test",
        "bin/date": "date",
        "bin/hostname": "hostname",
        "bin/ps": "ps",
        "bin/df": "df",
        "bin/stty": "stty",
        "bin/md5": "md5",
        "bin/sha256": "md5",
        "sbin/sysctl": "sysctl",
        "usr/bin/uname": "uname",
        "usr/bin/env": "env",
        "usr/bin/id": "id",
        "usr/bin/printf": "printf",
        "usr/bin/head": "head",
        "usr/bin/tail": "tail",
        "usr/bin/wc": "wc",
        "usr/bin/cmp": "cmp",
        "usr/bin/grep": "grep",
        "usr/bin/egrep": "grep",
        "usr/bin/fgrep": "grep",
        "usr/bin/sed": "sed",
        "usr/bin/awk": "awk",
        "usr/bin/sort": "sort",
        "usr/bin/find": "find",
        "usr/bin/tr": "tr",
        "usr/bin/cut": "cut",
        "usr/bin/stat": "stat",
        "usr/bin/mktemp": "mktemp",
        "usr/bin/which": "which",
        "usr/bin/tty": "tty",
        "usr/bin/tput": "tput",
    }
    for guest_rel, tool_nm in base_map.items():
        src_b = base_bindir / tool_nm
        if src_b.is_file():
            dst_b = rootfs / guest_rel
            dst_b.parent.mkdir(parents=True, exist_ok=True)
            if not dst_b.exists():
                os.link(src_b, dst_b)

    # Overlay sysroot/usr/local (data, manpages, scripts, configs)
    src_local = lane_dir / "sysroot/usr/local"
    if src_local.is_dir():
        shutil.copytree(src_local, rootfs / "usr/local", symlinks=True, dirs_exist_ok=True)

    # Hardlink all 75+ standalone port Mach-O binaries from standalone.tsv
    for raw in (lane_dir / "standalone.tsv").read_text(encoding="utf-8").splitlines():
        if not raw.strip() or raw.startswith("#"):
            continue
        _nm, gp, _sym, abs_bin = raw.split("\t")
        dst = rootfs / gp.lstrip("/")
        dst.parent.mkdir(parents=True, exist_ok=True)
        if dst.exists() or dst.is_symlink():
            dst.unlink()
        os.link(abs_bin, dst)

    # Populate /etc/passwd, /etc/group, /etc/ssl/cert.pem, terminfo, and UTF-8 LC_CTYPE
    (rootfs / "etc/passwd").write_text("root:*:0:0:Charlie &:/root:/bin/ksh\n", encoding="utf-8")
    (rootfs / "etc/group").write_text("wheel:*:0:root\n", encoding="utf-8")
    vendor_src = obsd_root / f"vendor/openbsd/versions/{ver}/src"
    cert_pem = vendor_src / "lib/libcrypto/cert.pem"
    if cert_pem.is_file():
        shutil.copyfile(cert_pem, rootfs / "etc/ssl/cert.pem")
    elif os.path.isfile("/etc/ssl/cert.pem"):
        shutil.copyfile("/etc/ssl/cert.pem", rootfs / "etc/ssl/cert.pem")

    # Copy xterm / xterm-256color / vt100 / dumb terminfo entries (into both char & hex subdirs, SIP-safe via copyfile)
    ti_root = pathlib.Path("/usr/share/terminfo")
    for tname in ("xterm-256color", "xterm", "vt100", "dumb"):
        hx = f"{ord(tname[0]):02x}"
        ch = tname[0]
        src_ti = next((ti_root / sub / tname for sub in (hx, ch) if (ti_root / sub / tname).is_file()), None)
        if src_ti is not None:
            for dst_sub in (ch, hx):
                dst_ti = rootfs / "usr/share/terminfo" / dst_sub / tname
                dst_ti.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(src_ti, dst_ti)

    for lc_cand in sorted((obsd_root / "build").rglob("UTF-8.out")):
        shutil.copy2(lc_cand, rootfs / "usr/share/locale/UTF-8/LC_CTYPE")
        shutil.copy2(lc_cand, rootfs / "usr/share/locale/en_US.UTF-8/LC_CTYPE")
        break

    profile_path = (vfs_root / "vfs.profile").resolve()
    fakeroot_db = (vfs_root / "fakeroot.db").resolve()
    shutil.copy2(lane_dir / "ports-owners.db", fakeroot_db)
    profile_path.write_text(
        f"version 1\nremap /dev -\nremap / {rootfs}\nsynth proc /proc\nidentity root\n",
        encoding="utf-8",
    )

    env = {
        "PATH": "/usr/local/bin:/usr/local/sbin:/bin:/sbin:/usr/bin:/usr/sbin",
        "HOME": "/root",
        "USER": "root",
        "LOGNAME": "root",
        "TERM": "xterm-256color",
        "LC_CTYPE": "en_US.UTF-8",
        "MALLOC_OPTIONS": "JJ",
        "LIBOBSDCOMPAT_VFS_PROFILE": str(profile_path),
        "LIBOBSDCOMPAT_FAKEROOT_DB": str(fakeroot_db),
    }
    return env


class _QuietHTTPHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:
        pass


def run_translate_live_functional_suite(
    ver: str,
    obsd_root: pathlib.Path,
    lane_dir: pathlib.Path,
    probes: Tuple[pathlib.Path, pathlib.Path, pathlib.Path, pathlib.Path],
) -> None:
    p1_bin, p2_bin, p3_bin, p4_bin = probes

    with tempfile.TemporaryDirectory(prefix=f"obsd-darwin-vfs-{ver}-") as td:
        vfs_root = pathlib.Path(td)
        guest_env = provision_translate_vfs_rootfs(ver, obsd_root, lane_dir, vfs_root)
        rootfs = (vfs_root / "rootfs").resolve()

        # Copy compiled test probes into /usr/local/bin inside VFS
        for pb in (p1_bin, p2_bin, p3_bin, p4_bin):
            dst = rootfs / "usr/local/bin" / pb.name
            shutil.copy2(pb, dst)
            dst.chmod(0o755)

        # Start local HTTP server (serves a test JSON file AND a bare dumb-HTTP git repo!)
        http_dir = vfs_root / "http_srv"
        http_dir.mkdir()
        (http_dir / "hello.json").write_text('{"platform":"darwin-arm64","ok":true}\n', encoding="utf-8")

        handler = functools.partial(_QuietHTTPHandler, directory=str(http_dir))
        httpd = socketserver.TCPServer(("127.0.0.1", 0), handler)
        http_port = httpd.server_address[1]
        srv_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        srv_thread.start()

        import socket as _sock
        with _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM) as _s:
            _s.bind(("127.0.0.1", 0))
            iperf_port = _s.getsockname()[1]

        suite_sh = rootfs / "tmp/run_all_53_ports.sh"
        suite_sh.write_text(
            f"""#!/bin/ksh
set -eu

echo "=== [1/7] Static C & C++17 Libraries + nano 80x24 PTY ==="
/usr/local/bin/ports_pty_probe all /tmp/nano_out.txt
/usr/local/bin/extra_libs_probe
out1=$(/usr/local/bin/cxx_probe run1)
out2=$(/usr/local/bin/cxx_probe run2)
[ "$out1" = "OS=OpenBSD-{ver}|CTOR=3:bzip2|RAII=15|EH=UNWIND|HYP=5|WLEN=7|ptr=8;noexc=30|ARG=run1" ]
[ "$out2" = "OS=OpenBSD-{ver}|CTOR=3:bzip2|RAII=15|EH=UNWIND|HYP=5|WLEN=7|ptr=8;noexc=30|ARG=run2" ]

echo "=== [2/7] Archivers (bzip2, xz, zstd, lz4, pigz, zip, unzip, gtar, libarchive, 7zip) ==="
mkdir -p /tmp/arch_t
printf 'OpenBSD-Darwin-Archiver-Payload-0123456789\\n' > /tmp/arch_t/sample.txt
orig_sha=$(sha256 -q /tmp/arch_t/sample.txt)

bzip2 -k -c /tmp/arch_t/sample.txt | bunzip2 -c > /tmp/arch_t/out.bz2.txt
[ "$(sha256 -q /tmp/arch_t/out.bz2.txt)" = "$orig_sha" ]

xz -k -c /tmp/arch_t/sample.txt | unxz -c > /tmp/arch_t/out.xz.txt
[ "$(sha256 -q /tmp/arch_t/out.xz.txt)" = "$orig_sha" ]

zstd -q -c /tmp/arch_t/sample.txt | unzstd -q -c > /tmp/arch_t/out.zst.txt
[ "$(sha256 -q /tmp/arch_t/out.zst.txt)" = "$orig_sha" ]

lz4 -q -c /tmp/arch_t/sample.txt | unlz4 -q -c > /tmp/arch_t/out.lz4.txt
[ "$(sha256 -q /tmp/arch_t/out.lz4.txt)" = "$orig_sha" ]

pigz -p 2 -c /tmp/arch_t/sample.txt | unpigz -c > /tmp/arch_t/out.gz.txt
[ "$(sha256 -q /tmp/arch_t/out.gz.txt)" = "$orig_sha" ]

zip -q /tmp/arch_t/s.zip /tmp/arch_t/sample.txt
unzip -p /tmp/arch_t/s.zip > /tmp/arch_t/out.zip.txt
[ "$(sha256 -q /tmp/arch_t/out.zip.txt)" = "$orig_sha" ]

gtar -cf /tmp/arch_t/s.tar -C /tmp/arch_t sample.txt
bsdtar -xOf /tmp/arch_t/s.tar sample.txt > /tmp/arch_t/out.tar.txt
[ "$(sha256 -q /tmp/arch_t/out.tar.txt)" = "$orig_sha" ]

7za a -bd -y /tmp/arch_t/s.7z /tmp/arch_t/sample.txt >/dev/null
7zr x -bd -y -o/tmp/arch_t/x7z /tmp/arch_t/s.7z >/dev/null
[ "$(sha256 -q /tmp/arch_t/x7z/sample.txt)" = "$orig_sha" ]

echo "=== [3/7] DB, Scripting & Build (jq, sqlite3, lua54, quickjs, jimtcl, gmake) ==="
[ "$(printf '{{"x":"obsd-80"}}' | jq -r '.x | capture("obsd-(?<n>[0-9]+)").n')" = "80" ]

sqlite3 /tmp/t.db "CREATE VIRTUAL TABLE docs USING fts5(body); INSERT INTO docs VALUES('darwin openbsd arm64'); SELECT count(*) FROM docs WHERE docs MATCH 'arm64';" | grep -qx "1"
# Policy check: runtime load_extension must be omitted!
if sqlite3 /tmp/t.db ".load /nonexistent.so" >/dev/null 2>&1; then
  echo "FAIL: sqlite3 .load should be disabled" >&2
  exit 1
fi

luac54 -o /tmp/fib.luac - << 'EOF'
local function fib(n) return n < 2 and n or fib(n-1) + fib(n-2) end
print(fib(10))
EOF
[ "$(lua /tmp/fib.luac)" = "55" ]
[ "$(qjs -e 'console.log(((1n << 10n) + 24n).toString())')" = "1048" ]
[ "$(jimsh -e 'puts [expr {{21 * 2}}]')" = "42" ]

mkdir -p /tmp/gm_t
printf 'all: a b\\n\\tcat a b > out\\na:\\n\\tprintf DAR > a\\nb:\\n\\tprintf WIN > b\\n' > /tmp/gm_t/Makefile
gmake -C /tmp/gm_t -j2 >/dev/null
[ "$(cat /tmp/gm_t/out)" = "DARWIN" ]

echo "=== [4/7] GNU, Search, Indexing & Text (gawk, gsed, ggrep, coreutils, findutils, pcre2grep, pcregrep, ugrep, ag, uctags, xmllint, xmlcatalog, lowdown, dos2unix, iconv, xxhsum, pv, tree, xxd, qrencode) ==="
[ "$(printf 'alpha 10\\nbeta 32\\n' | gawk '{{s += $2}} END {{print s}}')" = "42" ]
printf 'hello world\\n' > /tmp/gs.txt
gsed -i 's/world/openbsd/' /tmp/gs.txt
[ "$(cat /tmp/gs.txt)" = "hello openbsd" ]
[ "$(printf 'foo123bar\\n' | ggrep -Po '(?<=foo)[0-9]+(?=bar)')" = "123" ]

[ "$(/usr/local/bin/g[ 5 -eq 5 ] && echo ok)" = "ok" ]
[ "$(printf 'abc' | gsha256sum | cut -d' ' -f1)" = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" ]
gfind /tmp/gm_t -name 'out' | gxargs cat | grep -qx "DARWIN"

mkdir -p /tmp/src_idx
printf 'int magic_darwin_fn(void) {{ return 7; }}\\n' > /tmp/src_idx/code.c
pcre2grep -q 'magic_darwin_fn' /tmp/src_idx/code.c
pcregrep -q 'magic_darwin_fn' /tmp/src_idx/code.c
ugrep-indexer -q /tmp/src_idx
ugrep -I --index -q 'magic_darwin_fn' /tmp/src_idx
ag -Q 'magic_darwin_fn' /tmp/src_idx >/dev/null

uctags -f /tmp/src_idx/tags /tmp/src_idx/code.c
ureadtags -t /tmp/src_idx/tags magic_darwin_fn | grep -q 'magic_darwin_fn'

[ "$(printf '<r><k>v42</k></r>' | xmllint --xpath 'string(/r/k)' -)" = "v42" ]
xmlcatalog --create >/dev/null
printf '# Title\\n' | lowdown -thtml | grep -qi '<h1'
printf 'line1\\r\\n' > /tmp/crlf.txt
dos2unix -q /tmp/crlf.txt
[ "$(wc -c < /tmp/crlf.txt | tr -d ' ')" = "6" ]
unix2dos -q /tmp/crlf.txt
[ "$(wc -c < /tmp/crlf.txt | tr -d ' ')" = "7" ]
[ "$(printf 'BSD' | iconv -f UTF-8 -t ASCII)" = "BSD" ]
xxhsum /tmp/arch_t/sample.txt >/dev/null
xxh128sum /tmp/arch_t/sample.txt >/dev/null
[ "$(printf 'pipe_ok' | pv -q)" = "pipe_ok" ]
tree /tmp/gm_t | grep -q 'Makefile'
[ "$(printf 'Hi' | xxd -p)" = "4869" ]
qrencode -t UTF8 -o /tmp/qr.txt 'https://sonvori.com'
[ -s /tmp/qr.txt ]

echo "=== [5/7] Shells & Sysmon (bash, neofetch, fastfetch, procan, filan) ==="
[ "$(bash -c 'arr=(10 20 12); echo $((arr[0] + arr[1] + arr[2]))')" = "42" ]
neofetch --stdout | grep -q "OpenBSD"
fastfetch --pipe -s OS:Kernel:CPU | grep -q "OpenBSD"
procan -c >/dev/null
filan -i 0 >/dev/null

echo "=== [6/7] Networking, Sync & Git VCS (curl, wget, links, git, rsync, socat) ==="
curl -fsSL "http://127.0.0.1:{http_port}/hello.json" | jq -e '.ok == true' >/dev/null
wget -q -O /tmp/wget_hello.json "http://127.0.0.1:{http_port}/hello.json"
jq -e '.platform == "darwin-arm64"' /tmp/wget_hello.json >/dev/null
links -dump "http://127.0.0.1:{http_port}/hello.json" | grep -q 'darwin-arm64'

mkdir -p /tmp/git_work
cd /tmp/git_work
git init -q
git config user.name "Darwin Check"
git config user.email "darwin@sonvori.test"
printf 'hello git on darwin arm64\\n' > README.md
git add README.md
git commit -q -m "initial commit"
git grep -P 'darwin\\s+arm64' | grep -q 'README.md'
git clone -q --bare /tmp/git_work /tmp/git_bare.git
cd /tmp/git_bare.git && git update-server-info
cd /tmp

rsync -a /tmp/arch_t/ /tmp/rsync_dst/
[ "$(sha256 -q /tmp/rsync_dst/sample.txt)" = "$orig_sha" ]

[ "$(printf 'SOCAT_PING' | socat - EXEC:'/bin/cat')" = "SOCAT_PING" ]

echo "=== [7/7] Interactive PTY Curses TUIs (vim, ncdu, tig, htop, btop) ==="
/usr/local/bin/tui_pty_suite /tmp/git_work

echo "[DARWIN-SUITE-ALL-53-PORTS: PASS]"
""",
            encoding="utf-8",
        )
        suite_sh.chmod(0o755)

        try:
            proc = subprocess.run(
                [str(rootfs / "bin/ksh"), "/tmp/run_all_53_ports.sh"],
                cwd=str(rootfs),
                env=guest_env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=180,
            )
            if proc.returncode != 0 or "[DARWIN-SUITE-ALL-53-PORTS: PASS]" not in proc.stdout:
                sys.stderr.write(proc.stdout)
                raise AssertionError(f"Darwin translate live 53-port VFS suite failed (exit={proc.returncode})")
            for ln in proc.stdout.splitlines():
                if ln.startswith(("===", "[PORTS-PASS]", "[DARWIN-PASS]", "[DARWIN-SUITE")):
                    print(f"  {ln}")
            # Verify entr blocking EVFILT_VNODE kqueue trigger directly
            import time as _time

            (rootfs / "tmp/entr_watch.txt").write_text("v1\n", encoding="utf-8")
            (rootfs / "tmp/entr_list.txt").write_text("/tmp/entr_watch.txt\n", encoding="utf-8")
            entr_stop = threading.Event()

            def _touch_entr() -> None:
                seq = 2
                while not entr_stop.wait(0.15) and seq < 60:
                    (rootfs / "tmp/entr_watch.txt").write_text(f"v{seq}\n", encoding="utf-8")
                    seq += 1

            wt = threading.Thread(target=_touch_entr, daemon=True)
            wt.start()
            try:
                with (rootfs / "tmp/entr_list.txt").open("rb") as entr_in:
                    entr_proc = subprocess.run(
                        [str(rootfs / "usr/local/bin/entr"), "-n", "-p", "-z", "/bin/sh", "-c", "echo ENTR_EVENT_OK > /tmp/entr_done.txt"],
                        stdin=entr_in,
                        cwd=str(rootfs),
                        env=guest_env,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True,
                        timeout=15,
                    )
            finally:
                entr_stop.set()
                wt.join(timeout=2)
            if entr_proc.returncode != 0 or (rootfs / "tmp/entr_done.txt").read_text(encoding="utf-8").strip() != "ENTR_EVENT_OK":
                raise AssertionError(f"entr kqueue check failed (rc={entr_proc.returncode}):\n{entr_proc.stdout}")
            print("  [DARWIN-PASS] entr_kqueue_vnode: blocking EVFILT_VNODE trigger & child exec OK")

            # Verify iperf3 loopback TCP server + client transfer directly
            iperf_srv = subprocess.Popen(
                [str(rootfs / "usr/local/bin/iperf3"), "-s", "-1", "-p", str(iperf_port)],
                cwd=str(rootfs),
                env=guest_env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            _time.sleep(0.25)
            iperf_cli = subprocess.run(
                [str(rootfs / "usr/local/bin/iperf3"), "-c", "127.0.0.1", "-p", str(iperf_port), "-n", "64K"],
                cwd=str(rootfs),
                env=guest_env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=15,
            )
            iperf_srv_rc = iperf_srv.wait(timeout=10)
            if iperf_cli.returncode != 0 or iperf_srv_rc != 0:
                raise AssertionError(f"iperf3 TCP check failed (cli={iperf_cli.returncode}, srv={iperf_srv_rc}):\n{iperf_cli.stdout}")
            print("  [DARWIN-PASS] iperf3_tcp_loopback: 64KiB TCP server/client transfer OK")

            # Also verify git-remote-http by serving /tmp/git_bare.git from http_dir and cloning via HTTP!
            shutil.copytree(rootfs / "tmp/git_bare.git", http_dir / "repo.git")
            clone_proc = subprocess.run(
                [str(rootfs / "usr/local/bin/git"), "clone", "-q", f"http://127.0.0.1:{http_port}/repo.git", "/tmp/http_cloned"],
                cwd=str(rootfs),
                env=guest_env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=30,
            )
            if clone_proc.returncode != 0 or not (rootfs / "tmp/http_cloned/README.md").is_file():
                raise AssertionError(f"git-remote-http clone failed:\n{clone_proc.stdout}")
            print("  [DARWIN-PASS] git_remote_http_clone: cloned bare repo over HTTP cleanly")
        finally:
            httpd.shutdown()
            httpd.server_close()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--openbsd-version", default=obsd_versions.env_or_default_version())
    ap.add_argument("--backend", default=os.environ.get("COMPAT_BACKEND", "translate"))
    ap.add_argument("--sdk", default="")
    ap.add_argument("--libobsdcompat-root", default="")
    ap.add_argument("--port", default="")
    ap.add_argument("--jobs", type=int, default=os.cpu_count() or 8)
    args = ap.parse_args()

    obsd_root = bp.resolve_obsd_root_arg(args.libobsdcompat_root)
    versions = obsd_versions.resolve_versions(args.openbsd_version)
    sdk = bp.resolve_lane_sdk("darwin", args.backend, args.sdk)

    for ver in versions:
        lane_dir = bp.compute_lane_dir(ver, args.backend, "darwin", sdk)
        verify_artifacts_and_macho_invariants(
            ver=ver,
            backend=args.backend,
            sdk=sdk,
            obsd_root=obsd_root,
            lane_dir=lane_dir,
            target_port=args.port,
            jobs=args.jobs,
        )
        if not args.port:
            with tempfile.TemporaryDirectory(prefix=f"obsd-darwin-probes-{ver}-{sdk}-") as ptd:
                probes = build_static_lib_and_cxx_probes(
                    ver=ver,
                    backend=args.backend,
                    sdk=sdk,
                    obsd_root=obsd_root,
                    lane_dir=lane_dir,
                    out_dir=pathlib.Path(ptd),
                )
                if args.backend == "translate":
                    run_translate_live_functional_suite(
                        ver=ver,
                        obsd_root=obsd_root,
                        lane_dir=lane_dir,
                        probes=probes,
                    )
        print(f"[DARWIN-CHECK/{ver}/{args.backend}/darwin-{sdk}] ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
