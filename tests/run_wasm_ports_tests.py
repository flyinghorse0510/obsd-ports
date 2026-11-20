#!/usr/bin/env python3
"""
tests/run_wasm_ports_tests.py -- Comprehensive Tri-Release (OpenBSD 7.8 + 7.9 + 8.0)
WASM64 Port Verification Suite for `obsd-ports`.

Wired into `make check OPENBSD_VERSION=7.8|7.9|8.0` (and runnable standalone for
all releases via `--openbsd-version all`).

Verifies:
  1. Packaging & ABI Artifacts (`stage/`, `applets/*.o`, `ports-applets.tsv`,
     `sysroot/usr/local/`, `ports.svfs.gz`, `ports-owners.db`, `packages/*.tgz`).
  2. C Static Library & Header Closure (`tests/ports_pty_probe.c` compiled with
     `sdk/bin/obsd-cc` against `libbz2.a`, `liblzma.a`, `libzstd.a`, `libonig.a`,
     `libsqlite3.a`, `liblua5.4.a`, and `libcurl.a`).
  3. WASM64 Multi-Process Functional Execution on OpenBSD `7.8` and `7.9`:
     - `bzip2`/`bunzip2`/`bzcat` compress + decompress SHA256 round-trips
     - `xz`/`unxz`/`xzcat`/`lzma`/`unlzma`/`lzcat` SHA256 round-trips
     - `zstd`/`unzstd`/`zstdcat` SHA256 round-trips
     - `jq` JSON structural transform + Oniguruma regex capture/filter pipeline
     - `sqlite3 /tmp/test.db` persistent relational + FTS5 + JSON SQL queries
     - `lua54`, `lua` alias, and `luac54` bytecode fib/coroutine/table execution
     - `tree /usr/local` directory hierarchy rendering
     - `nano --version` + interactive 80x24 `openpty()` curses & UTF-8 save/exit
     - `curl --version` (LibreSSL + zlib + zstd) + live HTTP & live HTTPS TLS
       (`curl -fsSL https://example.com` with `/etc/ssl/cert.pem`) over `SVNP/1`!
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import pathlib
import shutil
import struct
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]

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
]

REQUIRED_PKGCONFIGS = [
    "libpcre2-8.pc",
    "libpcre2-16.pc",
    "libpcre2-32.pc",
    "libpcre2-posix.pc",
    "libpcre.pc",
    "libpcre16.pc",
    "libpcreposix.pc",
    "liblz4.pc",
    "libxxhash.pc",
    "libpng.pc",
    "libpng16.pc",
]

REQUIRED_APPLET_PATHS = [
    "/usr/local/bin/bzip2",
    "/usr/local/bin/bunzip2",
    "/usr/local/bin/bzcat",
    "/usr/local/bin/xz",
    "/usr/local/bin/unxz",
    "/usr/local/bin/xzcat",
    "/usr/local/bin/lzma",
    "/usr/local/bin/unlzma",
    "/usr/local/bin/lzcat",
    "/usr/local/bin/zstd",
    "/usr/local/bin/unzstd",
    "/usr/local/bin/zstdcat",
    "/usr/local/bin/jq",
    "/usr/local/bin/sqlite3",
    "/usr/local/bin/lua54",
    "/usr/local/bin/lua",
    "/usr/local/bin/luac54",
    "/usr/local/bin/tree",
    "/usr/local/bin/nano",
    "/usr/local/bin/curl",
    "/usr/local/bin/iconv",
    "/usr/local/bin/pcre2grep",
    "/usr/local/bin/pcre2test",
    "/usr/local/bin/pcregrep",
    "/usr/local/bin/pcretest",
    "/usr/local/bin/lz4",
    "/usr/local/bin/lz4c",
    "/usr/local/bin/lz4cat",
    "/usr/local/bin/unlz4",
    "/usr/local/bin/xxhsum",
    "/usr/local/bin/xxh32sum",
    "/usr/local/bin/xxh64sum",
    "/usr/local/bin/xxh128sum",
]

HOST_SUITE_C = r'''
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
ports_suite_thread(void *arg)
{
	(void)arg;
	const struct obsd_emulate_embed_builtin *builtin = obsd_emulate_embed_builtin();
	char arg0[] = "ksh";
	char arg1[] = "/tmp/run_ports_guest_suite.sh";
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
	    OBSD_EMULATE_EMBED_PREEMPT_STALLED;
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
	req.hostname = "obsd-ports-check";
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
suite_svnp_shm_lo(void)
{
	uintptr_t p = obsd_wasm_svnp_shm_addr ? obsd_wasm_svnp_shm_addr() : 0U;
	return (uint32_t)(p & 0xffffffffu);
}

EMSCRIPTEN_KEEPALIVE uint32_t
suite_svnp_shm_hi(void)
{
	uint64_t p = (uint64_t)(obsd_wasm_svnp_shm_addr ? obsd_wasm_svnp_shm_addr() : 0U);
	return (uint32_t)(p >> 32);
}

EMSCRIPTEN_KEEPALIVE uint32_t
suite_io_buf_addr(void)
{
	return (uint32_t)(uintptr_t)g_io_buf;
}

EMSCRIPTEN_KEEPALIVE int
suite_start(void)
{
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
	if (pthread_create(&t, NULL, ports_suite_thread, NULL) != 0)
		return -3;
	pthread_detach(t);
	return 0;
}

EMSCRIPTEN_KEEPALIVE int
suite_read_output(void)
{
	if (g_out_pipe[0] < 0)
		return 0;
	ssize_t n = obsd_wasm_host_read(g_out_pipe[0], g_io_buf, sizeof(g_io_buf));
	return (n > 0) ? (int)n : 0;
}

EMSCRIPTEN_KEEPALIVE int
suite_is_done(void)
{
	return __atomic_load_n(&g_done, __ATOMIC_SEQ_CST);
}

EMSCRIPTEN_KEEPALIVE int
suite_wait_status(void)
{
	return g_wait_status;
}

EMSCRIPTEN_KEEPALIVE uint32_t
suite_embed_error(void)
{
	return g_embed_error;
}
'''

GUEST_SUITE_SH_TEMPLATE = r'''#!/bin/ksh
set -e

EXPECTED_REL="__OPENBSD_VERSION__"

if [ ! -s /etc/pwd.db ]; then
	cp /etc/master.passwd /etc/master.passwd.in
	/usr/sbin/pwd_mkdb -p -d /etc /etc/master.passwd.in
fi

fail() {
	echo "[PORTS-FAIL] $*"
	exit 1
}

pass() {
	echo "[PORTS-PASS] $1: $2"
}

# 01. Release & PATH resolution check
OS_SYS=$(uname -s)
OS_REL=$(uname -r)
[ "$OS_SYS" = "OpenBSD" ] || fail "expected OpenBSD, got $OS_SYS"
[ "$OS_REL" = "$EXPECTED_REL" ] || fail "expected release $EXPECTED_REL, got $OS_REL"

for bin in bzip2 bunzip2 bzcat bzip2recover xz unxz xzcat lzma unlzma lzcat zstd unzstd zstdcat jq sqlite3 lua54 lua luac54 tree nano curl iconv pcre2grep pcre2test pcregrep pcretest lz4 lz4c lz4cat unlz4 xxhsum xxh32sum xxh64sum xxh128sum; do
	resolved=$(command -v "$bin") || fail "command -v $bin failed"
	[ "$resolved" = "/usr/local/bin/$bin" ] || fail "expected /usr/local/bin/$bin, got $resolved"
done
pass "01_release_and_which" "OpenBSD $OS_REL verified; all 33 port binaries on PATH"

# 02. Static library C API linkage & execution check
/usr/libexec/ports_pty_probe libs

# Build deterministic multi-KB test payload for archiver SHA256 round-trips
rm -rf /tmp/arch_test
mkdir -p /tmp/arch_test
cat /etc/services /etc/protocols /etc/group > /tmp/arch_test/payload.bin
ORIG_SHA=$(/bin/sha256 -q /tmp/arch_test/payload.bin)
ORIG_BYTES=$(wc -c < /tmp/arch_test/payload.bin | tr -d ' ')
[ -n "$ORIG_SHA" ] || fail "sha256 payload failed"

# 03. archivers/bzip2 (bzip2, bunzip2, bzcat)
cp /tmp/arch_test/payload.bin /tmp/arch_test/t_bz.bin
bzip2 -9 -k /tmp/arch_test/t_bz.bin
[ -s /tmp/arch_test/t_bz.bin.bz2 ] || fail "bzip2 did not create .bz2"
BZ_CAT_SHA=$(bzcat /tmp/arch_test/t_bz.bin.bz2 | /bin/sha256 -q)
[ "$BZ_CAT_SHA" = "$ORIG_SHA" ] || fail "bzcat SHA256 mismatch: $BZ_CAT_SHA != $ORIG_SHA"
rm -f /tmp/arch_test/t_bz.bin
bunzip2 /tmp/arch_test/t_bz.bin.bz2
BZ_UNZ_SHA=$(/bin/sha256 -q /tmp/arch_test/t_bz.bin)
[ "$BZ_UNZ_SHA" = "$ORIG_SHA" ] || fail "bunzip2 SHA256 mismatch: $BZ_UNZ_SHA != $ORIG_SHA"
BZ_PIPE_SHA=$(bzip2 -c < /tmp/arch_test/payload.bin | bunzip2 -c | /bin/sha256 -q)
[ "$BZ_PIPE_SHA" = "$ORIG_SHA" ] || fail "bzip2|bunzip2 pipeline SHA256 mismatch"
pass "03_bzip2_sha256_roundtrip" "bzip2/bunzip2/bzcat exact SHA256 ($ORIG_BYTES bytes, $ORIG_SHA)"

# 04. archivers/xz (xz, unxz, xzcat, lzma, unlzma, lzcat)
cp /tmp/arch_test/payload.bin /tmp/arch_test/t_xz.bin
xz -3 -k /tmp/arch_test/t_xz.bin
[ -s /tmp/arch_test/t_xz.bin.xz ] || fail "xz did not create .xz"
XZ_CAT_SHA=$(xzcat /tmp/arch_test/t_xz.bin.xz | /bin/sha256 -q)
[ "$XZ_CAT_SHA" = "$ORIG_SHA" ] || fail "xzcat SHA256 mismatch"
rm -f /tmp/arch_test/t_xz.bin
unxz /tmp/arch_test/t_xz.bin.xz
[ "$(/bin/sha256 -q /tmp/arch_test/t_xz.bin)" = "$ORIG_SHA" ] || fail "unxz SHA256 mismatch"

cp /tmp/arch_test/payload.bin /tmp/arch_test/t_lz.bin
lzma -3 -k /tmp/arch_test/t_lz.bin
[ -s /tmp/arch_test/t_lz.bin.lzma ] || fail "lzma did not create .lzma"
LZ_CAT_SHA=$(lzcat /tmp/arch_test/t_lz.bin.lzma | /bin/sha256 -q)
[ "$LZ_CAT_SHA" = "$ORIG_SHA" ] || fail "lzcat SHA256 mismatch"
rm -f /tmp/arch_test/t_lz.bin
unlzma /tmp/arch_test/t_lz.bin.lzma
[ "$(/bin/sha256 -q /tmp/arch_test/t_lz.bin)" = "$ORIG_SHA" ] || fail "unlzma SHA256 mismatch"
pass "04_xz_lzma_sha256_roundtrip" "xz/unxz/xzcat/lzma/unlzma/lzcat exact SHA256 ($ORIG_SHA)"

# 05. archivers/zstd (zstd, unzstd, zstdcat)
zstd -3 -q -f /tmp/arch_test/payload.bin -o /tmp/arch_test/t.zst
[ -s /tmp/arch_test/t.zst ] || fail "zstd did not create .zst"
ZSTD_CAT_SHA=$(zstdcat /tmp/arch_test/t.zst | /bin/sha256 -q)
[ "$ZSTD_CAT_SHA" = "$ORIG_SHA" ] || fail "zstdcat SHA256 mismatch"
unzstd -q -f /tmp/arch_test/t.zst -o /tmp/arch_test/t_unzstd.bin
[ "$(/bin/sha256 -q /tmp/arch_test/t_unzstd.bin)" = "$ORIG_SHA" ] || fail "unzstd SHA256 mismatch"
ZSTD_PIPE_SHA=$(zstd -19 -q -c < /tmp/arch_test/payload.bin | unzstd -q -c | /bin/sha256 -q)
[ "$ZSTD_PIPE_SHA" = "$ORIG_SHA" ] || fail "zstd -19 | unzstd pipeline SHA256 mismatch"
pass "05_zstd_sha256_roundtrip" "zstd/unzstd/zstdcat exact SHA256 ($ORIG_SHA)"

# 06. textproc/jq (JSON transform + Oniguruma regex filter/capture pipeline)
JQ_OUT1=$(printf '{"openbsd":{"release":"%s","ports":["bzip2","xz","zstd","jq","sqlite3","lua54","tree","nano","curl"]}}\n' "$OS_REL" | jq -r '.openbsd.ports | join(",")')
[ "$JQ_OUT1" = "bzip2,xz,zstd,jq,sqlite3,lua54,tree,nano,curl" ] || fail "jq join mismatch: $JQ_OUT1"

JQ_OUT2=$(printf '[{"name":"obsd-7.8","ok":true},{"name":"linux-6.1","ok":true},{"name":"obsd-7.9","ok":true}]\n' | jq -c '[.[] | select(.name | test("^obsd-[0-9]+\\.[0-9]+$")) | .name | capture("^obsd-(?<ver>[0-9]+\\.[0-9]+)$").ver]')
[ "$JQ_OUT2" = '["7.8","7.9"]' ] || fail "jq oniguruma regex mismatch: $JQ_OUT2"
pass "06_jq_json_and_onig_regex" "jq join + Oniguruma test/capture verified ($JQ_OUT2)"

# 07. databases/sqlite3 (persistent DB + transactions + FTS5 + JSON)
rm -f /tmp/test.db
sqlite3 /tmp/test.db <<'SQL_INIT'
PRAGMA journal_mode=DELETE;
CREATE TABLE ports (id INTEGER PRIMARY KEY, cat TEXT NOT NULL, name TEXT NOT NULL, score INTEGER NOT NULL);
BEGIN TRANSACTION;
INSERT INTO ports (cat, name, score) VALUES
  ('archivers', 'zstd', 95),
  ('textproc', 'jq', 98),
  ('databases', 'sqlite3', 99),
  ('net', 'curl', 100);
COMMIT;
CREATE VIRTUAL TABLE docs USING fts5(title, body);
INSERT INTO docs VALUES ('OpenBSD WASM64', 'Authentic OpenBSD ports running in WebAssembly 64-bit');
INSERT INTO docs VALUES ('LibreSSL TLS', 'Ported curl verified against /etc/ssl/cert.pem');
SQL_INIT

[ -s /tmp/test.db ] || fail "sqlite3 did not persist /tmp/test.db"
SQL_OUT=$(sqlite3 /tmp/test.db "SELECT COUNT(*) || ':' || SUM(score) || ':' || (SELECT name FROM ports ORDER BY score DESC LIMIT 1) FROM ports;")
[ "$SQL_OUT" = "4:392:curl" ] || fail "sqlite3 persistent query mismatch: $SQL_OUT"
FTS_OUT=$(sqlite3 /tmp/test.db "SELECT title FROM docs WHERE docs MATCH 'WebAssembly';")
[ "$FTS_OUT" = "OpenBSD WASM64" ] || fail "sqlite3 FTS5 query mismatch: $FTS_OUT"

# 20-iteration MALLOC_OPTIONS=JJ variadic stack/heap poison regression check
jj_i=0
while [ $jj_i -lt 20 ]; do
	JJ_OUT=$(MALLOC_OPTIONS=JJ sqlite3 :memory: 'SELECT sqlite_version(), 6*7;') || fail "MALLOC_OPTIONS=JJ sqlite3 crashed on iter $jj_i"
	case "$JJ_OUT" in
		*"|42") ;;
		*) fail "MALLOC_OPTIONS=JJ sqlite3 unexpected output on iter $jj_i: $JJ_OUT" ;;
	esac
	jj_i=$((jj_i + 1))
done
pass "07_sqlite3_persistent_sql" "sqlite3 /tmp/test.db persisted ($SQL_OUT, FTS5='$FTS_OUT', 20x MALLOC_OPTIONS=JJ OK)"

# 08. lang/lua/5.4 (lua54, lua alias, and luac54 bytecode execution)
cat > /tmp/ports_test.lua <<'LUA_EOF'
local function fib(n)
  local a, b = 0, 1
  for _ = 1, n do a, b = b, a + b end
  return a
end

local co = coroutine.create(function()
  for i = 1, 4 do
    coroutine.yield(i * i)
  end
end)

local squares = {}
while true do
  local ok, v = coroutine.resume(co)
  if not ok or v == nil then break end
  squares[#squares + 1] = tostring(v)
end

local t = { "curl", "jq", "sqlite3", "lua54" }
table.sort(t)
print(string.format("FIB20=%d;CO=%s;SORT=%s", fib(20), table.concat(squares, ","), table.concat(t, "+")))
LUA_EOF

LUA_OUT1=$(lua54 /tmp/ports_test.lua)
[ "$LUA_OUT1" = "FIB20=6765;CO=1,4,9,16;SORT=curl+jq+lua54+sqlite3" ] || fail "lua54 output mismatch: $LUA_OUT1"
LUA_ALIAS_OUT=$(lua -e 'print("ALIAS_OK=" .. _VERSION:sub(1,7))')
[ "$LUA_ALIAS_OUT" = "ALIAS_OK=Lua 5.4" ] || fail "lua alias mismatch: $LUA_ALIAS_OUT"
luac54 -o /tmp/ports_test.luac /tmp/ports_test.lua
[ -s /tmp/ports_test.luac ] || fail "luac54 did not produce bytecode"
LUAC_OUT=$(lua54 /tmp/ports_test.luac)
[ "$LUAC_OUT" = "$LUA_OUT1" ] || fail "luac54 bytecode execution mismatch: $LUAC_OUT"
pass "08_lua54_and_luac54" "lua54 + lua + luac54 verified ($LUA_OUT1)"

# 09. sysutils/tree
TREE_OUT=$(tree /usr/local)
echo "$TREE_OUT" | grep -q "bin" || fail "tree /usr/local missing bin"
echo "$TREE_OUT" | grep -q "include" || fail "tree /usr/local missing include"
echo "$TREE_OUT" | grep -q "share" || fail "tree /usr/local missing share"
echo "$TREE_OUT" | grep -q "|--" || fail "tree /usr/local missing ASCII hierarchy connectors"
pass "09_tree_usr_local" "tree /usr/local rendered hierarchy ($(echo "$TREE_OUT" | wc -l | tr -d ' ') lines)"

# 10. editors/nano (--version + interactive openpty 80x24 curses & UTF-8 save/exit)
NANO_VER=$(nano --version)
echo "$NANO_VER" | grep -q "GNU nano" || fail "nano --version missing GNU nano"
/usr/libexec/ports_pty_probe nano-pty /tmp/nano_pty_check.txt
pass "10_nano_version_and_pty" "$(echo "$NANO_VER" | head -n 1)"

# 11. net/curl (--version + live SVNP/1 local HTTP + live HTTPS https://example.com)
CURL_VER=$(curl --version)
echo "$CURL_VER" | grep -q "LibreSSL" || fail "curl --version missing LibreSSL: $CURL_VER"
echo "$CURL_VER" | grep -q "zlib" || fail "curl --version missing zlib: $CURL_VER"
echo "$CURL_VER" | grep -q "zstd" || fail "curl --version missing zstd: $CURL_VER"
echo "$CURL_VER" | grep -q "https" || fail "curl --version missing https protocol: $CURL_VER"

LOCAL_HTTP=$(curl -fsSL "http://127.0.0.1:__LOCAL_HTTP_PORT__/obsd-ports-ping")
[ "$LOCAL_HTTP" = "SVNP_HTTP_OK:$EXPECTED_REL" ] || fail "local SVNP/1 HTTP curl mismatch: $LOCAL_HTTP"

LIVE_HTTPS=$(curl -fsSL --connect-timeout 15 --max-time 30 https://example.com)
echo "$LIVE_HTTPS" | grep -q "Example Domain" || fail "live HTTPS curl https://example.com missing 'Example Domain'"
pass "11_curl_libressl_and_live_https" "$(echo "$CURL_VER" | head -n 1) + live HTTPS https://example.com OK"

# 12. Wave-2 Foundation Applets under MALLOC_OPTIONS=JJ (iconv, pcre2grep, pcregrep, lz4, xxhsum)
ICONV_RT=$(printf 'OpenBSD WASM64 \303\251\303\240\303\274\n' | MALLOC_OPTIONS=JJ iconv -f UTF-8 -t ISO-8859-1 | MALLOC_OPTIONS=JJ iconv -f ISO-8859-1 -t UTF-8)
[ "$ICONV_RT" = "$(printf 'OpenBSD WASM64 \303\251\303\240\303\274\n')" ] || fail "iconv UTF-8<->ISO-8859-1 mismatch: $ICONV_RT"

PCRE2_OUT=$(printf 'alpha-1\nOpenBSD-7.8\nOpenBSD-7.9\n' | MALLOC_OPTIONS=JJ pcre2grep -o1 '^OpenBSD-([0-9]+\.[0-9]+)$' | tr '\n' ',')
[ "$PCRE2_OUT" = "7.8,7.9," ] || fail "pcre2grep output mismatch: $PCRE2_OUT"

PCRE1_OUT=$(printf 'low\nOpenBSD_WASM64\n' | MALLOC_OPTIONS=JJ pcregrep -u '^\p{Lu}[A-Za-z0-9_]+$')
[ "$PCRE1_OUT" = "OpenBSD_WASM64" ] || fail "pcregrep UTF-8 unicode properties mismatch: $PCRE1_OUT"

MALLOC_OPTIONS=JJ lz4 -q -f /tmp/arch_test/payload.bin /tmp/arch_test/t.lz4
[ -s /tmp/arch_test/t.lz4 ] || fail "lz4 did not create .lz4"
LZ4_CAT_SHA=$(MALLOC_OPTIONS=JJ lz4cat /tmp/arch_test/t.lz4 | /bin/sha256 -q)
[ "$LZ4_CAT_SHA" = "$ORIG_SHA" ] || fail "lz4cat SHA256 mismatch: $LZ4_CAT_SHA != $ORIG_SHA"
MALLOC_OPTIONS=JJ unlz4 -q -f /tmp/arch_test/t.lz4 /tmp/arch_test/t_unlz4.bin
[ "$(/bin/sha256 -q /tmp/arch_test/t_unlz4.bin)" = "$ORIG_SHA" ] || fail "unlz4 SHA256 mismatch"

XXH64_LINE=$(MALLOC_OPTIONS=JJ xxh64sum /tmp/arch_test/payload.bin)
printf '%s\n' "$XXH64_LINE" > /tmp/arch_test/payload.xxh64
MALLOC_OPTIONS=JJ xxhsum -q -c /tmp/arch_test/payload.xxh64 || fail "xxhsum -c failed"
set -- $(MALLOC_OPTIONS=JJ xxh128sum /tmp/arch_test/payload.bin)
[ "${#1}" = "32" ] || fail "xxh128sum digest length mismatch: $1 (${#1})"
pass "12_wave2_foundation_applets" "MALLOC_OPTIONS=JJ iconv + pcre2grep + pcregrep + lz4/unlz4 + xxhsum/xxh64sum/xxh128sum OK"

echo "[PORTS-ALL-OK] OpenBSD $OS_REL WASM64 ports suite passed 100%"
'''

NODE_SUITE_MJS = r'''
import fs from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import dgram from 'node:dgram';
import dns from 'node:dns/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const [runtimePath, cfgPath] = process.argv.slice(2);
const cfg = JSON.parse(fs.readFileSync(cfgPath, 'utf8'));
const enc = new TextEncoder();
const dec = new TextDecoder('utf-8', { fatal: false });

// Start ephemeral local HTTP test server to verify SVNP/1 loopback HTTP alongside live external HTTPS
const localServer = http.createServer((req, res) => {
  if (req.url === '/obsd-ports-ping') {
    const body = `SVNP_HTTP_OK:${cfg.openbsdVersion}`;
    res.writeHead(200, { 'Content-Type': 'text/plain', 'Content-Length': Buffer.byteLength(body) });
    res.end(body);
    return;
  }
  res.writeHead(404);
  res.end('not found');
});
await new Promise((resolve) => localServer.listen(0, '127.0.0.1', resolve));
const localPort = localServer.address().port;

const createRuntime = (await import(pathToFileURL(path.resolve(runtimePath)).href)).default;
const Module = await createRuntime({
  locateFile: (f) => path.join(path.dirname(path.resolve(runtimePath)), f),
  noInitialRun: true,
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

function buildFakerootRecord(guestPath, mask, uid, gid, mode, rdev) {
  const pb = enc.encode(guestPath);
  const rec = new Uint8Array(24 + pb.byteLength);
  const dv = new DataView(rec.buffer);
  dv.setUint32(0, pb.byteLength, true);
  dv.setUint32(4, mask >>> 0, true);
  dv.setUint32(8, uid >>> 0, true);
  dv.setUint32(12, gid >>> 0, true);
  dv.setUint32(16, mode >>> 0, true);
  dv.setUint32(20, rdev >>> 0, true);
  rec.set(pb, 24);
  return rec;
}

function openbsdMakedev(maj, min) {
  return (((maj & 0xff) << 8) | (min & 0xff) | ((min & 0xffff00) << 8)) >>> 0;
}

const FR_UID = 1, FR_GID = 2, FR_MODE = 4, FR_RDEV = 8;
const S_IFCHR = 0o020000;
const frRecords = [];

for (const d of [
  '/bsd/sysroot/bin', '/bsd/sysroot/sbin', '/bsd/sysroot/usr/bin', '/bsd/sysroot/usr/sbin',
  '/bsd/sysroot/usr/libexec', '/bsd/sysroot/usr/local/bin', '/bsd/sysroot/usr/local/sbin',
  '/bsd/sysroot/usr/local/share', '/bsd/sysroot/usr/share/terminfo',
  '/bsd/sysroot/usr/share/locale/UTF-8', '/bsd/sysroot/dev', '/bsd/sysroot/etc/ssl',
  '/bsd/sysroot/root', '/bsd/sysroot/var/empty', '/bsd/sysroot/tmp', '/bsd/sysroot/proc',
  '/bsd/persist/etc/ssl', '/bsd/tmp',
]) {
  mkdirp(d, d.endsWith('/tmp') ? 0o1777 : 0o755);
}

const stubBytes = enc.encode(`Sonvori BSD applet stub.\ntable ${cfg.tableDigest}\n`);
FS.writeFile('/bsd/sysroot/.obsd-emulate-applet', stubBytes);
FS.chmod('/bsd/sysroot/.obsd-emulate-applet', 0o555);
frRecords.push(buildFakerootRecord('/.obsd-emulate-applet', FR_UID | FR_GID | FR_MODE, 0, 0, 0o100555, 0));

for (const gp of cfg.appletPaths) {
  const full = `/bsd/sysroot${gp}`;
  mkdirp(path.posix.dirname(full), 0o755);
  FS.writeFile(full, stubBytes);
  FS.chmod(full, 0o555);
  frRecords.push(buildFakerootRecord(gp, FR_UID | FR_GID | FR_MODE, 0, 0, 0o100555, 0));
}

const devNodes = [
  ['/dev/null', 0o666, openbsdMakedev(2, 2)],
  ['/dev/zero', 0o666, openbsdMakedev(2, 12)],
  ['/dev/urandom', 0o644, openbsdMakedev(45, 0)],
  ['/dev/random', 0o644, openbsdMakedev(45, 0)],
  ['/dev/tty', 0o666, openbsdMakedev(1, 0)],
  ['/dev/ptm', 0o666, openbsdMakedev(81, 0)],
];
for (const [dp, mode, rdev] of devNodes) {
  FS.writeFile(`/bsd/sysroot${dp}`, new Uint8Array(0));
  frRecords.push(buildFakerootRecord(dp, FR_UID | FR_GID | FR_MODE | FR_RDEV, 0, 0, S_IFCHR | mode, rdev));
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
if (fs.existsSync(cfg.portsOwnersDb)) {
  frRecords.push(new Uint8Array(fs.readFileSync(cfg.portsOwnersDb)));
}

for (const [gp, hp, mode] of cfg.stagedFiles) {
  const data = fs.readFileSync(hp);
  if (gp.startsWith('/etc/')) {
    const p1 = `/bsd/sysroot${gp}`;
    const p2 = `/bsd/persist${gp}`;
    mkdirp(path.posix.dirname(p1), 0o755);
    mkdirp(path.posix.dirname(p2), 0o755);
    FS.writeFile(p1, data);
    FS.chmod(p1, mode);
    FS.writeFile(p2, data);
    FS.chmod(p2, mode);
  } else {
    const dst = `/bsd/sysroot${gp}`;
    mkdirp(path.posix.dirname(dst), 0o755);
    FS.writeFile(dst, data);
    FS.chmod(dst, mode);
  }
  frRecords.push(buildFakerootRecord(gp, FR_UID | FR_GID | FR_MODE, 0, 0, 0o100000 | mode, 0));
}

const scriptContent = cfg.scriptTemplate.replaceAll('__LOCAL_HTTP_PORT__', String(localPort));
FS.writeFile('/bsd/tmp/run_ports_guest_suite.sh', enc.encode(scriptContent));
FS.chmod('/bsd/tmp/run_ports_guest_suite.sh', 0o755);

let frTotal = 0;
for (const r of frRecords) frTotal += r.byteLength;
const frBuf = new Uint8Array(frTotal);
let frOff = 0;
for (const r of frRecords) {
  frBuf.set(r, frOff);
  frOff += r.byteLength;
}
FS.writeFile('/bsd/persist/fakeroot.db', frBuf);
FS.writeFile(
  '/bsd/vfs.profile',
  enc.encode('version 1\nbind /etc /bsd/persist/etc\nbind /tmp /bsd/tmp\nremap / /bsd/sysroot\nsynth proc /proc\nidentity root\n'),
);

// Standalone SVNP/1 shared-memory socket & UDP/DNS bridge
const SVNP_MAGIC = 0x53564e50;
const SVNP_SHM_MAGIC = 0x53564e31;
const SOCKS_BASE_OFF = 64;
const SOCK_STRIDE = 16;
const SLOTS_BASE_OFF = 16448;
const SLOT_STRIDE = 65696;
const MAX_SLOTS = 32;
const SLOT_BUF_OFF = 32;

const lo = Module._suite_svnp_shm_lo() >>> 0;
const hi = Module._suite_svnp_shm_hi() >>> 0;
const shmOff = hi * 0x100000000 + lo;

const getViews = () => {
  const b = Module.wasmMemory.buffer;
  return { u8: new Uint8Array(b), i32: new Int32Array(b), u32: new Uint32Array(b) };
};

if (shmOff > 0) {
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
  if (family === 4 && ip && ip.includes('.')) {
    const ps = ip.split('.').map(Number);
    out[8] = ps[0]; out[9] = ps[1]; out[10] = ps[2]; out[11] = ps[3];
  }
  return out;
}

function decodeAddr(buf, off = 0) {
  const family = buf.readUInt8(off);
  const port = buf.readUInt16LE(off + 2);
  if (family === 4) {
    return { family, port, ip: `${buf[off+8]}.${buf[off+9]}.${buf[off+10]}.${buf[off+11]}` };
  }
  const groups = [];
  for (let i = 0; i < 16; i += 2) {
    groups.push(buf.readUInt16BE(off + 8 + i).toString(16));
  }
  return { family, port, ip: groups.join(':') };
}

function updateSockState(sockId, s) {
  const { i32, u32 } = getViews();
  let mask = 0;
  let avail = 0;
  for (const c of s.rxQueue) avail += c.data.length;
  if (avail > 0 || s.eof) mask |= 1; // POLLIN
  if (s.connected && !s.connecting) mask |= 4; // POLLOUT
  if (s.err) mask |= 8; // POLLERR
  if (s.eof) mask |= 16; // POLLHUP
  const off = shmOff + SOCKS_BASE_OFF + sockId * SOCK_STRIDE;
  Atomics.store(i32, off >> 2, mask);
  Atomics.store(u32, (off + 4) >> 2, avail >>> 0);
  Atomics.store(i32, (off + 8) >> 2, s.err | 0);
  Atomics.add(i32, (off + 12) >> 2, 1);
  Atomics.notify(i32, (off + 12) >> 2, 64);
  Atomics.add(i32, (shmOff + 20) >> 2, 1);
  Atomics.notify(i32, (shmOff + 20) >> 2, 64);
  while (s.waiters.length > 0 && (avail > 0 || s.eof || s.err)) {
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
    return;
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
    const s = { id, domain, type, tcp: null, udp: null, connected: type === 2, connecting: false, eof: false, err: 0, rxQueue: [], waiters: [], peer: null };
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

  if (op === 0x04) { // CONNECT
    const dst = decodeAddr(body, 0);
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
    let settled = false;
    sock.once('connect', () => {
      if (settled) return;
      settled = true;
      s.connecting = false; s.connected = true; updateSockState(sockId, s);
      finishSlot(slotIdx, reqId, sockId, 0, encodeAddr(sock.localAddress || '127.0.0.1', sock.localPort || 0, dst.family));
    });
    sock.on('error', (err) => {
      const code = err && (err.code === 'ENETUNREACH' || err.code === 'EHOSTUNREACH') ? 51 : 61;
      s.connecting = false; s.err = code; updateSockState(sockId, s);
      if (!settled) {
        settled = true;
        finishSlot(slotIdx, reqId, sockId, code);
      }
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
    if (!s.tcp || !s.connected) return finishSlot(slotIdx, reqId, sockId, 57);
    s.tcp.write(payload, (err) => {
      if (err) return finishSlot(slotIdx, reqId, sockId, 32);
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

  if (op === 0x09) return finishSlot(slotIdx, reqId, sockId, 0);
  if (op === 0x0a) {
    const level = body.readUInt16LE(0);
    const opt = body.readUInt16LE(2);
    const b = Buffer.alloc(4, 0);
    if (level === 1 && opt === 9) { b.writeInt32LE(s.err, 0); s.err = 0; }
    else if (level === 1 && opt === 12) { b.writeInt32LE(s.type, 0); }
    return finishSlot(slotIdx, reqId, sockId, 0, b);
  }
  if (op === 0x0b) return finishSlot(slotIdx, reqId, sockId, 0, encodeAddr('127.0.0.1', 0, 4));
  if (op === 0x0c) return finishSlot(slotIdx, reqId, sockId, s.peer ? 0 : 57, s.peer ? encodeAddr(s.peer.ip, s.peer.port, 4) : Buffer.alloc(0));
  if (op === 0x0d) { if (s.tcp) s.tcp.end(); return finishSlot(slotIdx, reqId, sockId, 0); }
  if (op === 0x0e) {
    if (s.tcp) s.tcp.destroy();
    if (s.udp) try { s.udp.close(); } catch {}
    socks.delete(sockId);
    return finishSlot(slotIdx, reqId, sockId, 0);
  }
  return finishSlot(slotIdx, reqId, sockId, 0);
}

if (shmOff > 0) {
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
}

const startRc = Module._suite_start();
if (startRc !== 0) {
  console.error(`[FAIL] suite_start failed: ${startRc}`);
  localServer.close();
  process.exit(1);
}

const outPtr = Module._suite_io_buf_addr() >>> 0;
let fullLog = '';
function drain() {
  for (;;) {
    const n = Module._suite_read_output();
    if (n <= 0) break;
    const chunk = new Uint8Array(n);
    chunk.set(Module.HEAPU8.subarray(outPtr, outPtr + n));
    const text = dec.decode(chunk);
    fullLog += text;
    process.stdout.write(text);
  }
}

const deadline = Date.now() + 180000;
while (!Module._suite_is_done()) {
  drain();
  if (Date.now() > deadline) {
    console.error(`[FAIL] Timed out waiting for OpenBSD ${cfg.openbsdVersion} WASM64 ports test suite`);
    localServer.close();
    process.exit(124);
  }
  await new Promise((r) => setTimeout(r, 12));
}
drain();
localServer.close();

const status = Module._suite_wait_status();
const embedErr = Module._suite_embed_error() >>> 0;
if (embedErr !== 0) {
  console.error(`[FAIL] embed error: ${embedErr}`);
  process.exit(1);
}
const exitCode = (status & 0x7f) === 0 ? ((status >> 8) & 0xff) : 128 + (status & 0x7f);
if (exitCode !== 0) {
  console.error(`[FAIL] Guest suite exited with code ${exitCode} (raw status=${status})`);
  process.exit(exitCode);
}
const passLines = (fullLog.match(/^\[PORTS-PASS\] /gm) || []).length;
if (passLines < 12) {
  console.error(`[FAIL] Expected >= 12 [PORTS-PASS] assertions, got ${passLines}`);
  process.exit(1);
}
process.exit(0);
'''


def resolve_obsd_root(cli_val: str) -> pathlib.Path:
    if cli_val:
        return pathlib.Path(cli_val).resolve()
    env_val = os.environ.get("LIBOBSDCOMPAT_ROOT", "").strip()
    if env_val:
        return pathlib.Path(env_val).resolve()
    out = subprocess.check_output(
        ["sh", str(REPO_ROOT / "tools/config/locate-libobsdcompat.sh")],
        text=True,
    ).strip()
    return pathlib.Path(out).resolve()


def find_node(obsd_root: pathlib.Path) -> str:
    env_node = os.environ.get("EMSDK_NODE", "").strip()
    if env_node and pathlib.Path(env_node).is_file():
        return env_node
    emsdk_nodes = sorted((obsd_root / "deps/emsdk/node").rglob("bin/node"))
    if emsdk_nodes:
        return str(emsdk_nodes[-1])
    w = shutil.which("node")
    if w:
        return w
    raise SystemExit("run_wasm_ports_tests: node executable not found")


def ensure_ports_built_and_packaged(ver: str, obsd_root: pathlib.Path, jobs: int) -> pathlib.Path:
    lane_dir = REPO_ROOT / "build/openbsd" / ver / "emulate/emscripten"
    build_py = REPO_ROOT / "tools/build_ports.py"

    # Always run build + package (idempotent & fast when up-to-date)
    for subcmd in ("build", "package"):
        rc = subprocess.run(
            [
                sys.executable,
                "-I",
                str(build_py),
                subcmd,
                "--openbsd-version",
                ver,
                "--backend",
                "emulate",
                "--pal",
                "emscripten",
                "--libobsdcompat-root",
                str(obsd_root),
                "--jobs",
                str(jobs),
            ],
            cwd=str(REPO_ROOT),
        ).returncode
        if rc != 0:
            raise SystemExit(f"[FAIL/{ver}] build_ports.py {subcmd} failed with exit code {rc}")

    return lane_dir


def verify_lane_artifacts(ver: str, lane_dir: pathlib.Path) -> None:
    stage_lib = lane_dir / "stage/usr/local/lib"
    sysroot_inc = lane_dir / "sysroot/usr/local/include"
    tsv_path = lane_dir / "ports-applets.tsv"
    svfs_gz = lane_dir / "ports.svfs.gz"
    owners_db = lane_dir / "ports-owners.db"
    pkgs_dir = lane_dir / "packages"

    for lib_name in REQUIRED_STATIC_LIBS:
        lp = stage_lib / lib_name
        if not lp.is_file() or lp.stat().st_size < 64:
            raise SystemExit(f"[FAIL/{ver}] missing or empty static library: {lp}")

    for hdr_rel in REQUIRED_HEADERS:
        hp = sysroot_inc / hdr_rel
        if not hp.is_file():
            raise SystemExit(f"[FAIL/{ver}] missing staged header: {hp}")

    stage_pc = lane_dir / "stage/usr/local/lib/pkgconfig"
    for pc_name in REQUIRED_PKGCONFIGS:
        pcp = stage_pc / pc_name
        if not pcp.is_file() and not pcp.is_symlink():
            raise SystemExit(f"[FAIL/{ver}] missing staged pkg-config file: {pcp}")

    if not tsv_path.is_file():
        raise SystemExit(f"[FAIL/{ver}] missing {tsv_path}")

    seen_paths = set()
    for raw in tsv_path.read_text(encoding="utf-8").splitlines():
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        sym, gp, ent, obj_rel = s.split("\t")
        seen_paths.add(gp)
        obj_p = lane_dir / obj_rel
        if not obj_p.is_file() or obj_p.read_bytes()[:8] != b"\x00asm\x01\x00\x00\x00":
            raise SystemExit(f"[FAIL/{ver}] invalid localized WASM64 applet object for {sym}: {obj_p}")

    missing_paths = [p for p in REQUIRED_APPLET_PATHS if p not in seen_paths]
    if missing_paths:
        raise SystemExit(f"[FAIL/{ver}] missing applet paths in ports-applets.tsv: {missing_paths}")

    if not svfs_gz.is_file():
        raise SystemExit(f"[FAIL/{ver}] missing {svfs_gz}")
    with gzip.open(svfs_gz, "rb") as gfp:
        hdr = gfp.read(12)
    magic, svfs_ver, _flags, entry_cnt = struct.unpack("<IHHI", hdr)
    if magic != 0x53564653 or svfs_ver != 1 or entry_cnt < 20:
        raise SystemExit(f"[FAIL/{ver}] invalid ports.svfs.gz header: magic=0x{magic:x} ver={svfs_ver} entries={entry_cnt}")

    if not owners_db.is_file() or owners_db.stat().st_size < 64:
        raise SystemExit(f"[FAIL/{ver}] missing or empty {owners_db}")

    tgz_files = sorted(pkgs_dir.glob("*.tgz"))
    if len(tgz_files) < 10:
        raise SystemExit(f"[FAIL/{ver}] expected >= 10 .tgz packages in {pkgs_dir}, found {len(tgz_files)}")

    print(
        f"[PORTS-PASS] [{ver}] 00_packaging_contract: {len(REQUIRED_STATIC_LIBS)} static libs, "
        f"{len(seen_paths)} applet paths, {entry_cnt} SVFS entries, {len(tgz_files)} .tgz packages"
    )


def build_suite_runtime(ver: str, obsd_root: pathlib.Path, lane_dir: pathlib.Path) -> Tuple[pathlib.Path, pathlib.Path]:
    suite_dir = lane_dir / "ports-check-suite"
    suite_dir.mkdir(parents=True, exist_ok=True)

    probe_c = REPO_ROOT / "tests/ports_pty_probe.c"
    probe_raw = suite_dir / "ports_pty_probe.raw"
    probe_loc = suite_dir / "ports_pty_probe.o"
    obsd_cc = REPO_ROOT / "sdk/bin/obsd-cc"
    wasm_obj_tool = obsd_root / "tools/build/personalities/openbsd/backends/emulate/wasm_object_tool.py"

    cc_env = dict(os.environ)
    cc_env["OPENBSD_VERSION"] = ver
    cc_env["LIBOBSDCOMPAT_ROOT"] = str(obsd_root)
    cc_env["OBSD_STAGE_DIR"] = str(lane_dir / "stage")

    subprocess.run(
        [
            str(obsd_cc),
            "-Wall",
            "-Wextra",
            str(probe_c),
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
            "-lutil",
            "-lm",
            "-o",
            str(probe_raw),
        ],
        env=cc_env,
        check=True,
    )

    llvm_nm = obsd_root / "deps/emsdk/upstream/bin/llvm-nm"
    nm_out = subprocess.check_output([str(llvm_nm), "--defined-only", "-g", str(probe_raw)], text=True)
    probe_entry = "__main_argc_argv" if " __main_argc_argv" in nm_out else "main"

    subprocess.run(
        [
            sys.executable,
            "-I",
            str(wasm_obj_tool),
            "localize-applet",
            "--applet-sym",
            "ports_pty_probe",
            "--entry-symbol",
            probe_entry,
            "-i",
            str(probe_raw),
            "-o",
            str(probe_loc),
        ],
        check=True,
    )
    probe_raw.unlink(missing_ok=True)

    # Create overlay lane TSV combining all ports applets + ports_pty_probe
    overlay_dir = suite_dir / "overlay-lane"
    overlay_dir.mkdir(parents=True, exist_ok=True)
    base_rows = []
    for raw in (lane_dir / "ports-applets.tsv").read_text(encoding="utf-8").splitlines():
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        sym, gp, ent, obj_rel = s.split("\t")
        base_rows.append(f"{sym}\t{gp}\t{ent}\t{(lane_dir / obj_rel).resolve()}")
    base_rows.append(
        f"ports_pty_probe\t/usr/libexec/ports_pty_probe\tobsd_applet_ports_pty_probe_main\t{probe_loc.resolve()}"
    )
    (overlay_dir / "ports-applets.tsv").write_text("\n".join(base_rows) + "\n", encoding="utf-8")

    # Compute cache stamp
    wasm_build_dir = obsd_root / f"build/wasm-{ver}"
    host_ar = wasm_build_dir / f"libobsd-wasm-host-{ver}.a"
    base_ar = wasm_build_dir / f"libobsdc-wasm-{ver}.a"

    sig_h = hashlib.sha256()
    sig_h.update(b"link-cfg-v2-pool32-4g")
    sig_h.update(f"{base_ar.stat().st_mtime_ns}:{host_ar.stat().st_mtime_ns}".encode())
    sig_h.update(HOST_SUITE_C.encode())
    sig_h.update(probe_loc.read_bytes())
    for raw in base_rows:
        p = pathlib.Path(raw.split("\t")[3])
        st = p.stat()
        sig_h.update(f"{p.name}:{st.st_size}:{st.st_mtime_ns}".encode())
    sig = sig_h.hexdigest()

    runtime_mjs = suite_dir / "ports-suite-runtime.mjs"
    table_tsv = suite_dir / "applet-table.tsv"
    stamp_file = suite_dir / "suite.stamp"
    if runtime_mjs.is_file() and table_tsv.is_file() and stamp_file.is_file() and stamp_file.read_text().strip() == sig:
        return runtime_mjs, table_tsv

    merge_mod_dir = REPO_ROOT / "targets/emulate/emscripten"
    if str(merge_mod_dir) not in sys.path:
        sys.path.insert(0, str(merge_mod_dir))
    import merge_wasm_guest as mwg  # type: ignore

    guest_o, table_c, table_tsv = mwg.merge_guest_objects(
        obsd_root=obsd_root,
        openbsd_version=ver,
        ports_lane_dir=overlay_dir,
        out_dir=suite_dir,
        base_mode="minimal",
    )

    emcc = obsd_root / "deps/emsdk/upstream/emscripten/emcc"
    emulate_prod = obsd_root / "src/personalities/openbsd/runtime/backends/emulate/product"
    emulate_pal = obsd_root / "src/personalities/openbsd/runtime/backends/emulate/pals/emscripten"

    table_o = suite_dir / "wasm_applet_table.o"
    subprocess.run(
        [str(emcc), "-c", "-m64", "-pthread", "-O2", "-sSUPPORT_LONGJMP=0", "-I", str(emulate_prod), str(table_c), "-o", str(table_o)],
        check=True,
    )

    host_c = suite_dir / "ports_suite_host.c"
    host_o = suite_dir / "ports_suite_host.o"
    host_c.write_text(HOST_SUITE_C, encoding="utf-8")
    subprocess.run(
        [str(emcc), "-c", "-m64", "-pthread", "-O2", "-sSUPPORT_LONGJMP=0", "-I", str(emulate_pal), str(host_c), "-o", str(host_o)],
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
        '["_suite_svnp_shm_lo","_suite_svnp_shm_hi","_suite_io_buf_addr",'
        '"_suite_start","_suite_read_output","_suite_is_done",'
        '"_suite_wait_status","_suite_embed_error"]'
    )
    exported_rt = '["FS","HEAPU8","wasmMemory"]'
    subprocess.run(
        [
            str(emcc),
            "-m64",
            "-pthread",
            "-O2",
            "-Wno-pthreads-mem-growth",
            "-Wl,--wrap=posix_memalign",
            "-sMODULARIZE=1",
            "-sEXPORT_ES6=1",
            "-sENVIRONMENT=node",
            "-sALLOW_MEMORY_GROWTH=1",
            "-sINITIAL_MEMORY=268435456",
            "-sMAXIMUM_MEMORY=4294967296",
            "-sSTACK_SIZE=1048576",
            "-sPTHREAD_POOL_SIZE=32",
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
        check=True,
    )
    stamp_file.write_text(sig + "\n", encoding="utf-8")
    return runtime_mjs, table_tsv


def collect_host_nameservers() -> List[str]:
    ns: List[str] = []
    rc = pathlib.Path("/etc/resolv.conf")
    if rc.is_file():
        for ln in rc.read_text(encoding="utf-8", errors="replace").splitlines():
            s = ln.strip()
            if s.startswith("nameserver "):
                ip = s.split()[1].strip()
                if "." in ip and ip not in ns:
                    ns.append(ip)
    for fallback in ("1.1.1.1", "8.8.8.8"):
        if fallback not in ns:
            ns.append(fallback)
    return ns[:3]


def run_single_release_check(ver: str, obsd_root: pathlib.Path, jobs: int) -> None:
    t0 = time.monotonic()
    print(f"\n=== [obsd-ports/check] Verifying OpenBSD {ver} WASM64 Ports Suite ===")

    lane_dir = ensure_ports_built_and_packaged(ver, obsd_root, jobs)
    verify_lane_artifacts(ver, lane_dir)
    runtime_mjs, table_tsv = build_suite_runtime(ver, obsd_root, lane_dir)

    raw_tsv = table_tsv.read_bytes()
    table_digest = hashlib.sha256(raw_tsv).hexdigest()
    applet_paths = sorted({ln.split("\t")[0] for ln in raw_tsv.decode("utf-8").splitlines() if ln.strip()})

    src_root = obsd_root / "vendor/openbsd/versions" / ver / "src"
    suite_dir = lane_dir / "ports-check-suite"
    etc_stage = suite_dir / "etc-stage"
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
    ns_lines = [f"nameserver {ip}" for ip in collect_host_nameservers()]
    ns_lines.append("lookup file bind")
    resolv_out.write_text("\n".join(ns_lines) + "\n", encoding="utf-8")

    staged_files: List[Tuple[str, str, int]] = [
        ("/etc/master.passwd", str(mpw), 0o600),
        ("/etc/passwd", str(pw_out), 0o644),
        ("/etc/group", str(src_root / "etc/group"), 0o644),
        ("/etc/services", str(src_root / "etc/services"), 0o644),
        ("/etc/protocols", str(src_root / "etc/protocols"), 0o644),
        ("/etc/hosts", str(hosts_out), 0o644),
        ("/etc/resolv.conf", str(resolv_out), 0o644),
    ]

    # OpenBSD /etc/ssl/cert.pem CA bundle
    cert_found = False
    for cert_cand in (
        src_root / "lib/libcrypto/cert.pem",
        pathlib.Path("/etc/ssl/certs/ca-certificates.crt"),
        pathlib.Path("/etc/ssl/cert.pem"),
    ):
        if cert_cand.is_file():
            staged_files.append(("/etc/ssl/cert.pem", str(cert_cand), 0o444))
            cert_found = True
            break
    if not cert_found:
        raise SystemExit(f"[FAIL/{ver}] no /etc/ssl/cert.pem source found")

    # Stage terminfo entries for OpenBSD libcurses + nano
    for rel_ti in ("d/dumb", "x/xterm", "x/xterm-256color", "v/vt100"):
        for base_ti in ("/usr/share/terminfo", "/lib/terminfo"):
            cand = pathlib.Path(base_ti) / rel_ti
            if cand.is_file():
                staged_files.append((f"/usr/share/terminfo/{rel_ti}", str(cand), 0o444))
                break

    # Stage OpenBSD UTF-8 LC_CTYPE if available from prebuilt locale data
    for lc_cand in (
        obsd_root.parent.parent / "runtime/overlay/usr/share/locale/UTF-8/LC_CTYPE",
        obsd_root / "vendor/openbsd/versions" / ver / "share/locale/UTF-8/LC_CTYPE",
    ):
        if lc_cand.is_file():
            staged_files.append(("/usr/share/locale/UTF-8/LC_CTYPE", str(lc_cand), 0o444))
            break

    runner_mjs = suite_dir / "run_ports_suite.mjs"
    runner_mjs.write_text(NODE_SUITE_MJS, encoding="utf-8")
    cfg_json = suite_dir / "suite_cfg.json"
    cfg_json.write_text(
        json.dumps(
            {
                "openbsdVersion": ver,
                "tableDigest": table_digest,
                "appletPaths": applet_paths,
                "sysrootUsrLocal": str(lane_dir / "sysroot/usr/local"),
                "portsOwnersDb": str(lane_dir / "ports-owners.db"),
                "stagedFiles": staged_files,
                "scriptTemplate": GUEST_SUITE_SH_TEMPLATE.replace("__OPENBSD_VERSION__", ver),
            }
        ),
        encoding="utf-8",
    )

    node_bin = find_node(obsd_root)
    rc = subprocess.run([node_bin, str(runner_mjs), str(runtime_mjs), str(cfg_json)], cwd=str(suite_dir)).returncode
    if rc != 0:
        raise SystemExit(f"[FAIL/{ver}] WASM64 ports guest verification failed (exit {rc})")

    elapsed = time.monotonic() - t0
    print(f"=== [obsd-ports/check] OpenBSD {ver} PASSED 100% ({elapsed:.1f}s) ===")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--openbsd-version",
        default=os.environ.get("OPENBSD_VERSION", "all"),
        help="Target OpenBSD version (7.8, 7.9, 8.0, or all)",
    )
    ap.add_argument("--libobsdcompat-root", default="")
    ap.add_argument("--jobs", type=int, default=os.cpu_count() or 8)
    ap.add_argument("--port", default="")
    args = ap.parse_args()

    obsd_root = resolve_obsd_root(args.libobsdcompat_root)
    target = args.openbsd_version.strip()
    versions = ["7.8", "7.9", "8.0"] if target in ("", "all") else [v.strip() for v in target.split(",") if v.strip()]

    for ver in versions:
        run_single_release_check(ver, obsd_root, args.jobs)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
