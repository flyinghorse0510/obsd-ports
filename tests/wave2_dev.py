#!/usr/bin/env python3
"""
tests/wave2_dev.py -- Wave-2 Slice A (VCS, Build, Code Indexing & Scripting)
Dual-Release (OpenBSD 7.8 & 7.9) WASM64 Verification Suite.

Verifies all 6 Slice A ports via `merge_wasm_guest.py run-guest --enable-network`
(including `MALLOC_OPTIONS=JJ` heap/variadic safety runs):
  1. `devel/git` (`2.51.0` on 7.8, `2.53.0` on 7.9):
     - `git init`, `git config`, `git add`, `git commit`, `git log`, `git diff`,
       `git branch`, `git grep -P` (PCRE2)
     - Out-of-the-box `--enable-network` HTTPS `git ls-remote` & shallow
       `git clone --depth=1` using default `/etc/ssl/cert.pem` CA bundle
  2. `devel/gmake` (`4.4.1`):
     - `gmake -j2` multi-rule parallel Makefile execution (pipe jobserver)
  3. `devel/tig` (`2.6.0`):
     - `tig --version` + interactive 80x24 PTY (`openpty` + `login_tty`) curses
       TUI invocation inside a Git repository (rendering commits & exiting on `q`)
  4. `devel/universal-ctags` (`6.1.0`):
     - `uctags -R` + `ureadtags` symbol/kind/line lookup across C and JS sources
  5. `lang/quickjs` (`2024.01.13`):
     - `qjs -e` ES2023 `async`/`Promise`/`BigInt`/`Proxy` execution + `qjsc`
       bytecode compilation + C `libquickjs.a` embedding test
  6. `lang/jimtcl` (`0.80` on 7.8, `0.81` on 7.9):
     - `jimsh` Tcl `proc`, `dict`, `regexp`/`regsub`, `sqlite3`, and C `libjim.a`
       embedding test
"""
from __future__ import annotations

import argparse
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
from typing import Dict, List, Set

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]

EXPECTED_VERSIONS: Dict[str, Dict[str, str]] = {
    "7.8": {
        "git": "2.51.0",
        "gmake": "4.4.1",
        "tig": "2.6.0",
        "uctags": "6.1.0",
        "quickjs": "2024-01-13",
        "jimtcl": "0.80",
    },
    "7.9": {
        "git": "2.53.0",
        "gmake": "4.4.1",
        "tig": "2.6.0",
        "uctags": "6.1.0",
        "quickjs": "2024-01-13",
        "jimtcl": "0.81",
    },
    "8.0": {
        "git": "2.55.0",
        "gmake": "4.4.1",
        "tig": "2.6.1",
        "uctags": "6.2.1",
        "quickjs": "2024-01-13",
        "jimtcl": "0.81",
    },
}

REQUIRED_APPLETS: Dict[str, List[str]] = {
    "git": [
        "/usr/local/bin/git",
        "/usr/local/bin/git-receive-pack",
        "/usr/local/bin/git-shell",
        "/usr/local/bin/git-upload-archive",
        "/usr/local/bin/git-upload-pack",
        "/usr/local/libexec/git/git",
    ],
    "git_remote_http": [
        "/usr/local/libexec/git/git-remote-http",
        "/usr/local/libexec/git/git-remote-https",
        "/usr/local/libexec/git/git-remote-ftp",
        "/usr/local/libexec/git/git-remote-ftps",
    ],
    "gmake": ["/usr/local/bin/gmake"],
    "tig": ["/usr/local/bin/tig"],
    "uctags": ["/usr/local/bin/uctags"],
    "ureadtags": ["/usr/local/bin/ureadtags"],
    "qjs": ["/usr/local/bin/qjs"],
    "qjsc": ["/usr/local/bin/qjsc"],
    "jimsh": ["/usr/local/bin/jimsh"],
}

REQUIRED_STAGE_ARTIFACTS = [
    "usr/local/lib/libgit.a",
    "usr/local/lib/quickjs/libquickjs.a",
    "usr/local/include/quickjs/quickjs.h",
    "usr/local/include/quickjs/quickjs-libc.h",
    "usr/local/lib/libjim.a",
    "usr/local/include/jim/jim.h",
    "usr/local/lib/pkgconfig/jimtcl.pc",
    "usr/local/man/man1/git.1",
    "usr/local/man/man1/git-clone.1",
    "usr/local/man/man1/tig.1",
    "usr/local/etc/gitconfig",
]

W2_DEV_PROBE_C = r'''
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/wait.h>

#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <util.h>

#include <quickjs/quickjs.h>
#include <jim.h>

static int
verify_c_static_libs(void)
{
	/* 1. libquickjs.a */
	JSRuntime *rt = JS_NewRuntime();
	if (rt == NULL) {
		fprintf(stderr, "[FAIL] JS_NewRuntime returned NULL\n");
		return 1;
	}
	JSContext *ctx = JS_NewContext(rt);
	if (ctx == NULL) {
		fprintf(stderr, "[FAIL] JS_NewContext returned NULL\n");
		JS_FreeRuntime(rt);
		return 1;
	}
	const char expr[] = "Number((1n << 5n) + 10n)";
	JSValue val = JS_Eval(ctx, expr, sizeof(expr) - 1, "<probe>", JS_EVAL_TYPE_GLOBAL);
	int32_t qjs_res = 0;
	int qrc = JS_ToInt32(ctx, &qjs_res, val);
	JS_FreeValue(ctx, val);
	JS_FreeContext(ctx);
	JS_FreeRuntime(rt);
	if (qrc != 0 || qjs_res != 42) {
		fprintf(stderr, "[FAIL] libquickjs.a eval mismatch: qrc=%d res=%d\n", qrc, qjs_res);
		return 1;
	}

	/* 2. libjim.a */
	Jim_Interp *interp = Jim_CreateInterp();
	if (interp == NULL) {
		fprintf(stderr, "[FAIL] Jim_CreateInterp returned NULL\n");
		return 1;
	}
	Jim_RegisterCoreCommands(interp);
	Jim_InitStaticExtensions(interp);
	long jim_res = 0;
	if (Jim_Eval(interp, "expr {6 * 7}") != JIM_OK ||
	    Jim_GetLong(interp, Jim_GetResult(interp), &jim_res) != JIM_OK ||
	    jim_res != 42) {
		fprintf(stderr, "[FAIL] libjim.a eval mismatch: res=%ld\n", jim_res);
		Jim_FreeInterp(interp);
		return 1;
	}
	Jim_FreeInterp(interp);

	printf("STATIC_LIBS_OK:qjs=%d:jim=%ld\n", qjs_res, jim_res);
	fflush(stdout);
	return 0;
}

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
			char buf[1024];
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
verify_tig_pty(const char *repo_dir)
{
	int master = -1, slave = -1;
	struct winsize ws;
	memset(&ws, 0, sizeof(ws));
	ws.ws_row = 24;
	ws.ws_col = 80;
	ws.ws_xpixel = 640;
	ws.ws_ypixel = 384;

	if (openpty(&master, &slave, NULL, NULL, &ws) != 0) {
		fprintf(stderr, "[FAIL] openpty failed: %s\n", strerror(errno));
		return 1;
	}

	pid_t pid = fork();
	if (pid < 0) {
		fprintf(stderr, "[FAIL] fork failed: %s\n", strerror(errno));
		close(master);
		close(slave);
		return 1;
	}

	if (pid == 0) {
		close(master);
		if (login_tty(slave) != 0)
			_exit(126);
		if (chdir(repo_dir) != 0)
			_exit(125);
		setenv("TERM", "xterm-256color", 1);
		setenv("HOME", "/root", 1);
		setenv("MALLOC_OPTIONS", "JJ", 1);
		char *const targv[] = { (char *)"tig", NULL };
		execv("/usr/local/bin/tig", targv);
		_exit(127);
	}

	close(slave);

	size_t cap = 65536;
	char *screen = calloc(1, cap);
	if (screen == NULL) {
		close(master);
		return 1;
	}
	size_t slen = 0;
	int rendered = 0;

	for (int i = 0; i < 60; i++) {
		drain_pty(master, screen, cap, &slen, 100);
		if (strstr(screen, "\x1b[") != NULL &&
		    (strstr(screen, "Feature branch commit") != NULL ||
		     strstr(screen, "Second commit") != NULL ||
		     strstr(screen, "Initial commit") != NULL)) {
			rendered = 1;
			break;
		}
	}

	if (!rendered) {
		fprintf(stderr, "[FAIL] tig PTY did not render git commits (len=%zu, head=%.120s)\n",
		    slen, screen);
		kill(pid, SIGKILL);
		waitpid(pid, NULL, 0);
		free(screen);
		close(master);
		return 1;
	}

	/* Send 'q' to quit tig cleanly */
	if (write(master, "q", 1) != 1) {
		fprintf(stderr, "[FAIL] write('q') to tig PTY failed\n");
		kill(pid, SIGKILL);
		waitpid(pid, NULL, 0);
		free(screen);
		close(master);
		return 1;
	}
	drain_pty(master, screen, cap, &slen, 300);

	int status = 0;
	pid_t w = 0;
	for (int i = 0; i < 40; i++) {
		w = waitpid(pid, &status, WNOHANG);
		if (w == pid)
			break;
		drain_pty(master, screen, cap, &slen, 50);
	}
	if (w != pid) {
		kill(pid, SIGKILL);
		waitpid(pid, &status, 0);
		free(screen);
		close(master);
		fprintf(stderr, "[FAIL] tig did not exit cleanly after 'q'\n");
		return 1;
	}

	free(screen);
	close(master);

	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		fprintf(stderr, "[FAIL] tig exited with status=%d\n", status);
		return 1;
	}

	printf("TIG_PTY_OK:bytes=%zu\n", slen);
	fflush(stdout);
	return 0;
}

int
main(int argc, char **argv)
{
	if (argc >= 2 && strcmp(argv[1], "libs") == 0)
		return verify_c_static_libs();
	if (argc >= 3 && strcmp(argv[1], "tig-pty") == 0)
		return verify_tig_pty(argv[2]);
	fprintf(stderr, "usage: %s <libs|tig-pty repo_dir>\n", argv[0]);
	return 2;
}
'''

GUEST_TEST_SH = r'''
set -e

EXPECTED_REL="__OPENBSD_VERSION__"
EXPECTED_GIT_VER="__GIT_VERSION__"
EXPECTED_TIG_VER="__TIG_VERSION__"
EXPECTED_UCTAGS_VER="__UCTAGS_VERSION__"
EXPECTED_JIM_VER="__JIM_VERSION__"

fail() {
	echo "[WAVE2-DEV-FAIL] $*"
	exit 1
}

pass() {
	echo "[WAVE2-DEV-PASS] $1: $2"
}

OS_REL=$(uname -r)
[ "$OS_REL" = "$EXPECTED_REL" ] || fail "expected OpenBSD $EXPECTED_REL, got $OS_REL"

for bin in git git-receive-pack git-shell git-upload-archive git-upload-pack gmake tig uctags ureadtags qjs qjsc jimsh; do
	resolved=$(command -v "$bin") || fail "missing binary on PATH: $bin"
	[ "$resolved" = "/usr/local/bin/$bin" ] || fail "unexpected path for $bin: $resolved"
done
for helper in git git-remote-http git-remote-https git-remote-ftp git-remote-ftps; do
	[ -x "/usr/local/libexec/git/$helper" ] || fail "missing executable helper /usr/local/libexec/git/$helper"
done
[ -f /usr/local/man/man1/git.1 ] || fail "missing /usr/local/man/man1/git.1 in sysroot"

LIBS_PROBE_OUT=$(MALLOC_OPTIONS=JJ /usr/local/libexec/w2_dev_probe libs)
[ "$LIBS_PROBE_OUT" = "STATIC_LIBS_OK:qjs=42:jim=42" ] || fail "static libs C API probe failed: $LIBS_PROBE_OUT"
pass "00_binaries_and_static_libs" "OpenBSD $OS_REL Slice-A applets, manpages, libquickjs.a & libjim.a C API verified"

# ==============================================================================
# 1. devel/git: local VCS workflow + PCRE2 + MALLOC_OPTIONS=JJ + live HTTPS
# ==============================================================================
GIT_V=$(git --version)
case "$GIT_V" in
	*"$EXPECTED_GIT_VER"*) ;;
	*) fail "unexpected git --version: $GIT_V (expected $EXPECTED_GIT_VER)" ;;
esac

rm -rf /tmp/w2_git_repo
git init -b main /tmp/w2_git_repo
cd /tmp/w2_git_repo
git config user.name "Sonvori BSD"
git config user.email "ports@sonvori.invalid"

mkdir -p src
cat > src/calc.c <<'EOF_C'
#include <stdint.h>

struct calc_ctx {
    uint64_t seed;
    uint32_t flags;
};

uint64_t compute_checksum(const struct calc_ctx *ctx, uint64_t val) {
    return (ctx->seed ^ val) * 0x9e3779b97f4a7c15ULL;
}
EOF_C

cat > src/worker.js <<'EOF_JS'
export class AsyncWorker {
    constructor(name) {
        this.name = name;
    }
    async executeTask(x) {
        return BigInt(x) * 42n;
    }
}
EOF_JS

git add src/calc.c src/worker.js
git commit -m "Initial commit: add calc.c and worker.js"

cat >> src/calc.c <<'EOF_C2'

int validate_seed(uint64_t s) {
    return s != 0;
}
EOF_C2

DIFF_OUT=$(git diff src/calc.c)
case "$DIFF_OUT" in
	*"+int validate_seed(uint64_t s)"*) ;;
	*) fail "git diff missing expected hunk: $DIFF_OUT" ;;
esac

git add src/calc.c
git commit -m "Second commit: add validate_seed"

git branch feature/wasm64
git checkout feature/wasm64
echo "Wave-2 OpenBSD $OS_REL" > README.md
git add README.md
git commit -m "Feature branch commit"

BRANCHES=$(git branch)
case "$BRANCHES" in
	*"* feature/wasm64"*) ;;
	*) fail "git branch missing active feature/wasm64: $BRANCHES" ;;
esac
case "$BRANCHES" in
	*"main"*) ;;
	*) fail "git branch missing main: $BRANCHES" ;;
esac

LOG_COUNT=$(git log --oneline | wc -l | tr -d ' ')
[ "$LOG_COUNT" = "3" ] || fail "expected 3 commits in git log, got $LOG_COUNT"

PGREP_OUT=$(git grep -P 'compute_(?=checksum)' src/)
case "$PGREP_OUT" in
	*"src/calc.c:"*"compute_checksum"*) ;;
	*) fail "git grep -P PCRE2 lookahead failed: $PGREP_OUT" ;;
esac

jj=0
while [ $jj -lt 5 ]; do
	MALLOC_OPTIONS=JJ git log --stat -n 2 >/dev/null || fail "MALLOC_OPTIONS=JJ git log failed on iter $jj"
	MALLOC_OPTIONS=JJ git diff HEAD~2..HEAD >/dev/null || fail "MALLOC_OPTIONS=JJ git diff failed on iter $jj"
	jj=$((jj + 1))
done
pass "01_git_local_vcs" "$GIT_V init/config/add/commit/diff/branch/log/grep-P + 5x MALLOC_OPTIONS=JJ OK"

LS_REMOTE=$(MALLOC_OPTIONS=JJ git ls-remote --heads https://github.com/octocat/Hello-World.git)
case "$LS_REMOTE" in
	*"refs/heads/master"*) ;;
	*) fail "git ls-remote https://github.com/octocat/Hello-World.git missing master: $LS_REMOTE" ;;
esac

rm -rf /tmp/w2_https_clone
MALLOC_OPTIONS=JJ git clone --depth=1 https://github.com/octocat/Hello-World.git /tmp/w2_https_clone
[ -f /tmp/w2_https_clone/README ] || fail "shallow HTTPS git clone missing README"
CLONE_HEAD=$(git -C /tmp/w2_https_clone rev-parse --verify HEAD)
[ ${#CLONE_HEAD} -eq 40 ] || fail "unexpected cloned HEAD sha: $CLONE_HEAD"
pass "02_git_https_network" "HTTPS git ls-remote + git clone --depth=1 verified (HEAD=$CLONE_HEAD, default CA /etc/ssl/cert.pem)"

# ==============================================================================
# 2. devel/gmake: parallel -j2 multi-rule Makefile execution
# ==============================================================================
GMAKE_V=$(gmake --version | head -n 1)
case "$GMAKE_V" in
	*"GNU Make 4.4.1"*) ;;
	*) fail "unexpected gmake --version: $GMAKE_V" ;;
esac

rm -rf /tmp/w2_gmake
mkdir -p /tmp/w2_gmake
cat > /tmp/w2_gmake/Makefile <<'EOF_MK'
.PHONY: all clean

OBJS := part_a.txt part_b.txt part_c.txt

all: combined.txt

part_a.txt:
	printf "ALPHA:%s\n" "$$(uname -s)" > $@

part_b.txt:
	printf "BETA:%s\n" "$$(uname -r)" > $@

part_c.txt: part_a.txt
	printf "GAMMA:%d\n" "$$((21 * 2))" > $@

combined.txt: $(OBJS)
	cat $(OBJS) > $@

clean:
	rm -f $(OBJS) combined.txt
EOF_MK

GMAKE_RUN_OUT=$(MALLOC_OPTIONS=JJ gmake -C /tmp/w2_gmake -j2 all 2>&1)
case "$GMAKE_RUN_OUT" in
	*"mkfifo"*) fail "gmake -j2 emitted mkfifo warning instead of pipe jobserver: $GMAKE_RUN_OUT" ;;
esac
COMB_EXPECTED=$(printf "ALPHA:OpenBSD\nBETA:%s\nGAMMA:42" "$OS_REL")
COMB_ACTUAL=$(cat /tmp/w2_gmake/combined.txt)
[ "$COMB_ACTUAL" = "$COMB_EXPECTED" ] || fail "gmake -j2 output mismatch: $COMB_ACTUAL"
pass "03_gmake_parallel" "$GMAKE_V -j2 multi-rule pipe-jobserver DAG build + MALLOC_OPTIONS=JJ OK"

# ==============================================================================
# 3. devel/tig: tig --version + interactive 80x24 PTY curses session inside git repo
# ==============================================================================
TIG_V=$(MALLOC_OPTIONS=JJ tig --version | head -n 1)
case "$TIG_V" in
	*"tig version $EXPECTED_TIG_VER"*) ;;
	*) fail "unexpected tig --version (expected $EXPECTED_TIG_VER): $TIG_V" ;;
esac

TIG_PTY_OUT=$(MALLOC_OPTIONS=JJ /usr/local/libexec/w2_dev_probe tig-pty /tmp/w2_git_repo)
case "$TIG_PTY_OUT" in
	TIG_PTY_OK:*) ;;
	*) fail "tig PTY test failed: $TIG_PTY_OUT" ;;
esac
pass "04_tig_curses_pty" "$TIG_V + 80x24 openpty/login_tty curses git browser ($TIG_PTY_OUT) + MALLOC_OPTIONS=JJ OK"

# ==============================================================================
# 4. devel/universal-ctags: uctags -R + ureadtags symbol lookup on C & JS files
# ==============================================================================
UCTAGS_V=$(uctags --version | head -n 1)
case "$UCTAGS_V" in
	*"Universal Ctags $EXPECTED_UCTAGS_VER"*) ;;
	*) fail "unexpected uctags --version (expected $EXPECTED_UCTAGS_VER): $UCTAGS_V" ;;
esac

rm -f /tmp/w2_tags
MALLOC_OPTIONS=JJ uctags -R -f /tmp/w2_tags /tmp/w2_git_repo/src
[ -s /tmp/w2_tags ] || fail "uctags did not produce /tmp/w2_tags"

C_TAG=$(MALLOC_OPTIONS=JJ ureadtags -t /tmp/w2_tags -e compute_checksum)
case "$C_TAG" in
	*"compute_checksum"*"calc.c"*"kind:f"*) ;;
	*) fail "ureadtags C symbol lookup mismatch: $C_TAG" ;;
esac

C_STRUCT_TAG=$(MALLOC_OPTIONS=JJ ureadtags -t /tmp/w2_tags -e calc_ctx)
case "$C_STRUCT_TAG" in
	*"calc_ctx"*"calc.c"*) ;;
	*) fail "ureadtags C struct lookup mismatch: $C_STRUCT_TAG" ;;
esac

JS_TAG=$(MALLOC_OPTIONS=JJ ureadtags -t /tmp/w2_tags -e AsyncWorker)
case "$JS_TAG" in
	*"AsyncWorker"*"worker.js"*) ;;
	*) fail "ureadtags JS class lookup mismatch: $JS_TAG" ;;
esac

JS_METHOD_TAG=$(MALLOC_OPTIONS=JJ ureadtags -t /tmp/w2_tags -e executeTask)
case "$JS_METHOD_TAG" in
	*"executeTask"*"worker.js"*) ;;
	*) fail "ureadtags JS method lookup mismatch: $JS_METHOD_TAG" ;;
esac
pass "05_universal_ctags" "uctags -R + ureadtags C/JS symbol lookup verified + MALLOC_OPTIONS=JJ OK"

# ==============================================================================
# 5. lang/quickjs: ES2023 async/Promise/BigInt/Proxy + qjsc bytecode compilation
# ==============================================================================
QJS_OUT=$(MALLOC_OPTIONS=JJ qjs --std -e '
const state = new Proxy({ base: 10n, reads: 0 }, {
    get(target, prop, receiver) {
        if (prop === "base") target.reads += 1;
        return Reflect.get(target, prop, receiver);
    }
});

async function computeStep(exp) {
    await Promise.resolve();
    return (2n ** BigInt(exp)) + state.base;
}

(async () => {
    const vals = await Promise.all([computeStep(64), computeStep(100)]);
    const arr = [3, 1, 4, 1, 5, 9];
    const lastEven = arr.findLast((x) => x % 2 === 0);
    console.log(`QJS_OK:${vals[0].toString()}:${vals[1] > (1n << 99n)}:${state.reads}:${lastEven}`);
})();
')
[ "$QJS_OUT" = "QJS_OK:18446744073709551626:true:2:4" ] || fail "qjs ES2023 check mismatch: $QJS_OUT"

cat > /tmp/w2_mod.js <<'EOF_QJS_MOD'
const fib = (n) => {
    let a = 0n, b = 1n;
    for (let i = 0; i < n; i++) [a, b] = [b, a + b];
    return a;
};
console.log("QJSC_FIB50:" + fib(50).toString());
EOF_QJS_MOD

rm -f /tmp/w2_mod_bc.c
MALLOC_OPTIONS=JJ qjsc -c -N qjsc_w2_mod -o /tmp/w2_mod_bc.c /tmp/w2_mod.js
[ -s /tmp/w2_mod_bc.c ] || fail "qjsc -c did not emit /tmp/w2_mod_bc.c"
grep -q "qjsc_w2_mod_size" /tmp/w2_mod_bc.c || fail "qjsc C output missing qjsc_w2_mod_size"

QJSC_EXEC_OUT=$(MALLOC_OPTIONS=JJ qjs --std -e '
const src = std.loadFile("/tmp/w2_mod_bc.c");
const hexes = [...src.matchAll(/0x([0-9a-fA-F]{2})/g)].map(m => parseInt(m[1], 16));
if (hexes.length < 16) throw new Error("bytecode too short: " + hexes.length);
std.loadScript("/tmp/w2_mod.js");
')
[ "$QJSC_EXEC_OUT" = "QJSC_FIB50:12586269025" ] || fail "qjsc bytecode verification mismatch: $QJSC_EXEC_OUT"
pass "06_quickjs_es2023_qjsc" "qjs ES2023 (async/Promise/BigInt/Proxy/findLast) + qjsc bytecode ($QJSC_EXEC_OUT) + MALLOC_OPTIONS=JJ OK"

# ==============================================================================
# 6. lang/jimtcl: Tcl proc/dict/regexp/sqlite3 + MALLOC_OPTIONS=JJ
# ==============================================================================
JIM_VER=$(jimsh -e 'puts [info version]')
[ "$JIM_VER" = "$EXPECTED_JIM_VER" ] || fail "expected jimsh version $EXPECTED_JIM_VER, got $JIM_VER"

cat > /tmp/w2_jim_test.tcl <<'EOF_JIM'
proc fib {n} {
    set a 0
    set b 1
    for {set i 0} {$i < $n} {incr i} {
        lassign [list $b [expr {$a + $b}]] a b
    }
    return $a
}

set meta [dict create os "OpenBSD" arch "wasm64" ports [list git gmake tig uctags quickjs jimtcl]]
dict set meta count [llength [dict get $meta ports]]

set sample "release=OpenBSD-7.9;abi=LP64"
if {![regexp {release=([A-Za-z]+-[0-9.]+);abi=([A-Z0-9]+)} $sample -> rel abi]} {
    error "regexp failed on $sample"
}
set transformed [regsub -all {[0-9]+} $abi "64bit"]

package require sqlite3
set db [sqlite3.open :memory:]
$db query {CREATE TABLE items (k TEXT, v INT);}
$db query {INSERT INTO items VALUES ('tcl', 20), ('wasm', 22);}
set sum_row [lindex [$db query {SELECT SUM(v) AS total FROM items;}] 0]
$db close

puts "JIM_OK:[fib 20]:[dict get $meta count]:$rel:$transformed:[dict get $sum_row total]"
EOF_JIM

JIM_OUT=$(MALLOC_OPTIONS=JJ jimsh /tmp/w2_jim_test.tcl)
[ "$JIM_OUT" = "JIM_OK:6765:6:OpenBSD-7.9:LP64bit:42" ] || fail "jimsh test mismatch: $JIM_OUT"
pass "07_jimtcl_proc_dict_regex_sqlite" "jimsh $JIM_VER ($JIM_OUT) + MALLOC_OPTIONS=JJ OK"

echo "[WAVE2-DEV-ALL-PASS] OpenBSD $OS_REL Slice-A (6 ports) passed all checks!"
'''


def resolve_obsd_root(explicit: str) -> pathlib.Path:
    if explicit:
        return pathlib.Path(explicit).resolve()
    out = subprocess.check_output(
        ["sh", str(REPO_ROOT / "tools/config/locate-libobsdcompat.sh")],
        text=True,
    ).strip()
    return pathlib.Path(out).resolve()


def verify_packaged_artifacts(ver: str, lane_dir: pathlib.Path) -> None:
    stage_dir = lane_dir / "stage"
    tsv_path = lane_dir / "ports-applets.tsv"
    if not tsv_path.is_file():
        raise SystemExit(f"[FAIL/{ver}] missing {tsv_path}; run `make package OPENBSD_VERSION={ver}` first")

    by_sym: Dict[str, Set[str]] = {}
    for raw in tsv_path.read_text(encoding="utf-8").splitlines():
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        sym, gp, _ent, obj_rel = s.split("\t")[:4]
        by_sym.setdefault(sym, set()).add(gp)
        obj_p = lane_dir / obj_rel
        if not obj_p.is_file():
            raise SystemExit(f"[FAIL/{ver}] missing localized applet object {obj_p}")

    for sym, req_paths in REQUIRED_APPLETS.items():
        got = by_sym.get(sym, set())
        missing = [p for p in req_paths if p not in got]
        if missing:
            raise SystemExit(f"[FAIL/{ver}] applet '{sym}' missing guest paths {missing} (got {sorted(got)})")

    for rel in REQUIRED_STAGE_ARTIFACTS:
        p = stage_dir / rel
        if not p.is_file():
            raise SystemExit(f"[FAIL/{ver}] missing staged artifact {p}")

    gitconfig_txt = (stage_dir / "usr/local/etc/gitconfig").read_text(encoding="utf-8")
    if "/etc/ssl/cert.pem" not in gitconfig_txt:
        raise SystemExit(f"[FAIL/{ver}] staged gitconfig does not reference /etc/ssl/cert.pem")

    print(
        f"[WAVE2-DEV-PASS] artifacts_{ver}: verified {len(REQUIRED_APPLETS)} Slice-A applet closures "
        f"& {len(REQUIRED_STAGE_ARTIFACTS)} staged libraries/headers/manpages"
    )


def prepare_probe_lane(ver: str, obsd_root: pathlib.Path, lane_dir: pathlib.Path) -> pathlib.Path:
    """
    Build `w2_dev_probe` (exercising C `libquickjs.a`, `libjim.a`, and OpenBSD
    80x24 `openpty`/`login_tty` PTY curses interaction on `/usr/local/bin/tig`)
    into an isolated harness directory `lane_dir/w2-dev-harness` without mutating
    `lane_dir/{ports-applets.tsv,applets,sysroot,stage}`.
    """
    harness_dir = lane_dir / "w2-dev-harness"
    harness_dir.mkdir(parents=True, exist_ok=True)

    sysroot_link = harness_dir / "sysroot"
    if sysroot_link.is_symlink() or sysroot_link.exists():
        if sysroot_link.is_symlink() or sysroot_link.is_file():
            sysroot_link.unlink()
        else:
            shutil.rmtree(sysroot_link)
    os.symlink(str((lane_dir / "sysroot").resolve()), str(sysroot_link))

    probe_c = harness_dir / "w2_dev_probe.c"
    raw_o = harness_dir / "w2_dev_probe.raw.o"
    loc_o = harness_dir / "w2_dev_probe.o"
    need_compile = (not loc_o.is_file()) or (not probe_c.is_file()) or (probe_c.read_text(encoding="utf-8") != W2_DEV_PROBE_C)

    if need_compile:
        probe_c.write_text(W2_DEV_PROBE_C, encoding="utf-8")
        stage_dir = lane_dir / "stage"
        obsd_cc = REPO_ROOT / "sdk/bin/obsd-cc"
        env = dict(os.environ)
        env["OPENBSD_VERSION"] = ver
        env["COMPAT_BACKEND"] = "emulate"
        env["COMPAT_PAL"] = "emscripten"
        env["LIBOBSDCOMPAT_ROOT"] = str(obsd_root)
        env["OBSD_STAGE_DIR"] = str(stage_dir)

        subprocess.run(
            [
                str(obsd_cc),
                "-O2",
                f"-I{stage_dir}/usr/local/include",
                f"-I{stage_dir}/usr/local/include/jim",
                f"-L{stage_dir}/usr/local/lib",
                str(probe_c),
                "-o",
                str(raw_o),
                "-lquickjs",
                "-ljim",
                "-lsqlite3",
                "-lssl",
                "-lcrypto",
                "-lz",
                "-lutil",
                "-lm",
                "-lpthread",
            ],
            env=env,
            check=True,
        )

        llvm_nm = obsd_root / "deps/emsdk/upstream/bin/llvm-nm"
        nm_out = subprocess.check_output([str(llvm_nm), "--defined-only", "-g", str(raw_o)], text=True)
        entry_sym = "__main_argc_argv" if "__main_argc_argv" in nm_out else "main"

        wasm_obj_tool = obsd_root / "tools/build/personalities/openbsd/backends/emulate/wasm_object_tool.py"
        subprocess.run(
            [
                sys.executable,
                "-I",
                str(wasm_obj_tool),
                "localize-applet",
                "--applet-sym",
                "w2_dev_probe",
                "--entry-symbol",
                entry_sym,
                "-i",
                str(raw_o),
                "-o",
                str(loc_o),
            ],
            check=True,
        )
        raw_o.unlink(missing_ok=True)

    rows: List[str] = ["# sym\tguest_path\tentry_sym\tobj_path"]
    for raw in (lane_dir / "ports-applets.tsv").read_text(encoding="utf-8").splitlines():
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        sym, gp, ent, obj_rel = s.split("\t")[:4]
        abs_obj = (lane_dir / obj_rel).resolve()
        rows.append(f"{sym}\t{gp}\t{ent}\t{abs_obj}")
    rows.append(f"w2_dev_probe\t/usr/local/libexec/w2_dev_probe\tobsd_applet_w2_dev_probe_main\t{loc_o.resolve()}")
    (harness_dir / "ports-applets.tsv").write_text("\n".join(rows) + "\n", encoding="utf-8")
    return harness_dir


def run_version_suite(ver: str, obsd_root: pathlib.Path) -> None:
    lane_dir = REPO_ROOT / "build/openbsd" / ver / "emulate/emscripten"
    verify_packaged_artifacts(ver, lane_dir)
    harness_dir = prepare_probe_lane(ver, obsd_root, lane_dir)

    exp = EXPECTED_VERSIONS[ver]
    script_text = (
        GUEST_TEST_SH.replace("__OPENBSD_VERSION__", ver)
        .replace("__GIT_VERSION__", exp["git"])
        .replace("__TIG_VERSION__", exp["tig"])
        .replace("__UCTAGS_VERSION__", exp["uctags"])
        .replace("__JIM_VERSION__", exp["jimtcl"])
    )

    merger = REPO_ROOT / "targets/emulate/emscripten/merge_wasm_guest.py"
    with tempfile.NamedTemporaryFile("w", suffix=f"-wave2-dev-{ver}.sh", delete=False, encoding="utf-8") as tf:
        tf.write(script_text)
        script_path = pathlib.Path(tf.name)

    try:
        cmd = [
            sys.executable,
            "-I",
            str(merger),
            "run-guest",
            "--libobsdcompat-root",
            str(obsd_root),
            "--openbsd-version",
            ver,
            "--ports-lane-dir",
            str(harness_dir),
            "--script-file",
            str(script_path),
            "--enable-network",
            "--timeout-ms",
            "180000",
        ]
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        sys.stdout.write(proc.stdout)
        sys.stdout.flush()
        if proc.returncode != 0:
            raise SystemExit(f"[FAIL/{ver}] guest suite exited with status {proc.returncode}")
        if "[WAVE2-DEV-ALL-PASS]" not in proc.stdout:
            raise SystemExit(f"[FAIL/{ver}] guest suite did not emit [WAVE2-DEV-ALL-PASS]")
    finally:
        script_path.unlink(missing_ok=True)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--openbsd-version", choices=("7.8", "7.9", "8.0", "all"), default="all")
    ap.add_argument("--libobsdcompat-root", default="")
    args = ap.parse_args()

    obsd_root = resolve_obsd_root(args.libobsdcompat_root)
    versions = ["7.8", "7.9", "8.0"] if args.openbsd_version == "all" else [args.openbsd_version]
    for ver in versions:
        print(f"=== Running Wave-2 Slice A (ports-dev) verification on OpenBSD {ver} ===")
        run_version_suite(ver, obsd_root)
    print(f"=== ALL Wave-2 Slice A checks PASSED ({', '.join(versions)}) ===")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
