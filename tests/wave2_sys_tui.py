#!/usr/bin/env python3
"""
tests/wave2_sys_tui.py -- Dual-Release (OpenBSD 7.8 + 7.9) WASM64 Verification
Suite for Wave-2 Slice D (Vim + xxd, ncdu, pv, entr, GNU coreutils, GNU
findutils, and libqrencode).

Standalone runnable via:
  python3 tests/wave2_sys_tui.py --openbsd-version 7.8
  python3 tests/wave2_sys_tui.py --openbsd-version 7.9
  python3 tests/wave2_sys_tui.py --openbsd-version all

Uses `targets/emulate/emscripten/merge_wasm_guest.py run-guest` (including
`MALLOC_OPTIONS=JJ` runs and genuine OpenBSD `openpty()` curses TUI sessions).
"""
from __future__ import annotations

import argparse
import hashlib
import os
import pathlib
import subprocess
import sys
import tempfile
from typing import Dict, List, Set, Tuple

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]

PROBE_C_SRC = r'''
/*
 * wave2_sys_tui_probe.c -- OpenBSD WASM64 PTY Curses (vim + ncdu) & libqrencode.a Probe
 */
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

#include <qrencode.h>

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
			char buf[2048];
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
test_qrencode_static_lib(void)
{
	const char *ver = QRcode_APIVersionString();
	if (ver == NULL || strncmp(ver, "4.1.", 4) != 0) {
		fprintf(stderr, "[FAIL] unexpected QRcode_APIVersionString: %s\n", ver ? ver : "NULL");
		return 1;
	}
	QRcode *qr = QRcode_encodeString("https://sonvori.com", 0, QR_ECLEVEL_M, QR_MODE_8, 1);
	if (qr == NULL || qr->width < 21 || qr->data == NULL || (qr->data[0] & 1) == 0) {
		fprintf(stderr, "[FAIL] QRcode_encodeString failed\n");
		if (qr != NULL)
			QRcode_free(qr);
		return 1;
	}
	int w = qr->width;
	QRcode_free(qr);
	printf("[SYS-TUI-PASS] libqrencode_static_c_api: version=%s width=%dx%d\n", ver, w, w);
	fflush(stdout);
	return 0;
}

static int
test_vim_pty_tui(const char *out_path)
{
	unlink(out_path);

	int master = -1, slave = -1;
	struct winsize ws;
	memset(&ws, 0, sizeof(ws));
	ws.ws_row = 24;
	ws.ws_col = 80;
	ws.ws_xpixel = 640;
	ws.ws_ypixel = 384;

	if (openpty(&master, &slave, NULL, NULL, &ws) != 0) {
		fprintf(stderr, "[FAIL] vim openpty failed: errno=%d (%s)\n", errno, strerror(errno));
		return 1;
	}

	pid_t pid = fork();
	if (pid < 0) {
		fprintf(stderr, "[FAIL] vim fork failed: errno=%d\n", errno);
		close(master);
		close(slave);
		return 1;
	}

	if (pid == 0) {
		close(master);
		if (login_tty(slave) != 0)
			_exit(126);
		setenv("TERM", "xterm-256color", 1);
		setenv("LC_CTYPE", "en_US.UTF-8", 1);
		setenv("HOME", "/root", 1);
		char *const vargv[] = {
			(char *)"vim",
			(char *)"-n",
			(char *)"--cmd",
			(char *)"set noswapfile nomodeline viminfo=",
			(char *)out_path,
			NULL
		};
		execv("/usr/local/bin/vim", vargv);
		_exit(127);
	}

	close(slave);

	size_t cap = 131072;
	char *screen = calloc(1, cap);
	if (screen == NULL) {
		close(master);
		return 1;
	}
	size_t slen = 0;

	/* Wait until Vim initializes curses and renders screen escape sequences */
	for (int attempt = 0; attempt < 60; attempt++) {
		drain_pty(master, screen, cap, &slen, 100);
		if (strstr(screen, "\x1b[") != NULL && slen >= 64)
			break;
	}

	if (strstr(screen, "\x1b[") == NULL) {
		fprintf(stderr, "[FAIL] vim did not emit curses ANSI sequences (len=%zu)\n", slen);
		kill(pid, SIGKILL);
		waitpid(pid, NULL, 0);
		free(screen);
		close(master);
		return 1;
	}

	/* Interactive TUI keystrokes: iHello Vim<Esc>:wq<CR> */
	if (write_all_pty(master, "iHello Vim\x1b", 11) != 0) {
		fprintf(stderr, "[FAIL] vim PTY write insert failed\n");
		kill(pid, SIGKILL);
		waitpid(pid, NULL, 0);
		free(screen);
		close(master);
		return 1;
	}
	drain_pty(master, screen, cap, &slen, 200);

	if (write_all_pty(master, ":wq\r", 4) != 0) {
		fprintf(stderr, "[FAIL] vim PTY write :wq failed\n");
		kill(pid, SIGKILL);
		waitpid(pid, NULL, 0);
		free(screen);
		close(master);
		return 1;
	}

	int status = -1;
	int reaped = 0;
	for (int i = 0; i < 120; i++) {
		drain_pty(master, screen, cap, &slen, 50);
		pid_t w = waitpid(pid, &status, WNOHANG);
		if (w == pid) {
			reaped = 1;
			break;
		}
	}
	if (!reaped) {
		kill(pid, SIGTERM);
		waitpid(pid, &status, 0);
	}
	close(master);

	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		fprintf(stderr, "[FAIL] vim PTY exited abnormally: status=0x%x\n", status);
		free(screen);
		return 1;
	}

	FILE *fp = fopen(out_path, "rb");
	if (fp == NULL) {
		fprintf(stderr, "[FAIL] vim PTY did not create %s\n", out_path);
		free(screen);
		return 1;
	}
	char saved[128] = {0};
	size_t nread = fread(saved, 1, sizeof(saved) - 1, fp);
	fclose(fp);

	const char expected[] = "Hello Vim\n";
	if (nread != strlen(expected) || memcmp(saved, expected, nread) != 0) {
		fprintf(stderr, "[FAIL] vim PTY saved mismatch: got '%s' (%zuB), expected '%s'\n",
		    saved, nread, expected);
		free(screen);
		return 1;
	}

	printf("[SYS-TUI-PASS] vim_pty_curses_tui: 80x24 PTY (%zuB ANSI) + iHello Vim<Esc>:wq<CR> verified\n",
	    slen);
	fflush(stdout);
	free(screen);
	return 0;
}

static int
test_ncdu_pty_tui(const char *scan_dir)
{
	int master = -1, slave = -1;
	struct winsize ws;
	memset(&ws, 0, sizeof(ws));
	ws.ws_row = 24;
	ws.ws_col = 80;
	ws.ws_xpixel = 640;
	ws.ws_ypixel = 384;

	if (openpty(&master, &slave, NULL, NULL, &ws) != 0) {
		fprintf(stderr, "[FAIL] ncdu openpty failed: errno=%d (%s)\n", errno, strerror(errno));
		return 1;
	}

	pid_t pid = fork();
	if (pid < 0) {
		fprintf(stderr, "[FAIL] ncdu fork failed: errno=%d\n", errno);
		close(master);
		close(slave);
		return 1;
	}

	if (pid == 0) {
		close(master);
		if (login_tty(slave) != 0)
			_exit(126);
		setenv("TERM", "xterm-256color", 1);
		setenv("LC_CTYPE", "en_US.UTF-8", 1);
		setenv("HOME", "/root", 1);
		char *const nargv[] = {
			(char *)"ncdu",
			(char *)"-r",
			(char *)scan_dir,
			NULL
		};
		execv("/usr/local/bin/ncdu", nargv);
		_exit(127);
	}

	close(slave);

	size_t cap = 131072;
	char *screen = calloc(1, cap);
	if (screen == NULL) {
		close(master);
		return 1;
	}
	size_t slen = 0;

	/* Wait until ncdu finishes scanning scan_dir and renders interactive browser */
	for (int attempt = 0; attempt < 80; attempt++) {
		drain_pty(master, screen, cap, &slen, 100);
		if (strstr(screen, "\x1b[") != NULL &&
		    strstr(screen, "ncdu") != NULL &&
		    (strstr(screen, "Total disk usage") != NULL || strstr(screen, "share") != NULL))
			break;
	}

	if (strstr(screen, "\x1b[") == NULL || strstr(screen, "ncdu") == NULL) {
		fprintf(stderr, "[FAIL] ncdu PTY did not render curses UI (len=%zu)\n", slen);
		kill(pid, SIGKILL);
		waitpid(pid, NULL, 0);
		free(screen);
		close(master);
		return 1;
	}

	/* Send 'q' to quit ncdu cleanly */
	(void)write_all_pty(master, "q", 1);

	int status = -1;
	int reaped = 0;
	for (int i = 0; i < 100; i++) {
		drain_pty(master, screen, cap, &slen, 50);
		pid_t w = waitpid(pid, &status, WNOHANG);
		if (w == pid) {
			reaped = 1;
			break;
		}
	}
	if (!reaped) {
		kill(pid, SIGTERM);
		waitpid(pid, &status, 0);
	}
	close(master);

	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		fprintf(stderr, "[FAIL] ncdu PTY exited abnormally: status=0x%x\n", status);
		free(screen);
		return 1;
	}

	printf("[SYS-TUI-PASS] ncdu_pty_curses_tui: 80x24 PTY (%zuB ANSI) scan of %s + clean 'q' exit verified\n",
	    slen, scan_dir);
	fflush(stdout);
	free(screen);
	return 0;
}

int
main(int argc, char **argv)
{
	const char *mode = (argc > 1) ? argv[1] : "all";
	if (strcmp(mode, "qrencode-lib") == 0 || strcmp(mode, "all") == 0) {
		if (test_qrencode_static_lib() != 0)
			return 1;
	}
	if (strcmp(mode, "vim-pty") == 0 || strcmp(mode, "all") == 0) {
		const char *out_p = (argc > 2) ? argv[2] : "/tmp/vim_pty_test.txt";
		if (test_vim_pty_tui(out_p) != 0)
			return 1;
	}
	if (strcmp(mode, "ncdu-pty") == 0 || strcmp(mode, "all") == 0) {
		const char *dir_p = (argc > 2) ? argv[2] : "/usr/local";
		if (test_ncdu_pty_tui(dir_p) != 0)
			return 1;
	}
	return 0;
}
'''

GUEST_TEST_SCRIPT = r'''
set -eu

fail() {
  echo "[SYS-TUI-FAIL] $*" >&2
  exit 1
}

pass() {
  printf '[SYS-TUI-PASS] %s: %s\n' "$1" "$2"
}

OS_REL=$(/usr/bin/uname -r)
echo "[SYS-TUI-INFO] Running Wave-2 Slice D guest suite on OpenBSD $OS_REL"

# 1. Vim (-Es batch edit + runtime syntax/defaults + aliases) & xxd / xxd -r round-trip
VIM_VER=$(MALLOC_OPTIONS=JJ vim --version | head -n 3)
printf '%s\n' "$VIM_VER" | grep -q "Vi IMproved 9\." || fail "unexpected vim --version: $VIM_VER"
MALLOC_OPTIONS=JJ vimdiff --version | head -n 1 | grep -q "Vi IMproved" || fail "vimdiff alias failed"
MALLOC_OPTIONS=JJ rvim --version | head -n 1 | grep -q "Vi IMproved" || fail "rvim alias failed"
MALLOC_OPTIONS=JJ rview --version | head -n 1 | grep -q "Vi IMproved" || fail "rview alias failed"

rm -rf /tmp/sys_tui
mkdir -p /tmp/sys_tui

cat > /tmp/sys_tui/batch.txt <<'EOF'
alpha one
alpha two
three
EOF

MALLOC_OPTIONS=JJ vim -Es -u NONE -N \
  -c '%s/alpha/OMEGA/g' \
  -c '2normal! A [vim-es]' \
  -c 'wq' /tmp/sys_tui/batch.txt

cat > /tmp/sys_tui/batch.exp <<'EOF'
OMEGA one
OMEGA two [vim-es]
three
EOF
cmp -s /tmp/sys_tui/batch.txt /tmp/sys_tui/batch.exp || fail "vim -Es batch edit output mismatch"

# Interactive openpty() curses Vim TUI (`iHello Vim<Esc>:wq<CR>`) + libqrencode C API
MALLOC_OPTIONS=JJ /usr/local/bin/wave2_sys_tui_probe qrencode-lib
MALLOC_OPTIONS=JJ /usr/local/bin/wave2_sys_tui_probe vim-pty /tmp/sys_tui/vim_pty.txt

# xxd & xxd -r binary round-trip (including NULs and non-ASCII bytes)
MALLOC_OPTIONS=JJ gdd if=/dev/urandom of=/tmp/sys_tui/xxd_orig.bin bs=256 count=1 status=none
ORIG_SHA=$(/bin/sha256 -q /tmp/sys_tui/xxd_orig.bin)
MALLOC_OPTIONS=JJ xxd /tmp/sys_tui/xxd_orig.bin > /tmp/sys_tui/xxd_dump.hex
grep -q "^00000000:" /tmp/sys_tui/xxd_dump.hex || fail "xxd hex dump missing offset header"
MALLOC_OPTIONS=JJ xxd -r /tmp/sys_tui/xxd_dump.hex /tmp/sys_tui/xxd_rev.bin
REV_SHA=$(/bin/sha256 -q /tmp/sys_tui/xxd_rev.bin)
[ "$ORIG_SHA" = "$REV_SHA" ] || fail "xxd -r SHA256 mismatch ($ORIG_SHA != $REV_SHA)"

MALLOC_OPTIONS=JJ xxd -p /tmp/sys_tui/xxd_orig.bin | MALLOC_OPTIONS=JJ xxd -r -p > /tmp/sys_tui/xxd_plain_rev.bin
[ "$(/bin/sha256 -q /tmp/sys_tui/xxd_plain_rev.bin)" = "$ORIG_SHA" ] || fail "xxd -p / -r -p mismatch"
pass "1_vim_and_xxd" "vim -Es batch + PTY curses TUI + xxd/xxd -r SHA256 round-trip OK"

# 2. ncdu JSON export (`ncdu -0 -o - /usr/local`) + interactive PTY curses render
MALLOC_OPTIONS=JJ ncdu -0 -o - /usr/local > /tmp/sys_tui/ncdu.json
MALLOC_OPTIONS=JJ ghead -c 4 /tmp/sys_tui/ncdu.json | grep -q '^\[1,' || fail "ncdu JSON export header invalid"
grep -q '"/usr/local"' /tmp/sys_tui/ncdu.json || fail "ncdu JSON missing /usr/local root"
grep -q '"bin"' /tmp/sys_tui/ncdu.json || fail "ncdu JSON missing bin entry"
grep -q '"share"' /tmp/sys_tui/ncdu.json || fail "ncdu JSON missing share entry"
MALLOC_OPTIONS=JJ /usr/local/bin/wave2_sys_tui_probe ncdu-pty /usr/local
pass "2_ncdu" "ncdu -0 -o - /usr/local JSON scan + 80x24 PTY curses render OK"

# 3. pv pipeline byte transfer (`pv -b -f`)
MALLOC_OPTIONS=JJ gdd if=/dev/urandom of=/tmp/sys_tui/pv_in.bin bs=1024 count=64 status=none
PV_IN_SHA=$(/bin/sha256 -q /tmp/sys_tui/pv_in.bin)
cat /tmp/sys_tui/pv_in.bin | MALLOC_OPTIONS=JJ pv -b -f > /tmp/sys_tui/pv_out.bin 2> /tmp/sys_tui/pv_human.err
[ "$(/bin/sha256 -q /tmp/sys_tui/pv_out.bin)" = "$PV_IN_SHA" ] || fail "pv -b -f corrupted payload"
[ -s /tmp/sys_tui/pv_human.err ] || fail "pv -b -f produced empty stderr progress"
cat /tmp/sys_tui/pv_in.bin | MALLOC_OPTIONS=JJ pv -n -b -f > /tmp/sys_tui/pv_out2.bin 2> /tmp/sys_tui/pv_num.err
[ "$(/bin/sha256 -q /tmp/sys_tui/pv_out2.bin)" = "$PV_IN_SHA" ] || fail "pv -n -b -f corrupted payload"
tail -n 1 /tmp/sys_tui/pv_num.err | grep -q '^65536$' || fail "pv -n -b -f final byte count != 65536: $(cat /tmp/sys_tui/pv_num.err)"
pass "3_pv" "pv -b -f & pv -n -b -f 65536-byte pipeline transfer OK"

# 4. entr (`entr -n` one-shot + `entr -n -p` kqueue EVFILT_VNODE file modification)
mkdir -p /tmp/sys_tui/entr
printf 'hello-entr\n' > /tmp/sys_tui/entr/watch.txt
printf '/tmp/sys_tui/entr/watch.txt\n' | MALLOC_OPTIONS=JJ entr -n -z /bin/ksh -c 'cp "$1" /tmp/sys_tui/entr/oneshot.out' -- /_
[ "$(cat /tmp/sys_tui/entr/oneshot.out)" = "hello-entr" ] || fail "entr -n -z one-shot failed"

rm -f /tmp/sys_tui/entr/postponed.out
printf '/tmp/sys_tui/entr/watch.txt\n' | MALLOC_OPTIONS=JJ entr -n -p -z /bin/ksh -c 'cp "$1" /tmp/sys_tui/entr/postponed.out' -- /_ &
ENTR_PID=$!
sleep 1
if [ -f /tmp/sys_tui/entr/postponed.out ]; then
  kill "$ENTR_PID" 2>/dev/null || true
  fail "entr -n -p executed before watched file was modified"
fi
ATT=0
while [ "$ATT" -lt 25 ]; do
  printf 'modified-%d-%0*d\n' "$ATT" "$((ATT + 1))" 0 > /tmp/sys_tui/entr/watch.txt
  if [ -s /tmp/sys_tui/entr/postponed.out ]; then
    break
  fi
  sleep 1
  ATT=$((ATT + 1))
done
wait "$ENTR_PID"
grep -q '^modified-' /tmp/sys_tui/entr/postponed.out || fail "entr -n -p did not trigger on file modification"
pass "4_entr" "entr -n -z one-shot + entr -n -p kqueue EVFILT_VNODE file-modification trigger OK"

# 5. GNU coreutils single-binary argv[0] multi-call dispatch (`gls` & `/usr/local/bin/gls` + 12 tools)
MALLOC_OPTIONS=JJ gls --color=never /usr/local/bin | grep -qx 'gcoreutils' || fail "bare gls argv[0] dispatch failed"
MALLOC_OPTIONS=JJ /usr/local/bin/gls --color=never /usr/local/bin | grep -qx 'vim' || fail "/usr/local/bin/gls argv[0] dispatch failed"

GSTAT_OUT=$(MALLOC_OPTIONS=JJ gstat -c '%s:%F' /tmp/sys_tui/pv_in.bin)
[ "$GSTAT_OUT" = "65536:regular file" ] || fail "gstat unexpected output: $GSTAT_OUT"

GDATE_OUT=$(MALLOC_OPTIONS=JJ gdate -u -d '@1700000000' '+%Y-%m-%dT%H:%M:%SZ')
[ "$GDATE_OUT" = "2023-11-14T22:13:20Z" ] || fail "gdate unexpected output: $GDATE_OUT"

set -- $(MALLOC_OPTIONS=JJ gsha256sum /tmp/sys_tui/pv_in.bin)
[ "$1" = "$PV_IN_SHA" ] || fail "gsha256sum mismatch ($1 != $PV_IN_SHA)"

set -- $(MALLOC_OPTIONS=JJ gb2sum --length=256 /tmp/sys_tui/pv_in.bin)
[ "${#1}" = "64" ] || fail "gb2sum --length=256 unexpected digest: $1"

SHUF_SORTED=$(MALLOC_OPTIONS=JJ gshuf -i 1-5 | MALLOC_OPTIONS=JJ gsort -n | tr '\n' ' ')
[ "$SHUF_SORTED" = "1 2 3 4 5 " ] || fail "gshuf/gsort permutation mismatch: '$SHUF_SORTED'"

B64_RT=$(printf 'Sonvori Coreutils MultiCall!\n' | MALLOC_OPTIONS=JJ gbase64 | MALLOC_OPTIONS=JJ gbase64 -d)
[ "$B64_RT" = "Sonvori Coreutils MultiCall!" ] || fail "gbase64 round-trip mismatch: $B64_RT"

B32HEX_RT=$(printf 'WASM64' | MALLOC_OPTIONS=JJ gbasenc --base16)
[ "$B32HEX_RT" = "5741534D3634" ] || fail "gbasenc --base16 mismatch: $B32HEX_RT"

GREAL=$(MALLOC_OPTIONS=JJ grealpath /usr/local/bin/../share/vim)
[ "$GREAL" = "/usr/local/share/vim" ] || fail "grealpath mismatch: $GREAL"

GNPROC=$(MALLOC_OPTIONS=JJ gnproc)
[ "$GNPROC" -ge 1 ] || fail "gnproc invalid: $GNPROC"

GSEQ=$(MALLOC_OPTIONS=JJ gseq -s ',' 1 4)
[ "$GSEQ" = "1,2,3,4" ] || fail "gseq mismatch: $GSEQ"

GGID=$(MALLOC_OPTIONS=JJ ggid -u)
[ "$GGID" = "0" ] || fail "ggid (OpenBSD double-g alias) mismatch: $GGID"
pass "5_coreutils_multicall" "single-binary argv[0] dispatch across gls, /usr/local/bin/gls, gstat, gdate, gsha256sum, gb2sum, gshuf, gsort, gbase64, gbasenc, grealpath, gnproc, gseq, ggid OK"

# 6. GNU findutils (`gfind /usr/local -name '*.pc' | gxargs head -n 1`)
FIND_XARGS_OUT=$(MALLOC_OPTIONS=JJ gfind /usr/local -name '*.pc' | MALLOC_OPTIONS=JJ gxargs head -n 1)
printf '%s\n' "$FIND_XARGS_OUT" | grep -q 'libqrencode.pc' || fail "gfind|gxargs missing libqrencode.pc: $FIND_XARGS_OUT"
pass "6_findutils" "gfind /usr/local -name '*.pc' | gxargs head -n 1 OK"

# 7. libqrencode (`qrencode -t ANSIUTF8` + PNG header `\x89PNG\r\n\x1a\n`)
MALLOC_OPTIONS=JJ qrencode -t ANSIUTF8 'https://sonvori.com' > /tmp/sys_tui/qr_ansi.txt
ANSI_LINES=$(wc -l < /tmp/sys_tui/qr_ansi.txt | tr -d ' ')
[ "$ANSI_LINES" -ge 10 ] || fail "qrencode -t ANSIUTF8 too short ($ANSI_LINES lines)"
ESC_CHAR=$(printf '\033')
grep -q "${ESC_CHAR}\[" /tmp/sys_tui/qr_ansi.txt || fail "qrencode -t ANSIUTF8 missing ANSI escapes"

MALLOC_OPTIONS=JJ qrencode -o /tmp/sys_tui/qr.png 'https://sonvori.com'
PNG_MAGIC=$(MALLOC_OPTIONS=JJ xxd -p -l 8 /tmp/sys_tui/qr.png)
[ "$PNG_MAGIC" = "89504e470d0a1a0a" ] || fail "qrencode PNG header mismatch: $PNG_MAGIC"
pass "7_qrencode" "qrencode -t ANSIUTF8 ($ANSI_LINES lines) + PNG magic \\x89PNG\\r\\n\\x1a\\n OK"

echo "[SYS-TUI-ALL-OK] OpenBSD $OS_REL Wave-2 Slice D passed 100%"
'''


def resolve_obsd_root(cli_val: str = "") -> pathlib.Path:
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


def verify_host_packaging(openbsd_version: str, lane_dir: pathlib.Path) -> List[Tuple[str, str, str, pathlib.Path]]:
    tsv_path = lane_dir / "ports-applets.tsv"
    if not tsv_path.is_file():
        raise AssertionError(f"[{openbsd_version}] missing {tsv_path}; run `make package OPENBSD_VERSION={openbsd_version}` first")

    rows: List[Tuple[str, str, str, pathlib.Path]] = []
    by_path: Dict[str, Tuple[str, str, pathlib.Path]] = {}
    coreutils_objs: Set[str] = set()
    coreutils_paths: List[str] = []

    for raw in tsv_path.read_text(encoding="utf-8").splitlines():
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        sym, gpath, entry_sym, obj_rel = s.split("\t")[:4]
        obj_p = (lane_dir / obj_rel).resolve()
        assert obj_p.is_file(), f"[{openbsd_version}] missing localized applet object: {obj_p}"
        rows.append((sym, gpath, entry_sym, obj_p))
        by_path[gpath] = (sym, entry_sym, obj_p)
        if sym == "coreutils":
            coreutils_objs.add(obj_rel)
            coreutils_paths.append(gpath)

    required_paths = [
        "/usr/local/bin/vim",
        "/usr/local/bin/vimdiff",
        "/usr/local/bin/rvim",
        "/usr/local/bin/rview",
        "/usr/local/bin/xxd",
        "/usr/local/bin/ncdu",
        "/usr/local/bin/pv",
        "/usr/local/bin/entr",
        "/usr/local/bin/gcoreutils",
        "/usr/local/bin/gls",
        "/usr/local/bin/gstat",
        "/usr/local/bin/gdate",
        "/usr/local/bin/gsha256sum",
        "/usr/local/bin/gb2sum",
        "/usr/local/bin/gshuf",
        "/usr/local/bin/gbase64",
        "/usr/local/bin/gbasenc",
        "/usr/local/bin/grealpath",
        "/usr/local/bin/gnproc",
        "/usr/local/bin/gsort",
        "/usr/local/bin/gseq",
        "/usr/local/bin/gtimeout",
        "/usr/local/bin/gdu",
        "/usr/local/bin/gdf",
        "/usr/local/bin/ggid",
        "/usr/local/bin/ggod",
        "/usr/local/bin/ggpr",
        "/usr/local/bin/gfind",
        "/usr/local/bin/gxargs",
        "/usr/local/bin/qrencode",
    ]
    for rp in required_paths:
        assert rp in by_path, f"[{openbsd_version}] missing applet guest path in ports-applets.tsv: {rp}"

    # Base /usr/bin/ex & /usr/bin/view must not be shadowed in /usr/local/bin
    for forbidden in ("/usr/local/bin/ex", "/usr/local/bin/view"):
        assert forbidden not in by_path, f"[{openbsd_version}] {forbidden} must not be exported"
        assert not (lane_dir / "sysroot" / forbidden.lstrip("/")).exists(), f"[{openbsd_version}] {forbidden} present in sysroot"

    # Verify coreutils uses exactly ONE single-binary .o closure across ~100+ g* tools
    assert coreutils_objs == {"applets/coreutils.o"}, f"[{openbsd_version}] expected single coreutils.o, got {coreutils_objs}"
    assert len(coreutils_paths) >= 100, f"[{openbsd_version}] expected >=100 coreutils aliases, got {len(coreutils_paths)}"

    # Verify libqrencode.a, qrencode.h, libqrencode.pc
    stage_usr = lane_dir / "stage/usr/local"
    assert (stage_usr / "lib/libqrencode.a").is_file(), f"[{openbsd_version}] missing libqrencode.a"
    assert (stage_usr / "include/qrencode.h").is_file(), f"[{openbsd_version}] missing qrencode.h"
    assert (stage_usr / "lib/pkgconfig/libqrencode.pc").is_file(), f"[{openbsd_version}] missing libqrencode.pc"

    # Verify Vim runtime size hygiene & preserved runtime directories
    vim_share = lane_dir / "sysroot/usr/local/share/vim"
    vim_rts = sorted(p for p in vim_share.glob("vim[0-9]*") if p.is_dir())
    assert len(vim_rts) == 1, f"[{openbsd_version}] expected 1 vim runtime dir under {vim_share}, found {vim_rts}"
    rt = vim_rts[0]
    for must_exist in ("defaults.vim", "filetype.vim", "scripts.vim", "syntax", "indent", "ftplugin", "colors", "autoload", "plugin", "doc"):
        assert (rt / must_exist).exists(), f"[{openbsd_version}] Vim runtime missing required '{must_exist}' in {rt}"
    for trimmed in ("spell", "tutor", "lang", "keymap", "print", "tools"):
        assert not (rt / trimmed).exists(), f"[{openbsd_version}] Vim runtime bloat '{trimmed}' was not trimmed in {rt}"
    if openbsd_version == "7.8":
        assert (rt / "colors/legacy").is_dir(), "[7.8] expected legacy colorschemes staged under colors/legacy"

    svfs_sz = (lane_dir / "ports.svfs.gz").stat().st_size
    print(
        f"[SYS-TUI-HOST] [{openbsd_version}] host artifacts verified: "
        f"coreutils_aliases={len(coreutils_paths)} vim_rt={rt.name} ports.svfs.gz={svfs_sz / (1024 * 1024):.2f}MiB"
    )
    return rows


def prepare_overlay_lane_with_pty_probe(
    openbsd_version: str,
    obsd_root: pathlib.Path,
    lane_dir: pathlib.Path,
    base_rows: List[Tuple[str, str, str, pathlib.Path]],
) -> pathlib.Path:
    overlay_dir = lane_dir / "wave2-sys-tui-lane"
    (overlay_dir / "applets").mkdir(parents=True, exist_ok=True)

    sysroot_link = overlay_dir / "sysroot"
    if sysroot_link.is_symlink() or sysroot_link.exists():
        if sysroot_link.is_symlink():
            sysroot_link.unlink()
    if not sysroot_link.exists():
        os.symlink(str((lane_dir / "sysroot").resolve()), str(sysroot_link))

    owners_src = lane_dir / "ports-owners.db"
    owners_dst = overlay_dir / "ports-owners.db"
    if owners_src.is_file():
        owners_dst.write_bytes(owners_src.read_bytes())

    probe_loc = overlay_dir / "applets/wave2_sys_tui_probe.o"
    probe_sig_file = overlay_dir / "applets/wave2_sys_tui_probe.sig"
    qrencode_a = lane_dir / "stage/usr/local/lib/libqrencode.a"
    sig = hashlib.sha256(
        PROBE_C_SRC.encode("utf-8") + f":{qrencode_a.stat().st_mtime_ns}:{qrencode_a.stat().st_size}".encode()
    ).hexdigest()

    if not probe_loc.is_file() or not probe_sig_file.is_file() or probe_sig_file.read_text().strip() != sig:
        obsd_cc = REPO_ROOT / "sdk/bin/obsd-cc"
        wasm_obj_tool = obsd_root / "tools/build/personalities/openbsd/backends/emulate/wasm_object_tool.py"
        env = dict(os.environ)
        env["OPENBSD_VERSION"] = openbsd_version
        env["LIBOBSDCOMPAT_ROOT"] = str(obsd_root)
        env["OBSD_STAGE_DIR"] = str(lane_dir / "stage")

        with tempfile.TemporaryDirectory(prefix=f"wave2-sys-tui-probe-{openbsd_version}-") as td:
            tp = pathlib.Path(td)
            src_c = tp / "wave2_sys_tui_probe.c"
            raw_bin = tp / "wave2_sys_tui_probe"
            src_c.write_text(PROBE_C_SRC, encoding="utf-8")
            subprocess.run(
                [
                    str(obsd_cc),
                    "-O2",
                    "-Wall",
                    "-Wextra",
                    f"-I{lane_dir}/stage/usr/local/include",
                    str(src_c),
                    f"-L{lane_dir}/stage/usr/local/lib",
                    "-lqrencode",
                    "-lpng",
                    "-lz",
                    "-lm",
                    "-lpthread",
                    "-lutil",
                    "-o",
                    str(raw_bin),
                ],
                env=env,
                check=True,
            )
            subprocess.run(
                [
                    sys.executable,
                    "-I",
                    str(wasm_obj_tool),
                    "localize-applet",
                    "--applet-sym",
                    "wave2_sys_tui_probe",
                    "--entry-symbol",
                    "__main_argc_argv",
                    "-i",
                    str(raw_bin),
                    "-o",
                    str(probe_loc),
                ],
                env=env,
                check=True,
            )
        probe_sig_file.write_text(sig + "\n", encoding="utf-8")

    tsv_lines = ["# sym\tguest_path\tentry_sym\tobj_path"]
    for sym, gpath, entry_sym, obj_p in base_rows:
        tsv_lines.append(f"{sym}\t{gpath}\t{entry_sym}\t{obj_p}")
    tsv_lines.append(
        f"wave2_sys_tui_probe\t/usr/local/bin/wave2_sys_tui_probe\tobsd_applet_wave2_sys_tui_probe_main\t{probe_loc.resolve()}"
    )
    (overlay_dir / "ports-applets.tsv").write_text("\n".join(tsv_lines) + "\n", encoding="utf-8")
    return overlay_dir


def run_version_suite(openbsd_version: str, obsd_root: pathlib.Path, custom_lane_dir: str = "") -> None:
    lane_dir = (
        pathlib.Path(custom_lane_dir).resolve()
        if custom_lane_dir
        else (REPO_ROOT / "build/openbsd" / openbsd_version / "emulate/emscripten").resolve()
    )
    base_rows = verify_host_packaging(openbsd_version, lane_dir)
    overlay_dir = prepare_overlay_lane_with_pty_probe(openbsd_version, obsd_root, lane_dir, base_rows)

    merge_guest_py = REPO_ROOT / "targets/emulate/emscripten/merge_wasm_guest.py"
    with tempfile.NamedTemporaryFile("w", suffix=".sh", prefix=f"wave2_sys_tui_{openbsd_version}_", delete=False) as tf:
        tf.write(GUEST_TEST_SCRIPT)
        script_path = pathlib.Path(tf.name)

    try:
        proc = subprocess.run(
            [
                sys.executable,
                "-I",
                str(merge_guest_py),
                "run-guest",
                "--libobsdcompat-root",
                str(obsd_root),
                "--openbsd-version",
                openbsd_version,
                "--ports-lane-dir",
                str(overlay_dir),
                "--script-file",
                str(script_path),
                "--timeout-ms",
                "240000",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
    finally:
        script_path.unlink(missing_ok=True)

    sys.stdout.write(proc.stdout)
    sys.stdout.flush()
    if proc.returncode != 0:
        raise SystemExit(f"[wave2_sys_tui] OpenBSD {openbsd_version} run-guest failed with exit code {proc.returncode}")
    if f"[SYS-TUI-ALL-OK] OpenBSD {openbsd_version}" not in proc.stdout:
        raise SystemExit(f"[wave2_sys_tui] OpenBSD {openbsd_version} missing completion banner")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--openbsd-version", default=os.environ.get("OPENBSD_VERSION", "all"))
    ap.add_argument("--libobsdcompat-root", default="")
    ap.add_argument("--ports-lane-dir", default="")
    args = ap.parse_args()

    obsd_root = resolve_obsd_root(args.libobsdcompat_root)
    target = args.openbsd_version.strip()
    versions = ["7.8", "7.9", "8.0"] if target in ("", "all") else [v.strip() for v in target.split(",") if v.strip()]

    for ver in versions:
        run_version_suite(ver, obsd_root, args.ports_lane_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
