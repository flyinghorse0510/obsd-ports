#!/usr/bin/env python3
"""
tests/wave3_sysmon.py -- Tri-Release (OpenBSD 7.8 + 7.9 + 8.0) WASM64
Verification Suite for Wave-3 System Monitoring & Shell Ports:
  1. `shells/bash` (`5.3.3` on 7.8, `5.3.9` on 7.9, `5.3.20` on 8.0)
  2. `sysutils/neofetch` (`7.1.0p0` on 7.8, 7.9, 8.0)
  3. `sysutils/fastfetch` (`2.53.0` on 7.8, `2.60.0` on 7.9, `2.69.0` on 8.0)
  4. `sysutils/htop` (`3.4.1` on 7.8/7.9, `3.5.3` on 8.0) — 80x24 `openpty()` TUI
  5. `sysutils/btop` (`1.4.5` on 7.8, `1.4.6p0` on 7.9, `1.4.7` on 8.0) — 100x30 `openpty()` C++23 TUI

Standalone runnable via:
  python3 -I tests/wave3_sysmon.py --openbsd-version 8.0
  python3 -I tests/wave3_sysmon.py --openbsd-version 7.9
  python3 -I tests/wave3_sysmon.py --openbsd-version 7.8
  python3 -I tests/wave3_sysmon.py --openbsd-version all
"""
from __future__ import annotations

import argparse
import hashlib
import os
import pathlib
import re
import subprocess
import sys
import tempfile
from typing import Dict, List, Set, Tuple

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "tools/config"))
import obsd_versions  # noqa: E402  (release axis from config/versions/index.tsv)

EXPECTED_VERSIONS: Dict[str, Dict[str, str]] = {
    "7.8": {
        "bash": "5.3.3",
        "htop": "3.4.1",
        "btop": "1.4.5",
        "fastfetch": "2.53.0",
    },
    "7.9": {
        "bash": "5.3.9",
        "htop": "3.4.1",
        "btop": "1.4.6",
        "fastfetch": "2.60.0",
    },
    "8.0": {
        "bash": "5.3.20",
        "htop": "3.5.3",
        "btop": "1.4.7",
        "fastfetch": "2.69.0",
    },
}

PROBE_C_SRC = r'''
/*
 * wave3_sysmon_probe.c -- OpenBSD WASM64 PTY TUI Frame Capture & Clean-Quit
 * Verifier for htop (80x24 widechar curses) and btop (100x30 C++23 Braille/UTF-8).
 */
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <ctype.h>
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

/*
 * Minimal VT100/ANSI screen buffer renderer so we can inspect exact visible
 * rows/columns rendered by ncursesw (htop) and direct ANSI cursor positioning (btop).
 */
static void
render_vt_grid(const char *raw, size_t raw_len, int rows, int cols, char *out_text, size_t out_cap)
{
	char *grid = malloc((size_t)rows * (size_t)cols);
	if (grid == NULL) {
		if (out_cap > 0)
			out_text[0] = '\0';
		return;
	}
	memset(grid, ' ', (size_t)rows * (size_t)cols);

	int r = 0, c = 0;
	size_t i = 0;
	while (i < raw_len) {
		unsigned char ch = (unsigned char)raw[i];
		if (ch == 0x1b) {
			i++;
			if (i >= raw_len)
				break;
			if (raw[i] == '[') {
				i++;
				int params[8] = {0};
				int nparam = 0;
				int cur = -1;
				while (i < raw_len) {
					unsigned char pc = (unsigned char)raw[i];
					if (pc >= '0' && pc <= '9') {
						cur = (cur < 0 ? 0 : cur * 10) + (pc - '0');
						i++;
					} else if (pc == ';') {
						if (nparam < 8)
							params[nparam++] = (cur < 0) ? 0 : cur;
						cur = -1;
						i++;
					} else if (pc == '?' || pc == '>' || pc == ' ') {
						i++;
					} else {
						if (cur >= 0 && nparam < 8)
							params[nparam++] = cur;
						char cmd = raw[i++];
						if (cmd == 'H' || cmd == 'f') {
							r = (nparam >= 1 && params[0] > 0) ? (params[0] - 1) : 0;
							c = (nparam >= 2 && params[1] > 0) ? (params[1] - 1) : 0;
						} else if (cmd == 'A') {
							r -= (nparam >= 1 && params[0] > 0) ? params[0] : 1;
						} else if (cmd == 'B') {
							r += (nparam >= 1 && params[0] > 0) ? params[0] : 1;
						} else if (cmd == 'C') {
							c += (nparam >= 1 && params[0] > 0) ? params[0] : 1;
						} else if (cmd == 'D') {
							c -= (nparam >= 1 && params[0] > 0) ? params[0] : 1;
						} else if (cmd == 'G') {
							c = (nparam >= 1 && params[0] > 0) ? (params[0] - 1) : 0;
						} else if (cmd == 'd') {
							r = (nparam >= 1 && params[0] > 0) ? (params[0] - 1) : 0;
						} else if (cmd == 'J') {
							int mode = (nparam >= 1) ? params[0] : 0;
							if (mode == 2 || mode == 3)
								memset(grid, ' ', (size_t)rows * (size_t)cols);
						} else if (cmd == 'K') {
							int mode = (nparam >= 1) ? params[0] : 0;
							if (r >= 0 && r < rows) {
								int start_c = (mode == 0) ? (c < 0 ? 0 : c) : 0;
								int end_c = (mode == 1) ? (c < cols ? c + 1 : cols) : cols;
								for (int kc = start_c; kc < end_c; kc++)
									grid[r * cols + kc] = ' ';
							}
						} else if (cmd == 'X') {
							int cnt = (nparam >= 1 && params[0] > 0) ? params[0] : 1;
							if (r >= 0 && r < rows) {
								for (int kc = 0; kc < cnt && (c + kc) < cols; kc++)
									if (c + kc >= 0)
										grid[r * cols + c + kc] = ' ';
							}
						}
						if (r < 0) r = 0;
						if (r >= rows) r = rows - 1;
						if (c < 0) c = 0;
						if (c >= cols) c = cols - 1;
						break;
					}
				}
			} else if (raw[i] == ']') {
				i++;
				while (i < raw_len) {
					if ((unsigned char)raw[i] == 0x07) {
						i++;
						break;
					}
					if (raw[i] == 0x1b && i + 1 < raw_len && raw[i + 1] == '\\') {
						i += 2;
						break;
					}
					i++;
				}
			} else if (raw[i] == '(' || raw[i] == ')') {
				i += (i + 1 < raw_len) ? 2 : 1;
			} else {
				i++;
			}
			continue;
		}
		if (ch == '\r') {
			c = 0;
			i++;
			continue;
		}
		if (ch == '\n') {
			r = (r + 1 < rows) ? (r + 1) : (rows - 1);
			i++;
			continue;
		}
		if (ch == '\b') {
			if (c > 0)
				c--;
			i++;
			continue;
		}
		if (ch < 0x20) {
			i++;
			continue;
		}
		if (ch >= 0x80) {
			/* Advance past multi-byte UTF-8 sequence as 1 cell placeholder '#' */
			size_t seq = 1;
			if ((ch & 0xe0) == 0xc0) seq = 2;
			else if ((ch & 0xf0) == 0xe0) seq = 3;
			else if ((ch & 0xf8) == 0xf0) seq = 4;
			if (r >= 0 && r < rows && c >= 0 && c < cols)
				grid[r * cols + c] = '#';
			c++;
			i += (i + seq <= raw_len) ? seq : 1;
			continue;
		}
		if (r >= 0 && r < rows && c >= 0 && c < cols)
			grid[r * cols + c] = (char)ch;
		c++;
		i++;
	}

	size_t pos = 0;
	for (int rr = 0; rr < rows && pos + (size_t)cols + 2 < out_cap; rr++) {
		memcpy(out_text + pos, grid + rr * cols, (size_t)cols);
		pos += (size_t)cols;
		out_text[pos++] = '\n';
	}
	if (out_cap > 0)
		out_text[pos < out_cap ? pos : out_cap - 1] = '\0';
	free(grid);
}

static int
save_file(const char *path, const void *buf, size_t len)
{
	if (path == NULL || path[0] == '\0')
		return 0;
	FILE *fp = fopen(path, "wb");
	if (fp == NULL)
		return -1;
	(void)fwrite(buf, 1, len, fp);
	fclose(fp);
	return 0;
}

static int
test_htop_pty(const char *dump_prefix)
{
	int master = -1, slave = -1;
	struct winsize ws;
	memset(&ws, 0, sizeof(ws));
	ws.ws_row = 24;
	ws.ws_col = 80;
	ws.ws_xpixel = 640;
	ws.ws_ypixel = 384;

	if (openpty(&master, &slave, NULL, NULL, &ws) != 0) {
		fprintf(stderr, "[SYSMON-FAIL] htop openpty failed: %s\n", strerror(errno));
		return 1;
	}

	pid_t pid = fork();
	if (pid < 0) {
		fprintf(stderr, "[SYSMON-FAIL] htop fork failed: %s\n", strerror(errno));
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
		setenv("MALLOC_OPTIONS", "JJ", 1);
		char *const hargv[] = {
			(char *)"htop",
			NULL
		};
		execv("/usr/local/bin/htop", hargv);
		_exit(127);
	}
	close(slave);

	size_t cap = 262144;
	char *raw = calloc(1, cap);
	char *txt = calloc(1, 8192);
	if (raw == NULL || txt == NULL) {
		free(raw);
		free(txt);
		close(master);
		return 1;
	}

	size_t rlen = 0;
	int ready = 0;
	for (int attempt = 0; attempt < 100; attempt++) {
		drain_pty(master, raw, cap, &rlen, 100);
		render_vt_grid(raw, rlen, 24, 80, txt, 8192);
		if (strstr(txt, "Mem[") != NULL &&
		    strstr(txt, "Tasks:") != NULL &&
		    strstr(txt, "PID") != NULL &&
		    strstr(txt, "RES") != NULL &&
		    strstr(txt, "htop") != NULL) {
			ready = 1;
			break;
		}
	}

	if (!ready) {
		fprintf(stderr, "[SYSMON-FAIL] htop 80x24 PTY did not render full screen (rlen=%zu):\n%s\n", rlen, txt);
		kill(pid, SIGKILL);
		waitpid(pid, NULL, 0);
		free(raw);
		free(txt);
		close(master);
		return 1;
	}

	/* Snapshot screen BEFORE sending 'q' so alternate-screen teardown cannot clear it */
	char raw_path[256], txt_path[256];
	snprintf(raw_path, sizeof(raw_path), "%s.raw", dump_prefix);
	snprintf(txt_path, sizeof(txt_path), "%s.txt", dump_prefix);
	save_file(raw_path, raw, rlen);
	save_file(txt_path, txt, strlen(txt));

	if (strstr(txt, "0MHz") != NULL || strstr(txt, "0.0GHz") != NULL) {
		fprintf(stderr, "[SYSMON-FAIL] htop rendered bogus 0MHz CPU frequency:\n%s\n", txt);
		kill(pid, SIGKILL);
		waitpid(pid, NULL, 0);
		free(raw);
		free(txt);
		close(master);
		return 1;
	}

	/* Verify non-zero RES column on the htop process row */
	int res_col_idx = -1;
	int pid_header_found = 0;
	int nonzero_res_found = 0;
	char *saveptr = NULL;
	char *dup_txt = strdup(txt);
	for (char *line = strtok_r(dup_txt, "\n", &saveptr); line != NULL; line = strtok_r(NULL, "\n", &saveptr)) {
		if (!pid_header_found && strstr(line, "PID") != NULL && strstr(line, "RES") != NULL && strstr(line, "Command") != NULL) {
			/* Tokenize header row to locate RES column index */
			char *hdup = strdup(line);
			char *hsp = NULL;
			int col = 0;
			for (char *tok = strtok_r(hdup, " ", &hsp); tok != NULL; tok = strtok_r(NULL, " ", &hsp)) {
				if (strcmp(tok, "RES") == 0) {
					res_col_idx = col;
					break;
				}
				col++;
			}
			free(hdup);
			pid_header_found = 1;
			continue;
		}
		if (pid_header_found && res_col_idx >= 0 && (strstr(line, "htop") != NULL || strstr(line, "ksh") != NULL || strstr(line, "wave3_sysmon") != NULL)) {
			char *rdup = strdup(line);
			char *rsp = NULL;
			int col = 0;
			for (char *tok = strtok_r(rdup, " ", &rsp); tok != NULL; tok = strtok_r(NULL, " ", &rsp)) {
				if (col == res_col_idx) {
					/* Must start with [1-9] (e.g. 1248, 4520, 12.4M, 896K), never "0" */
					if (tok[0] >= '1' && tok[0] <= '9')
						nonzero_res_found = 1;
					break;
				}
				col++;
			}
			free(rdup);
		}
	}
	free(dup_txt);

	if (!nonzero_res_found) {
		fprintf(stderr, "[SYSMON-FAIL] htop process rows showed zero RES memory (res_col_idx=%d):\n%s\n", res_col_idx, txt);
		kill(pid, SIGKILL);
		waitpid(pid, NULL, 0);
		free(raw);
		free(txt);
		close(master);
		return 1;
	}

	/* Send 'q' for clean interactive quit */
	(void)write_all_pty(master, "q", 1);

	int status = -1;
	int reaped = 0;
	for (int i = 0; i < 120; i++) {
		drain_pty(master, raw, cap, &rlen, 50);
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

	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		fprintf(stderr, "[SYSMON-FAIL] htop exited abnormally after 'q': status=0x%x (reaped=%d)\n", status, reaped);
		free(raw);
		free(txt);
		return 1;
	}

	printf("[SYSMON-PASS] htop_pty_tui: 80x24 widechar curses (%zuB ANSI), header bars + live non-zero RES + clean 'q' exit OK\n", rlen);
	fflush(stdout);
	free(raw);
	free(txt);
	return 0;
}

static int
test_btop_pty(const char *dump_prefix)
{
	int master = -1, slave = -1;
	struct winsize ws;
	memset(&ws, 0, sizeof(ws));
	ws.ws_row = 30;
	ws.ws_col = 100;
	ws.ws_xpixel = 800;
	ws.ws_ypixel = 480;

	if (openpty(&master, &slave, NULL, NULL, &ws) != 0) {
		fprintf(stderr, "[SYSMON-FAIL] btop openpty failed: %s\n", strerror(errno));
		return 1;
	}

	pid_t pid = fork();
	if (pid < 0) {
		fprintf(stderr, "[SYSMON-FAIL] btop fork failed: %s\n", strerror(errno));
		close(master);
		close(slave);
		return 1;
	}

	if (pid == 0) {
		close(master);
		if (login_tty(slave) != 0)
			_exit(126);
		setenv("TERM", "xterm-256color", 1);
		setenv("COLORTERM", "truecolor", 1);
		setenv("LC_CTYPE", "en_US.UTF-8", 1);
		setenv("HOME", "/root", 1);
		setenv("MALLOC_OPTIONS", "JJ", 1);
		char *const bargv[] = {
			(char *)"btop",
			(char *)"--utf-force",
			NULL
		};
		execv("/usr/local/bin/btop", bargv);
		_exit(127);
	}
	close(slave);

	size_t cap = 524288;
	char *raw = calloc(1, cap);
	char *txt = calloc(1, 16384);
	if (raw == NULL || txt == NULL) {
		free(raw);
		free(txt);
		close(master);
		return 1;
	}

	size_t rlen = 0;
	int ready = 0;
	for (int attempt = 0; attempt < 120; attempt++) {
		drain_pty(master, raw, cap, &rlen, 100);
		render_vt_grid(raw, rlen, 30, 100, txt, 16384);
		if (rlen >= 1024 &&
		    (strstr(txt, "cpu") != NULL || strstr(txt, "CPU") != NULL) &&
		    (strstr(txt, "mem") != NULL || strstr(txt, "MEM") != NULL) &&
		    (strstr(txt, "disks") != NULL || strstr(txt, "root") != NULL) &&
		    (strstr(txt, "proc") != NULL || strstr(txt, "Pid:") != NULL || strstr(txt, "Program:") != NULL) &&
		    strstr(txt, "btop") != NULL) {
			ready = 1;
			break;
		}
	}

	if (!ready) {
		fprintf(stderr, "[SYSMON-FAIL] btop 100x30 PTY did not render CPU/Mem/Disk/Proc boxes (rlen=%zu):\n%s\n", rlen, txt);
		kill(pid, SIGKILL);
		waitpid(pid, NULL, 0);
		free(raw);
		free(txt);
		close(master);
		return 1;
	}

	char raw_path[256], txt_path[256];
	snprintf(raw_path, sizeof(raw_path), "%s.raw", dump_prefix);
	snprintf(txt_path, sizeof(txt_path), "%s.txt", dump_prefix);
	save_file(raw_path, raw, rlen);
	save_file(txt_path, txt, strlen(txt));

	if (strstr(txt, "0.0 GHz") != NULL || strstr(txt, "0 MHz") != NULL || strstr(txt, "0MHz") != NULL) {
		fprintf(stderr, "[SYSMON-FAIL] btop rendered bogus 0.0 GHz / 0 MHz CPU speed:\n%s\n", txt);
		kill(pid, SIGKILL);
		waitpid(pid, NULL, 0);
		free(raw);
		free(txt);
		close(master);
		return 1;
	}

	/* Verify UTF-8 box-drawing / Braille multi-byte characters were emitted in raw stream */
	int has_utf8_box_or_braille = 0;
	for (size_t i = 0; i + 2 < rlen; i++) {
		unsigned char b0 = (unsigned char)raw[i];
		unsigned char b1 = (unsigned char)raw[i + 1];
		/* U+2500..U+257F box drawing (0xE2 0x94/0x95) or U+2800..U+28FF Braille (0xE2 0xA0..0xA3) */
		if (b0 == 0xe2 && (b1 == 0x94 || b1 == 0x95 || (b1 >= 0xa0 && b1 <= 0xa3))) {
			has_utf8_box_or_braille = 1;
			break;
		}
	}
	if (!has_utf8_box_or_braille) {
		fprintf(stderr, "[SYSMON-FAIL] btop --utf-force did not emit UTF-8 box-drawing/Braille glyphs\n");
		kill(pid, SIGKILL);
		waitpid(pid, NULL, 0);
		free(raw);
		free(txt);
		close(master);
		return 1;
	}

	/* Send 'q' for clean quit */
	(void)write_all_pty(master, "q", 1);

	int status = -1;
	int reaped = 0;
	for (int i = 0; i < 120; i++) {
		drain_pty(master, raw, cap, &rlen, 50);
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

	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		fprintf(stderr, "[SYSMON-FAIL] btop exited abnormally after 'q': status=0x%x (reaped=%d)\n", status, reaped);
		free(raw);
		free(txt);
		return 1;
	}

	printf("[SYSMON-PASS] btop_pty_tui: 100x30 C++23 UTF-8/Braille TUI (%zuB ANSI), CPU/Mem/Disk/Proc boxes + clean 'q' exit OK\n", rlen);
	fflush(stdout);
	free(raw);
	free(txt);
	return 0;
}

int
main(int argc, char **argv)
{
	const char *mode = (argc > 1) ? argv[1] : "all";
	if (strcmp(mode, "htop-pty") == 0 || strcmp(mode, "all") == 0) {
		const char *p = (argc > 2) ? argv[2] : "/tmp/htop_pty";
		if (test_htop_pty(p) != 0)
			return 1;
	}
	if (strcmp(mode, "btop-pty") == 0 || strcmp(mode, "all") == 0) {
		const char *p = (argc > 2) ? argv[2] : "/tmp/btop_pty";
		if (test_btop_pty(p) != 0)
			return 1;
	}
	return 0;
}
'''

GUEST_TEST_TEMPLATE = r'''
set -eu

fail() {
  echo "[SYSMON-FAIL] $*" >&2
  exit 1
}

pass() {
  printf '[SYSMON-PASS] %s: %s\n' "$1" "$2"
}

OS_REL=$(/usr/bin/uname -r)
[ "$OS_REL" = "__EXP_REL__" ] || fail "expected OpenBSD __EXP_REL__, got $OS_REL"
echo "[SYSMON-INFO] Running Wave-3 sysmon & bash guest suite on OpenBSD $OS_REL"

rm -rf /tmp/sysmon
mkdir -p /tmp/sysmon

# 1. GNU Bash 5.3 version + bashisms ([[ =~ ]], indexed/assoc arrays, <<< here-strings, process subst)
BASH_VER=$(MALLOC_OPTIONS=JJ /usr/local/bin/bash --version | head -n 1)
printf '%s\n' "$BASH_VER" | grep -q "__EXP_BASH__" || fail "unexpected bash --version: $BASH_VER (expected __EXP_BASH__)"

BASHISM_OUT=$(MALLOC_OPTIONS=JJ /usr/local/bin/bash -c '
  set -euo pipefail
  rel="OpenBSD-'"$OS_REL"'"
  [[ "$rel" =~ ^OpenBSD-([0-9]+\.[0-9]+)$ ]] || exit 11
  cap="${BASH_REMATCH[1]}"
  ports=(htop btop fastfetch neofetch bash)
  declare -A meta=([os]="OpenBSD" [abi]="wasm64")
  IFS=: read -r x y z <<< "one:two:three"
  ans=$(( 6 * 7 ))
  upper="${y^^}"
  printf "CAP=%s;CNT=%d;P2=%s;HERE=%s-%s;META=%s+%s:%d\n" "$cap" "${#ports[@]}" "${ports[2]}" "$x" "$upper" "${meta[os]}" "${meta[abi]}" "$ans"
')
[ "$BASHISM_OUT" = "CAP=${OS_REL};CNT=5;P2=fastfetch;HERE=one-TWO;META=OpenBSD+wasm64:42" ] || fail "bashisms output mismatch: $BASHISM_OUT"
pass "1_bash_53" "$BASH_VER + [[ =~ ]], arrays, assoc, <<<, (( )) under MALLOC_OPTIONS=JJ OK"

# 2. sysutils/neofetch (--stdout + ANSI Puffie output, verifying zero 0MHz / 0.000GHz bugs)
NEO_PLAIN=$(MALLOC_OPTIONS=JJ /usr/local/bin/neofetch --stdout)
printf '%s\n' "$NEO_PLAIN" | grep -q "OS: OpenBSD $OS_REL" || fail "neofetch --stdout missing 'OS: OpenBSD $OS_REL': $NEO_PLAIN"
printf '%s\n' "$NEO_PLAIN" | grep -q "Uptime:" || fail "neofetch --stdout missing Uptime: $NEO_PLAIN"
printf '%s\n' "$NEO_PLAIN" | grep -q "Shell:" || fail "neofetch --stdout missing Shell: $NEO_PLAIN"
printf '%s\n' "$NEO_PLAIN" | grep -q "Memory:" || fail "neofetch --stdout missing Memory: $NEO_PLAIN"
if printf '%s\n' "$NEO_PLAIN" | grep -Eq '0MHz|0\.000GHz|0\.0GHz|@ 0\.'; then
  fail "neofetch --stdout contains bogus zero CPU speed: $NEO_PLAIN"
fi

MALLOC_OPTIONS=JJ /usr/local/bin/neofetch > /tmp/sysmon/neofetch_ansi.out
ESC_CHAR=$(printf '\033')
grep -q "${ESC_CHAR}\[" /tmp/sysmon/neofetch_ansi.out || fail "neofetch default output missing ANSI escapes"
grep -q "OpenBSD" /tmp/sysmon/neofetch_ansi.out || fail "neofetch default output missing OpenBSD"
pass "2_neofetch" "neofetch --stdout + ANSI Puffie art (OS/Uptime/Shell/Memory verified, 0MHz absent) OK"

# 3. sysutils/fastfetch (--version, --pipe, ANSI logo, and neofetch preset)
FF_VER=$(MALLOC_OPTIONS=JJ /usr/local/bin/fastfetch --version)
printf '%s\n' "$FF_VER" | grep -q "__EXP_FASTFETCH__" || fail "unexpected fastfetch --version: $FF_VER (expected __EXP_FASTFETCH__)"

FF_PIPE=$(MALLOC_OPTIONS=JJ /usr/local/bin/fastfetch --pipe)
printf '%s\n' "$FF_PIPE" | grep -q "OS: OpenBSD" || fail "fastfetch --pipe missing OS: OpenBSD: $FF_PIPE"
printf '%s\n' "$FF_PIPE" | grep -q "Kernel:" || fail "fastfetch --pipe missing Kernel:: $FF_PIPE"
printf '%s\n' "$FF_PIPE" | grep -q "Uptime:" || fail "fastfetch --pipe missing Uptime:: $FF_PIPE"
printf '%s\n' "$FF_PIPE" | grep -q "Memory:" || fail "fastfetch --pipe missing Memory:: $FF_PIPE"
if printf '%s\n' "$FF_PIPE" | grep -Eq '0\.00 GHz|0 MHz|0MHz'; then
  fail "fastfetch --pipe contains bogus zero CPU speed: $FF_PIPE"
fi

MALLOC_OPTIONS=JJ /usr/local/bin/fastfetch --logo OpenBSD --pipe false > /tmp/sysmon/fastfetch_ansi.out
grep -q "${ESC_CHAR}\[" /tmp/sysmon/fastfetch_ansi.out || fail "fastfetch --pipe false missing ANSI escapes"
grep -q "OpenBSD" /tmp/sysmon/fastfetch_ansi.out || fail "fastfetch --pipe false missing OpenBSD"

MALLOC_OPTIONS=JJ /usr/local/bin/fastfetch -c neofetch --pipe > /tmp/sysmon/fastfetch_preset.out
grep -q "OpenBSD" /tmp/sysmon/fastfetch_preset.out || fail "fastfetch -c neofetch preset failed"
pass "3_fastfetch" "$FF_VER --pipe + ANSI logo + neofetch.jsonc preset under MALLOC_OPTIONS=JJ OK"

# 4. sysutils/htop (--version + 80x24 openpty() curses TUI frame capture & non-zero RES)
HTOP_VER=$(MALLOC_OPTIONS=JJ /usr/local/bin/htop --version | head -n 1)
printf '%s\n' "$HTOP_VER" | grep -q "__EXP_HTOP__" || fail "unexpected htop --version: $HTOP_VER (expected __EXP_HTOP__)"
MALLOC_OPTIONS=JJ /usr/local/bin/wave3_sysmon_probe htop-pty /tmp/sysmon/htop_frame

# 5. sysutils/btop (--version + 100x30 openpty() btop --utf-force C++23 TUI frame capture)
BTOP_VER=$(MALLOC_OPTIONS=JJ /usr/local/bin/btop --version | head -n 1)
printf '%s\n' "$BTOP_VER" | grep -q "__EXP_BTOP__" || fail "unexpected btop --version: $BTOP_VER (expected __EXP_BTOP__)"
MALLOC_OPTIONS=JJ /usr/local/bin/wave3_sysmon_probe btop-pty /tmp/sysmon/btop_frame

echo "[SYSMON-ALL-OK] OpenBSD $OS_REL Wave-3 sysmon & bash suite passed 100%"
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
        raise AssertionError(
            f"[{openbsd_version}] missing {tsv_path}; run `make package OPENBSD_VERSION={openbsd_version}` first"
        )

    rows: List[Tuple[str, str, str, pathlib.Path]] = []
    by_path: Dict[str, Tuple[str, str, pathlib.Path]] = {}
    for raw in tsv_path.read_text(encoding="utf-8").splitlines():
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        sym, gpath, entry_sym, obj_rel = s.split("\t")[:4]
        obj_p = (lane_dir / obj_rel).resolve()
        assert obj_p.is_file(), f"[{openbsd_version}] missing localized applet object: {obj_p}"
        rows.append((sym, gpath, entry_sym, obj_p))
        by_path[gpath] = (sym, entry_sym, obj_p)

    for rp in (
        "/usr/local/bin/bash",
        "/usr/local/bin/htop",
        "/usr/local/bin/btop",
        "/usr/local/bin/fastfetch",
    ):
        assert rp in by_path, f"[{openbsd_version}] missing applet guest path in ports-applets.tsv: {rp}"

    # neofetch must be staged as an executable bash script (not a WASM binary stub)
    neofetch_script = lane_dir / "sysroot/usr/local/bin/neofetch"
    assert neofetch_script.is_file(), f"[{openbsd_version}] missing staged script {neofetch_script}"
    first_line = neofetch_script.read_text(encoding="utf-8", errors="replace").splitlines()[0]
    assert first_line == "#!/usr/local/bin/bash", (
        f"[{openbsd_version}] unexpected neofetch shebang: {first_line!r}"
    )

    # Manpages
    man1_dir = lane_dir / "sysroot/usr/local/man/man1"
    for mp in ("bash.1", "htop.1", "btop.1", "fastfetch.1", "neofetch.1"):
        assert (man1_dir / mp).is_file(), f"[{openbsd_version}] missing manpage {man1_dir / mp}"

    # btop themes & fastfetch presets
    themes = sorted((lane_dir / "sysroot/usr/local/share/btop/themes").glob("*.theme"))
    assert len(themes) >= 10, f"[{openbsd_version}] expected >= 10 btop themes, found {len(themes)}"
    assert (lane_dir / "sysroot/usr/local/share/fastfetch/presets/neofetch.jsonc").is_file(), (
        f"[{openbsd_version}] missing fastfetch neofetch.jsonc preset"
    )

    # Verify total packaged ports == 53
    pkg_idx = lane_dir / "packages/index.tsv"
    assert pkg_idx.is_file(), f"[{openbsd_version}] missing {pkg_idx}"
    pkg_rows = [
        ln for ln in pkg_idx.read_text(encoding="utf-8").splitlines() if ln.strip() and not ln.startswith("#")
    ]
    assert len(pkg_rows) == 53, f"[{openbsd_version}] expected 53 packaged ports in {pkg_idx}, got {len(pkg_rows)}"

    print(
        f"[SYSMON-HOST] [{openbsd_version}] host artifacts verified: "
        f"53 packages, {len(themes)} btop themes, 5 manpages, neofetch->#!/usr/local/bin/bash"
    )
    return rows


def prepare_overlay_lane_with_probe(
    openbsd_version: str,
    obsd_root: pathlib.Path,
    lane_dir: pathlib.Path,
    base_rows: List[Tuple[str, str, str, pathlib.Path]],
) -> pathlib.Path:
    overlay_dir = lane_dir / "wave3-sysmon-lane"
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

    probe_loc = overlay_dir / "applets/wave3_sysmon_probe.o"
    probe_sig_file = overlay_dir / "applets/wave3_sysmon_probe.sig"
    base_ar = obsd_root / f"build/wasm-{openbsd_version}/libobsdc-wasm-{openbsd_version}.a"
    sig = hashlib.sha256(
        PROBE_C_SRC.encode("utf-8") + f":{base_ar.stat().st_mtime_ns}:{base_ar.stat().st_size}".encode()
    ).hexdigest()

    if not probe_loc.is_file() or not probe_sig_file.is_file() or probe_sig_file.read_text().strip() != sig:
        obsd_cc = REPO_ROOT / "sdk/bin/obsd-cc"
        wasm_obj_tool = obsd_root / "tools/build/personalities/openbsd/backends/emulate/wasm_object_tool.py"
        env = dict(os.environ)
        env["OPENBSD_VERSION"] = openbsd_version
        env["LIBOBSDCOMPAT_ROOT"] = str(obsd_root)
        env["OBSD_STAGE_DIR"] = str(lane_dir / "stage")

        with tempfile.TemporaryDirectory(prefix=f"wave3-sysmon-probe-{openbsd_version}-") as td:
            tp = pathlib.Path(td)
            src_c = tp / "wave3_sysmon_probe.c"
            raw_bin = tp / "wave3_sysmon_probe"
            src_c.write_text(PROBE_C_SRC, encoding="utf-8")
            subprocess.run(
                [
                    str(obsd_cc),
                    "-O2",
                    "-Wall",
                    "-Wextra",
                    str(src_c),
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
                    "wave3_sysmon_probe",
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
        f"wave3_sysmon_probe\t/usr/local/bin/wave3_sysmon_probe\tobsd_applet_wave3_sysmon_probe_main\t{probe_loc.resolve()}"
    )
    (overlay_dir / "ports-applets.tsv").write_text("\n".join(tsv_lines) + "\n", encoding="utf-8")
    return overlay_dir


def run_version_suite(openbsd_version: str, obsd_root: pathlib.Path, custom_lane_dir: str = "") -> None:
    if openbsd_version not in EXPECTED_VERSIONS:
        raise SystemExit(f"unsupported OpenBSD version: {openbsd_version}")
    exp = EXPECTED_VERSIONS[openbsd_version]

    lane_dir = (
        pathlib.Path(custom_lane_dir).resolve()
        if custom_lane_dir
        else (REPO_ROOT / "build/openbsd" / openbsd_version / "emulate/emscripten").resolve()
    )
    base_rows = verify_host_packaging(openbsd_version, lane_dir)
    overlay_dir = prepare_overlay_lane_with_probe(openbsd_version, obsd_root, lane_dir, base_rows)

    guest_script = (
        GUEST_TEST_TEMPLATE.replace("__EXP_REL__", openbsd_version)
        .replace("__EXP_BASH__", exp["bash"])
        .replace("__EXP_HTOP__", exp["htop"])
        .replace("__EXP_BTOP__", exp["btop"])
        .replace("__EXP_FASTFETCH__", exp["fastfetch"])
    )

    merge_guest_py = REPO_ROOT / "targets/emulate/emscripten/merge_wasm_guest.py"
    with tempfile.NamedTemporaryFile("w", suffix=".sh", prefix=f"wave3_sysmon_{openbsd_version}_", delete=False) as tf:
        tf.write(guest_script)
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
        raise SystemExit(f"[wave3_sysmon] OpenBSD {openbsd_version} run-guest failed with exit code {proc.returncode}")
    if f"[SYSMON-ALL-OK] OpenBSD {openbsd_version}" not in proc.stdout:
        raise SystemExit(f"[wave3_sysmon] OpenBSD {openbsd_version} missing completion banner")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--openbsd-version", default=os.environ.get("OPENBSD_VERSION", "all"))
    ap.add_argument("--libobsdcompat-root", default="")
    ap.add_argument("--ports-lane-dir", default="")
    args = ap.parse_args()

    obsd_root = resolve_obsd_root(args.libobsdcompat_root)
    req = args.openbsd_version.strip()
    versions = obsd_versions.resolve_versions(req)
    for v in versions:
        run_version_suite(v, obsd_root, args.ports_lane_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
