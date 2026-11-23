#!/usr/bin/env python3
"""
tests/wave4_ai_python.py -- Tri-Release (OpenBSD 7.8 + 7.9 + 8.0) WASM64
Verification Suite for Slice B:
  1. `lang/python/3` (`3.12.11` on 7.8, `3.13.13` on 7.9, `3.14.7` on 8.0)
     - Static stdlib C modules: `ssl` (live HTTPS `urlopen("https://example.com")`
       verifying `/etc/ssl/cert.pem`), `hashlib`, `sqlite3`, `asyncio`,
       `subprocess`, `pty`, `termios`, `fcntl`, `select`, `curses`, `readline`,
       `zlib`, `bz2`, `lzma`, `pyexpat`, `json`, repeated `MALLOC_OPTIONS=JJ` runs.
  2. Pure-Python ecosystem + Official OpenBSD 8.0 `devel/swival` (`1.0.37`):
     - `swival --version` & `swival --help`
     - `tiktoken` lossless roundtrip & `litellm` streaming/async/exception tests
     - Full Multi-Turn Autonomous Coding Agent Loop against a local OpenAI SSE
       server (`/v1/chat/completions`: `read_file` -> `edit_file` -> `run_command`
       `python3 calc.py` -> final answer)
     - Full Multi-Turn Autonomous Coding Agent Loop against a local Anthropic
       `/v1/messages` SSE server (`x-api-key`, `input_schema`, `tool_use` /
       `tool_result`, `thinking_delta` + `input_json_delta` streaming)
     - Live HTTPS web fetch (`certifi.where() == "/etc/ssl/cert.pem"`,
       `httpx.get("https://example.com")`, and `swival` `fetch_url` tool)
     - In-guest `swival` A2A ASGI server (`Starlette` + `uvicorn` + `httpx` over
       OpenBSD `AF_UNIX` socket)
     - Interactive 80x24 `openpty()` `swival` `prompt_toolkit` + `rich` REPL
       startup, `/tools`, and clean `/exit`!

Standalone runnable via:
  python3 -I tests/wave4_ai_python.py --openbsd-version 8.0
  python3 -I tests/wave4_ai_python.py --openbsd-version 7.9
  python3 -I tests/wave4_ai_python.py --openbsd-version 7.8
  python3 -I tests/wave4_ai_python.py --openbsd-version all
"""
from __future__ import annotations

import argparse
import hashlib
import http.server
import json
import os
import pathlib
import socketserver
import subprocess
import sys
import tempfile
import threading
from typing import Any, Dict, List, Tuple

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]

EXPECTED_PYTHON: Dict[str, Tuple[str, str, str]] = {
    "7.8": ("3.12", "3.12.11", "openbsd7"),
    "7.9": ("3.13", "3.13.13", "openbsd7"),
    "8.0": ("3.14", "3.14.7", "openbsd8"),
}

PROBE_C_SRC = r'''
/*
 * wave4_ai_python_probe.c -- OpenBSD WASM64 80x24 openpty() verifier for:
 *   1. CPython `curses` + `readline` interactive TTY rendering (`python-curses-pty`)
 *   2. `swival --repl` interactive `prompt_toolkit` + `rich` TUI startup & `/exit` (`swival-repl-pty`)
 */
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
 * Respond to terminal CPR (`ESC [ 6 n` -> cursor position report `ESC [ 1 ; 1 R`)
 * sent by `prompt_toolkit` on PTY startup.
 */
static void
drain_pty_with_cpr(int master_fd, char *acc, size_t cap, size_t *len_inout, size_t *scan_pos, int wait_ms)
{
	drain_pty(master_fd, acc, cap, len_inout, wait_ms);
	while (*scan_pos + 4 <= *len_inout) {
		if (memcmp(acc + *scan_pos, "\x1b[6n", 4) == 0) {
			(void)write_all_pty(master_fd, "\x1b[1;1R", 6);
			*scan_pos += 4;
			continue;
		}
		(*scan_pos)++;
	}
}

static int
test_python_curses_pty(void)
{
	int master = -1, slave = -1;
	struct winsize ws;
	memset(&ws, 0, sizeof(ws));
	ws.ws_row = 24;
	ws.ws_col = 80;

	if (openpty(&master, &slave, NULL, NULL, &ws) != 0) {
		fprintf(stderr, "[PYAI-FAIL] openpty failed: %s\n", strerror(errno));
		return 1;
	}

	pid_t pid = fork();
	if (pid < 0) {
		close(master);
		close(slave);
		return 1;
	}

	if (pid == 0) {
		close(master);
		if (login_tty(slave) != 0)
			_exit(126);
		setenv("TERM", "xterm-256color", 1);
		setenv("MALLOC_OPTIONS", "JJ", 1);
		setenv("PYTHONPYCACHEPREFIX", "/tmp/.pycache-0", 1);
		char *const argv_py[] = {
			(char *)"python3",
			(char *)"-c",
			(char *)"import curses, readline; "
			        "readline.add_history('obsd_hist_1'); "
			        "assert readline.get_current_history_length() >= 1; "
			        "scr = curses.initscr(); "
			        "rows, cols = scr.getmaxyx(); "
			        "scr.addstr(1, 2, f'CURSES_OK_{cols}x{rows}'); "
			        "scr.refresh(); "
			        "curses.endwin()",
			NULL
		};
		execv("/usr/local/bin/python3", argv_py);
		_exit(127);
	}
	close(slave);

	size_t cap = 65536, rlen = 0;
	char *raw = calloc(1, cap);
	if (!raw) {
		close(master);
		return 1;
	}

	int status = -1;
	for (int i = 0; i < 120; i++) {
		drain_pty(master, raw, cap, &rlen, 100);
		if (waitpid(pid, &status, WNOHANG) == pid)
			break;
	}
	drain_pty(master, raw, cap, &rlen, 100);
	close(master);

	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		fprintf(stderr, "[PYAI-FAIL] python curses child failed (status=0x%x): %s\n", status, raw);
		free(raw);
		return 1;
	}
	if (strstr(raw, "CURSES_OK_80x24") == NULL) {
		fprintf(stderr, "[PYAI-FAIL] missing CURSES_OK_80x24 in PTY output (%zuB): %s\n", rlen, raw);
		free(raw);
		return 1;
	}
	printf("[PYAI-PASS] 3_python_curses_readline_pty: 80x24 curses.initscr() + readline history (%zuB ANSI) OK\n", rlen);
	fflush(stdout);
	free(raw);
	return 0;
}

static int
test_swival_repl_pty(const char *work_dir, const char *base_url)
{
	int master = -1, slave = -1;
	struct winsize ws;
	memset(&ws, 0, sizeof(ws));
	ws.ws_row = 24;
	ws.ws_col = 80;

	if (openpty(&master, &slave, NULL, NULL, &ws) != 0) {
		fprintf(stderr, "[PYAI-FAIL] swival openpty failed: %s\n", strerror(errno));
		return 1;
	}

	pid_t pid = fork();
	if (pid < 0) {
		close(master);
		close(slave);
		return 1;
	}

	if (pid == 0) {
		close(master);
		if (login_tty(slave) != 0)
			_exit(126);
		if (work_dir && work_dir[0])
			(void)chdir(work_dir);
		setenv("TERM", "xterm-256color", 1);
		setenv("LC_CTYPE", "en_US.UTF-8", 1);
		setenv("HOME", "/tmp/swival_repl_home", 1);
		setenv("PYTHONPYCACHEPREFIX", "/tmp/.pycache-0", 1);
		setenv("MALLOC_OPTIONS", "JJ", 1);
		char *const sargv[] = {
			(char *)"swival",
			(char *)"--repl",
			(char *)"--provider",
			(char *)"generic",
			(char *)"--base-url",
			(char *)(base_url && base_url[0] ? base_url : "http://127.0.0.1:18080/v1"),
			(char *)"--model",
			(char *)"gpt-4o",
			(char *)"--api-key",
			(char *)"sk-repl-test",
			(char *)"--max-context-tokens",
			(char *)"128000",
			(char *)"--no-mcp",
			(char *)"--no-skills",
			NULL
		};
		execv("/usr/local/bin/swival", sargv);
		_exit(127);
	}
	close(slave);

	size_t cap = 524288, rlen = 0, scan_pos = 0;
	char *raw = calloc(1, cap);
	if (!raw) {
		close(master);
		return 1;
	}

	int prompt_ready = 0;
	for (int attempt = 0; attempt < 250; attempt++) {
		drain_pty_with_cpr(master, raw, cap, &rlen, &scan_pos, 100);
		if (strstr(raw, "swival>") != NULL) {
			prompt_ready = 1;
			break;
		}
	}

	if (!prompt_ready) {
		fprintf(stderr, "[PYAI-FAIL] swival --repl did not render 'swival>' prompt (rlen=%zu):\n%s\n", rlen, raw);
		kill(pid, SIGKILL);
		waitpid(pid, NULL, 0);
		free(raw);
		close(master);
		return 1;
	}

	/* Let initial prompt_toolkit bottom toolbar redraw + CPR settle */
	drain_pty_with_cpr(master, raw, cap, &rlen, &scan_pos, 150);
	size_t after_p1 = rlen;

	/* Exercise slash command `/tools` and wait for BOTH output AND next `swival>` prompt */
	(void)write_all_pty(master, "/tools\r", 7);
	int saw_tools = 0;
	for (int attempt = 0; attempt < 200; attempt++) {
		drain_pty_with_cpr(master, raw, cap, &rlen, &scan_pos, 100);
		if (strstr(raw + after_p1, "read_file") != NULL &&
		    strstr(raw + after_p1, "edit_file") != NULL &&
		    strstr(raw + after_p1, "swival>") != NULL) {
			saw_tools = 1;
			break;
		}
	}

	if (!saw_tools) {
		fprintf(stderr, "[PYAI-FAIL] swival REPL '/tools' did not render built-in tools + next prompt (rlen=%zu):\n%s\n", rlen, raw + after_p1);
		kill(pid, SIGKILL);
		waitpid(pid, NULL, 0);
		free(raw);
		close(master);
		return 1;
	}

	/* Let second prompt's CPR + toolbar settle before sending `/exit` */
	drain_pty_with_cpr(master, raw, cap, &rlen, &scan_pos, 150);
	(void)write_all_pty(master, "/exit\r", 6);

	int status = -1;
	int reaped = 0;
	for (int i = 0; i < 300; i++) {
		drain_pty_with_cpr(master, raw, cap, &rlen, &scan_pos, 100);
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
		fprintf(stderr, "[PYAI-FAIL] swival --repl exited abnormally after /exit: status=0x%x (reaped=%d)\n", status, reaped);
		free(raw);
		return 1;
	}

	printf("[PYAI-PASS] 6_swival_repl_pty: 80x24 prompt_toolkit + rich REPL ('swival>', '/tools', '/exit' -> exit 0, %zuB ANSI) OK\n", rlen);
	fflush(stdout);
	free(raw);
	return 0;
}

int
main(int argc, char **argv)
{
	const char *mode = (argc > 1) ? argv[1] : "python-curses-pty";
	if (strcmp(mode, "python-curses-pty") == 0)
		return test_python_curses_pty();
	if (strcmp(mode, "swival-repl-pty") == 0)
		return test_swival_repl_pty(
			(argc > 2) ? argv[2] : "/tmp",
			(argc > 3) ? argv[3] : "http://127.0.0.1:18080/v1"
		);
	fprintf(stderr, "unknown mode: %s\n", mode);
	return 1;
}
'''


class _ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class MockLLMAndEchoServer:
    """
    Local 127.0.0.1 HTTP/1.1 + SSE server reached from the OpenBSD WASM64 guest
    over SVNP/1 (`http://127.0.0.1:<port>`):
      1. `GET /v1/models` & `/ping` -> JSON model list / echo check for asyncio TCP
      2. `POST /err/401/chat/completions` & `/err/context/chat/completions` -> error mapping
      3. `POST /v1/chat/completions` -> OpenAI / Gemini / local `llama-server` streaming SSE
         driving multi-turn autonomous `swival` (`read_file` -> `edit_file` -> `run_command`
         `python3 calc.py` -> final answer) + live `fetch_url("https://example.com")`
      4. `POST /v1/messages` -> Anthropic Claude `/v1/messages` streaming SSE (`message_start`,
         `content_block_start`, `thinking_delta`, `input_json_delta`, `text_delta`, `message_delta`,
         `message_stop`) driving multi-turn autonomous `swival` (`tool_use` <-> `tool_result`)!
    """

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.openai_records: List[Dict[str, Any]] = []
        self.anthropic_records: List[Dict[str, Any]] = []

        parent = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, fmt: str, *args: object) -> None:
                return

            def _send_json(self, code: int, obj: Dict[str, Any]) -> None:
                raw = json.dumps(obj).encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(raw)
                self.wfile.flush()

            def _send_sse(self, events: List[str]) -> None:
                body = "".join(events).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream; charset=utf-8")
                self.send_header("Cache-Control", "no-cache")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(body)
                self.wfile.flush()

            def do_GET(self) -> None:
                if self.path == "/ping":
                    self._send_json(200, {"ok": True, "pong": "obsd-svnp-tcp"})
                    return
                if self.path.startswith("/v1/models") or self.path.startswith("/models"):
                    self._send_json(
                        200,
                        {
                            "object": "list",
                            "data": [
                                {"id": "gpt-4o", "object": "model", "context_length": 128000},
                                {"id": "claude-sonnet-4-5", "object": "model", "context_length": 200000},
                            ],
                        },
                    )
                    return
                self._send_json(404, {"error": {"message": "not found"}})

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", "0"))
                raw_body = self.rfile.read(length).decode("utf-8")
                req = json.loads(raw_body)

                if self.path.startswith("/err/401"):
                    self._send_json(
                        401,
                        {"error": {"message": "invalid api key", "type": "authentication_error"}},
                    )
                    return
                if self.path.startswith("/err/context"):
                    self._send_json(
                        400,
                        {
                            "error": {
                                "message": "This model's maximum context length is 8192 tokens.",
                                "code": "context_length_exceeded",
                            }
                        },
                    )
                    return

                # Route 1: OpenAI / Gemini / OpenAI-compatible `/v1/chat/completions` SSE
                if self.path.endswith("/chat/completions"):
                    msgs = req.get("messages", [])
                    user_texts = " ".join(
                        str(m.get("content", ""))
                        for m in msgs
                        if isinstance(m, dict) and m.get("role") == "user"
                    )
                    tool_msgs = [m for m in msgs if isinstance(m, dict) and m.get("role") == "tool"]

                    # Direct unit ping check (not recorded in agent-loop counter)
                    if user_texts.strip() == "UNIT_STREAM_PING":
                        args_json = json.dumps({"file_path": "calc.py"})
                        events = [
                            f"data: {json.dumps({'id': 'chatcmpl-u1', 'model': req.get('model', 'gemini-2.5-flash'), 'choices': [{'index': 0, 'delta': {'role': 'assistant', 'tool_calls': [{'index': 0, 'id': 'call_u1', 'type': 'function', 'function': {'name': 'read_file', 'arguments': args_json[:10]}}]}, 'finish_reason': None}]})}\n\n",
                            f"data: {json.dumps({'id': 'chatcmpl-u1', 'model': req.get('model', 'gemini-2.5-flash'), 'choices': [{'index': 0, 'delta': {'tool_calls': [{'index': 0, 'function': {'arguments': args_json[10:]}}]}, 'finish_reason': None}]})}\n\n",
                            f"data: {json.dumps({'id': 'chatcmpl-u1', 'model': req.get('model', 'gemini-2.5-flash'), 'choices': [{'index': 0, 'delta': {}, 'finish_reason': 'tool_calls'}], 'usage': {'prompt_tokens': 40, 'completion_tokens': 12, 'total_tokens': 52}})}\n\n",
                            "data: [DONE]\n\n",
                        ]
                        self._send_sse(events)
                        return

                    # Live HTTPS `fetch_url` agent task
                    if "FETCH_EXAMPLE_HTTPS_TASK" in user_texts:
                        if not tool_msgs:
                            args_json = json.dumps({"url": "https://example.com", "format": "markdown"})
                            events = [
                                f"data: {json.dumps({'id': 'chatcmpl-f1', 'model': req.get('model', 'gpt-4o'), 'choices': [{'index': 0, 'delta': {'role': 'assistant', 'tool_calls': [{'index': 0, 'id': 'call_fetch_1', 'type': 'function', 'function': {'name': 'fetch_url', 'arguments': args_json[:18]}}]}, 'finish_reason': None}]})}\n\n",
                                f"data: {json.dumps({'id': 'chatcmpl-f1', 'model': req.get('model', 'gpt-4o'), 'choices': [{'index': 0, 'delta': {'tool_calls': [{'index': 0, 'function': {'arguments': args_json[18:]}}]}, 'finish_reason': None}]})}\n\n",
                                f"data: {json.dumps({'id': 'chatcmpl-f1', 'model': req.get('model', 'gpt-4o'), 'choices': [{'index': 0, 'delta': {}, 'finish_reason': 'tool_calls'}], 'usage': {'prompt_tokens': 120, 'completion_tokens': 20, 'total_tokens': 140}})}\n\n",
                                "data: [DONE]\n\n",
                            ]
                            self._send_sse(events)
                            return
                        last_fetch = str(tool_msgs[-1].get("content", ""))
                        ok_tag = (
                            "HTTPS_FETCH_VERIFIED"
                            if ("Example Domain" in last_fetch or "documentation examples" in last_fetch)
                            else f"FETCH_BAD:{last_fetch[:240]}"
                        )
                        events = [
                            f"data: {json.dumps({'id': 'chatcmpl-f2', 'model': req.get('model', 'gpt-4o'), 'choices': [{'index': 0, 'delta': {'role': 'assistant', 'content': ok_tag}, 'finish_reason': None}]})}\n\n",
                            f"data: {json.dumps({'id': 'chatcmpl-f2', 'model': req.get('model', 'gpt-4o'), 'choices': [{'index': 0, 'delta': {}, 'finish_reason': 'stop'}], 'usage': {'prompt_tokens': 200, 'completion_tokens': 10, 'total_tokens': 210}})}\n\n",
                            "data: [DONE]\n\n",
                        ]
                        self._send_sse(events)
                        return

                    # Multi-turn autonomous coding agent loop on `/tmp/calc_proj/calc.py`
                    with parent.lock:
                        parent.openai_records.append(
                            {
                                "path": self.path,
                                "auth": self.headers.get("Authorization", ""),
                                "model": req.get("model"),
                                "messages": msgs,
                                "tools": req.get("tools", []),
                                "stream": req.get("stream"),
                            }
                        )

                    n_tools = len(tool_msgs)
                    if n_tools == 0:
                        tc_id, fn_name, fn_args = "call_oa_1", "read_file", json.dumps({"file_path": "calc.py"})
                    elif n_tools == 1:
                        tc_id, fn_name, fn_args = (
                            "call_oa_2",
                            "edit_file",
                            json.dumps(
                                {
                                    "file_path": "calc.py",
                                    "old_string": "return a - b",
                                    "new_string": "return a + b",
                                }
                            ),
                        )
                    elif n_tools == 2:
                        tc_id, fn_name, fn_args = (
                            "call_oa_3",
                            "run_command",
                            json.dumps({"command": ["python3", "calc.py"]}),
                        )
                    else:
                        cmd_out = str(tool_msgs[-1].get("content", ""))
                        ans = (
                            "OPENAI_AGENT_FIXED_42"
                            if "CALC_OPENAI_PASS_42" in cmd_out
                            else f"UNEXPECTED_CMD_OUT:{cmd_out}"
                        )
                        events = [
                            f"data: {json.dumps({'id': 'chatcmpl-oa4', 'model': 'gpt-4o', 'choices': [{'index': 0, 'delta': {'role': 'assistant', 'reasoning_content': 'Verified test output.', 'content': ans[:10]}, 'finish_reason': None}]})}\n\n",
                            f"data: {json.dumps({'id': 'chatcmpl-oa4', 'model': 'gpt-4o', 'choices': [{'index': 0, 'delta': {'content': ans[10:]}, 'finish_reason': None}]})}\n\n",
                            f"data: {json.dumps({'id': 'chatcmpl-oa4', 'model': 'gpt-4o', 'choices': [{'index': 0, 'delta': {}, 'finish_reason': 'stop'}], 'usage': {'prompt_tokens': 300, 'completion_tokens': 15, 'total_tokens': 315}})}\n\n",
                            "data: [DONE]\n\n",
                        ]
                        self._send_sse(events)
                        return

                    mid = len(fn_args) // 2
                    events = [
                        f"data: {json.dumps({'id': f'chatcmpl-{tc_id}', 'model': 'gpt-4o', 'choices': [{'index': 0, 'delta': {'role': 'assistant', 'tool_calls': [{'index': 0, 'id': tc_id, 'type': 'function', 'function': {'name': fn_name, 'arguments': fn_args[:mid]}}]}, 'finish_reason': None}]})}\n\n",
                        f"data: {json.dumps({'id': f'chatcmpl-{tc_id}', 'model': 'gpt-4o', 'choices': [{'index': 0, 'delta': {'tool_calls': [{'index': 0, 'function': {'arguments': fn_args[mid:]}}]}, 'finish_reason': None}]})}\n\n",
                        f"data: {json.dumps({'id': f'chatcmpl-{tc_id}', 'model': 'gpt-4o', 'choices': [{'index': 0, 'delta': {}, 'finish_reason': 'tool_calls'}], 'usage': {'prompt_tokens': 180, 'completion_tokens': 25, 'total_tokens': 205}})}\n\n",
                        "data: [DONE]\n\n",
                    ]
                    self._send_sse(events)
                    return

                # Route 2: Anthropic Claude `/v1/messages` SSE
                if self.path.endswith("/v1/messages"):
                    with parent.lock:
                        parent.anthropic_records.append(
                            {
                                "x_api_key": self.headers.get("x-api-key", ""),
                                "anthropic_version": self.headers.get("anthropic-version", ""),
                                "model": req.get("model"),
                                "system": req.get("system"),
                                "tools": req.get("tools", []),
                                "messages": req.get("messages", []),
                            }
                        )
                    tool_results: List[Dict[str, Any]] = []
                    for m in req.get("messages", []):
                        if isinstance(m, dict) and m.get("role") == "user" and isinstance(m.get("content"), list):
                            for blk in m["content"]:
                                if isinstance(blk, dict) and blk.get("type") == "tool_result":
                                    tool_results.append(blk)

                    n_tr = len(tool_results)
                    if n_tr == 0:
                        tu_id, fn_name, fn_args = "toolu_ant_1", "read_file", json.dumps({"file_path": "calc.py"})
                    elif n_tr == 1:
                        tu_id, fn_name, fn_args = (
                            "toolu_ant_2",
                            "edit_file",
                            json.dumps(
                                {
                                    "file_path": "calc.py",
                                    "old_string": "return x + y",
                                    "new_string": "return x * y",
                                }
                            ),
                        )
                    elif n_tr == 2:
                        tu_id, fn_name, fn_args = (
                            "toolu_ant_3",
                            "run_command",
                            json.dumps({"command": ["python3", "calc.py"]}),
                        )
                    else:
                        last_out = str(tool_results[-1].get("content", ""))
                        final_txt = (
                            "ANTHROPIC_AGENT_FIXED_42"
                            if "CALC_ANTHROPIC_PASS_42" in last_out
                            else f"BAD_ANT_OUT:{last_out}"
                        )
                        events = [
                            f"event: message_start\ndata: {json.dumps({'type': 'message_start', 'message': {'id': 'msg_ant_final', 'type': 'message', 'role': 'assistant', 'model': req.get('model', 'claude-sonnet-4-5'), 'usage': {'input_tokens': 240, 'cache_read_input_tokens': 100}}})}\n\n",
                            f"event: content_block_start\ndata: {json.dumps({'type': 'content_block_start', 'index': 0, 'content_block': {'type': 'thinking', 'thinking': ''}})}\n\n",
                            f"event: content_block_delta\ndata: {json.dumps({'type': 'content_block_delta', 'index': 0, 'delta': {'type': 'thinking_delta', 'thinking': 'All tests passed.'}})}\n\n",
                            f"event: content_block_stop\ndata: {json.dumps({'type': 'content_block_stop', 'index': 0})}\n\n",
                            f"event: content_block_start\ndata: {json.dumps({'type': 'content_block_start', 'index': 1, 'content_block': {'type': 'text', 'text': ''}})}\n\n",
                            f"event: content_block_delta\ndata: {json.dumps({'type': 'content_block_delta', 'index': 1, 'delta': {'type': 'text_delta', 'text': final_txt[:12]}})}\n\n",
                            f"event: content_block_delta\ndata: {json.dumps({'type': 'content_block_delta', 'index': 1, 'delta': {'type': 'text_delta', 'text': final_txt[12:]}})}\n\n",
                            f"event: content_block_stop\ndata: {json.dumps({'type': 'content_block_stop', 'index': 1})}\n\n",
                            f"event: message_delta\ndata: {json.dumps({'type': 'message_delta', 'delta': {'stop_reason': 'end_turn'}, 'usage': {'output_tokens': 18}})}\n\n",
                            f"event: message_stop\ndata: {json.dumps({'type': 'message_stop'})}\n\n",
                        ]
                        self._send_sse(events)
                        return

                    mid = len(fn_args) // 2
                    events = [
                        f"event: message_start\ndata: {json.dumps({'type': 'message_start', 'message': {'id': f'msg_{tu_id}', 'type': 'message', 'role': 'assistant', 'model': req.get('model', 'claude-sonnet-4-5'), 'usage': {'input_tokens': 190}}})}\n\n",
                        f"event: content_block_start\ndata: {json.dumps({'type': 'content_block_start', 'index': 0, 'content_block': {'type': 'tool_use', 'id': tu_id, 'name': fn_name, 'input': {}}})}\n\n",
                        f"event: content_block_delta\ndata: {json.dumps({'type': 'content_block_delta', 'index': 0, 'delta': {'type': 'input_json_delta', 'partial_json': fn_args[:mid]}})}\n\n",
                        f"event: content_block_delta\ndata: {json.dumps({'type': 'content_block_delta', 'index': 0, 'delta': {'type': 'input_json_delta', 'partial_json': fn_args[mid:]}})}\n\n",
                        f"event: content_block_stop\ndata: {json.dumps({'type': 'content_block_stop', 'index': 0})}\n\n",
                        f"event: message_delta\ndata: {json.dumps({'type': 'message_delta', 'delta': {'stop_reason': 'tool_use'}, 'usage': {'output_tokens': 24}})}\n\n",
                        f"event: message_stop\ndata: {json.dumps({'type': 'message_stop'})}\n\n",
                    ]
                    self._send_sse(events)
                    return

                self._send_json(404, {"error": {"message": f"unhandled path {self.path}"}})

        self._srv = _ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self._srv.server_address[1]
        self._thread = threading.Thread(target=self._srv.serve_forever, daemon=True)
        self._thread.start()

    def close(self) -> None:
        try:
            self._srv.shutdown()
            self._srv.server_close()
        except Exception:
            pass


GUEST_COMMON_SH = r'''
set -eu

export PYTHONPYCACHEPREFIX=/tmp/.pycache-0

fail() {
  echo "[PYAI-FAIL] $*" >&2
  exit 1
}

pass() {
  printf '[PYAI-PASS] %s: %s\n' "$1" "$2"
}

OS_REL=$(/usr/bin/uname -r)
[ "$OS_REL" = "__EXP_REL__" ] || fail "expected OpenBSD __EXP_REL__, got $OS_REL"
echo "[PYAI-INFO] Running Wave-4 CPython & AI Agent suite on OpenBSD $OS_REL"

# 1. Repeated MALLOC_OPTIONS=JJ runs across python3.<minor>, python3, and python
for bin_p in "/usr/local/bin/python__EXP_MINOR__" "/usr/local/bin/python3" "/usr/local/bin/python"; do
  [ -x "$bin_p" ] || fail "missing executable $bin_p"
  VER_OUT=$(MALLOC_OPTIONS=JJ "$bin_p" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}:{sys.platform}")')
  [ "$VER_OUT" = "__EXP_FULL__:__EXP_PLAT__" ] || fail "$bin_p reported $VER_OUT (expected __EXP_FULL__:__EXP_PLAT__)"
done
pass "1_python_ident_malloc_jj" "python__EXP_MINOR__ / python3 / python == __EXP_FULL__ (__EXP_PLAT__) under repeated MALLOC_OPTIONS=JJ OK"

# 2. Comprehensive CPython static stdlib + live TLS HTTPS verification
MALLOC_OPTIONS=JJ /usr/local/bin/python3 - <<'PY_STDLIB_EOF'
import asyncio
import bz2
import curses
import fcntl
import hashlib
import io
import json
import lzma
import os
import pty
import readline
import select
import sqlite3
import ssl
import subprocess
import sys
import termios
import urllib.request
import xml.etree.ElementTree as ET
import zlib

# Verify compression modules roundtrip
payload = (b"OpenBSD WASM64 CPython stdlib verification! " * 64)
assert zlib.decompress(zlib.compress(payload)) == payload
assert bz2.decompress(bz2.compress(payload)) == payload
assert lzma.decompress(lzma.compress(payload)) == payload

# Verify cryptographic hashes (LibreSSL _hashlib + HACL* builtins)
assert len(hashlib.sha256(payload).hexdigest()) == 64
assert len(hashlib.sha512(payload).hexdigest()) == 128
assert len(hashlib.sha3_256(payload).hexdigest()) == 64
assert len(hashlib.blake2b(payload).hexdigest()) == 128
assert len(hashlib.md5(payload).hexdigest()) == 32
assert len(hashlib.sha1(payload).hexdigest()) == 40
dk = hashlib.pbkdf2_hmac("sha256", b"passphrase", b"obsd-salt", 1000, 32)
assert len(dk) == 32

# Verify pyexpat / ElementTree XML parsing
root = ET.fromstring("<ports><port name='python'>3</port></ports>")
assert root.find("port").attrib["name"] == "python" and root.find("port").text == "3"

# Verify SQLite3 WAL + JSON + transactions on OpenBSD VFS
os.makedirs("/tmp/py_test_db", exist_ok=True)
db_file = "/tmp/py_test_db/test.sqlite3"
if os.path.exists(db_file):
    os.unlink(db_file)
conn = sqlite3.connect(db_file)
conn.execute("PRAGMA journal_mode=WAL")
conn.execute("CREATE TABLE items (id INTEGER PRIMARY KEY, meta TEXT)")
conn.executemany("INSERT INTO items (meta) VALUES (?)", [(json.dumps({"k": i}),) for i in range(5)])
conn.commit()
rows = conn.execute("SELECT COUNT(*), SUM(id) FROM items").fetchone()
assert rows == (5, 15), f"unexpected sqlite3 rows: {rows}"
conn.close()

# Verify subprocess + pipes
sp = subprocess.run(["/usr/bin/uname", "-srm"], capture_output=True, text=True, check=True)
assert "OpenBSD" in sp.stdout, f"unexpected subprocess output: {sp.stdout!r}"

# Verify pty + termios + fcntl + select
m_fd, s_fd = pty.openpty()
attrs = termios.tcgetattr(s_fd)
assert isinstance(attrs, list) and len(attrs) >= 6
fl = fcntl.fcntl(m_fd, fcntl.F_GETFL)
assert isinstance(fl, int)
os.write(s_fd, b"pty_ping\n")
rdy, _, _ = select.select([m_fd], [], [], 2.0)
assert m_fd in rdy
read_back = os.read(m_fd, 64)
assert b"pty_ping" in read_back, f"unexpected pty read: {read_back!r}"
os.close(s_fd)
os.close(m_fd)

# Verify asyncio tasks: in-guest AF_UNIX server/client + AF_INET TCP over SVNP/1
async def _asyncio_roundtrips() -> None:
    sock_path = "/tmp/py_asyncio_unix.sock"
    if os.path.exists(sock_path):
        os.unlink(sock_path)

    async def _unix_handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        data = await reader.read(128)
        writer.write(b"ACK:" + data)
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    srv = await asyncio.start_unix_server(_unix_handle, sock_path)
    async with srv:
        u_r, u_w = await asyncio.open_unix_connection(sock_path)
        u_w.write(b"obsd-asyncio")
        await u_w.drain()
        u_w.write_eof()
        reply = await u_r.read(128)
        u_w.close()
        await u_w.wait_closed()
        assert reply == b"ACK:obsd-asyncio", f"unexpected unix asyncio reply: {reply!r}"

    t_r, t_w = await asyncio.open_connection("127.0.0.1", __MOCK_PORT__)
    t_w.write(b"GET /ping HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
    await t_w.drain()
    http_raw = await t_r.read(4096)
    t_w.close()
    await t_w.wait_closed()
    assert b"obsd-svnp-tcp" in http_raw, f"unexpected TCP asyncio HTTP response: {http_raw!r}"

asyncio.run(_asyncio_roundtrips())

# Verify default SSL cert path (/etc/ssl/cert.pem) & live HTTPS TLS verification
vp = ssl.get_default_verify_paths()
assert os.path.isfile("/etc/ssl/cert.pem"), "missing /etc/ssl/cert.pem in guest"
assert vp.cafile == "/etc/ssl/cert.pem" or vp.openssl_cafile == "/etc/ssl/cert.pem", f"unexpected ssl verify paths: {vp}"

req = urllib.request.Request("https://example.com/", headers={"User-Agent": "OpenBSD-CPython-Test/1.0"})
with urllib.request.urlopen(req, timeout=25) as resp:
    assert resp.status == 200, f"expected HTTP 200, got {resp.status}"
    html_body = resp.read().decode("utf-8", errors="replace")
    assert "Example Domain" in html_body, f"missing Example Domain in HTTPS response ({len(html_body)}B)"

# Verify pure-Python TUI/syntax libraries staged across all 3 releases
import wcwidth, mdurl, markdown_it, pygments, prompt_toolkit, rich
from rich.console import Console
buf = io.StringIO()
Console(file=buf, force_terminal=True, width=60).print("[bold green]Rich OpenBSD OK[/bold green]")
assert "Rich OpenBSD OK" in buf.getvalue()

print("[PYAI-PASS] 2_cpython_stdlib_tls: ssl live HTTPS (example.com) + hashlib + sqlite3 WAL + asyncio (UNIX & TCP) + subprocess + pty/termios + zlib/bz2/lzma + rich/prompt_toolkit/pygments OK")
PY_STDLIB_EOF

# 3. 80x24 openpty() CPython curses + readline verification
MALLOC_OPTIONS=JJ /usr/local/bin/wave4_ai_python_probe python-curses-pty
'''

GUEST_80_SWIVAL_SH = r'''
# Warm /tmp/.pycache-0 once so repeated MALLOC_OPTIONS=JJ swival spawns start in <0.5s
/usr/local/bin/python3 -c "import swival.agent, swival.a2a_server, httpx, uvicorn, starlette, prompt_toolkit, rich, litellm, tiktoken"

# 4. OpenBSD 8.0 `devel/swival` (1.0.37) CLI --version & --help under MALLOC_OPTIONS=JJ
SWIVAL_VER=$(MALLOC_OPTIONS=JJ /usr/local/bin/swival --version)
[ "$SWIVAL_VER" = "1.0.37" ] || fail "unexpected swival --version: '$SWIVAL_VER' (expected 1.0.37)"
MALLOC_OPTIONS=JJ /usr/local/bin/swival --help > /tmp/swival_help.txt
grep -q -- "--provider" /tmp/swival_help.txt || fail "swival --help missing --provider"
grep -q -- "--repl" /tmp/swival_help.txt || fail "swival --help missing --repl"
grep -q -- "--serve" /tmp/swival_help.txt || fail "swival --help missing --serve"
pass "4_swival_cli_meta" "swival --version ($SWIVAL_VER) + --help under MALLOC_OPTIONS=JJ OK"

# 5. Pure-Python `tiktoken` + `litellm` + Autonomous Multi-Turn Agent Loops (OpenAI SSE & Anthropic /v1/messages SSE) + Live HTTPS Fetch + A2A Server
MALLOC_OPTIONS=JJ /usr/local/bin/python3 - <<'PY_SWIVAL_SUITE_EOF'
import asyncio
import json
import os
import pathlib
import shutil
import subprocess
import sys

import certifi
import httpx
import litellm
import tiktoken
import uvicorn
from html_to_markdown import convert as html2md
from rank_bm25 import BM25Okapi
from swival.a2a_server import A2aServer
from swival.tokens import count_tokens, truncate_to_tokens

MOCK_PORT = __MOCK_PORT__

# --- 5A. Verify certifi, tiktoken, html_to_markdown, rank_bm25, litellm ---
assert certifi.where() == "/etc/ssl/cert.pem", f"unexpected certifi.where(): {certifi.where()}"
assert set(tiktoken.list_encoding_names()) >= {"cl100k_base", "o200k_base"}
enc = tiktoken.get_encoding("cl100k_base")
enc_gpt4o = tiktoken.encoding_for_model("gpt-4o")
assert enc_gpt4o.name == "o200k_base"

samples = [
    "Hello, OpenBSD 8.0 WASM64!",
    "def fib(n: int) -> int:\n    return n if n <= 1 else fib(n - 1) + fib(n - 2)\n",
    "Unicode lossless check: café, naïve, 東京, 🚀✨, box ─│┌┐└┘!",
    "",
]
for s in samples:
    toks = enc.encode(s)
    assert enc.decode(toks) == s, f"tiktoken roundtrip mismatch on {s!r}"
long_txt = "alpha beta gamma delta epsilon " * 50
trunc = truncate_to_tokens(long_txt, 25)
assert count_tokens(trunc) <= 25 and long_txt.startswith(trunc[:20])

eot_toks = enc.encode("hi<|endoftext|>", allowed_special={"<|endoftext|>"})
assert enc.eot_token in eot_toks and enc.decode(eot_toks) == "hi<|endoftext|>"
try:
    enc.encode("bad<|endoftext|>")
    raise AssertionError("expected ValueError for disallowed special token")
except ValueError:
    pass

md_res = html2md("<h1>Example</h1><p>Visit <a href='https://openbsd.org'>OpenBSD</a>.</p>")
assert "# Example" in md_res.content and "[OpenBSD](https://openbsd.org)" in md_res.content, f"bad md: {md_res.content!r}"
bm25 = BM25Okapi([["openbsd", "wasm", "ports"], ["python", "sqlite", "wal"], ["rust", "cargo", "crate"]])
sc = bm25.get_scores(["openbsd", "ports"])
assert sc[0] > sc[1] and sc[0] > sc[2], f"unexpected bm25 scores: {sc}"

assert litellm.get_max_tokens("gpt-4o") == 16384
assert litellm.get_model_info("anthropic/claude-sonnet-4-5")["max_input_tokens"] == 200000
assert litellm.get_model_info("gemini/gemini-2.5-pro")["litellm_provider"] == "gemini"

try:
    litellm.completion(
        model="openai/gpt-4o",
        messages=[{"role": "user", "content": "hi"}],
        api_base=f"http://127.0.0.1:{MOCK_PORT}/err/401/chat/completions",
        api_key="bad",
    )
    raise AssertionError("expected AuthenticationError")
except litellm.AuthenticationError as e:
    assert e.status_code == 401

try:
    litellm.completion(
        model="openai/gpt-4o",
        messages=[{"role": "user", "content": "hi"}],
        api_base=f"http://127.0.0.1:{MOCK_PORT}/err/context/chat/completions",
        api_key="k",
    )
    raise AssertionError("expected ContextWindowExceededError")
except litellm.ContextWindowExceededError:
    pass

async def _test_async_stream() -> None:
    agen = await litellm.acompletion(
        model="gemini/gemini-2.5-flash",
        messages=[{"role": "user", "content": "UNIT_STREAM_PING"}],
        api_base=f"http://127.0.0.1:{MOCK_PORT}/v1",
        api_key="gem-key",
        stream=True,
    )
    collected = [ch async for ch in agen]
    rebuilt = litellm.stream_chunk_builder(collected)
    assert rebuilt.choices[0].finish_reason == "tool_calls"
    assert rebuilt.choices[0].message.tool_calls[0].function.name == "read_file"

asyncio.run(_test_async_stream())
print("[PYAI-PASS] 5a_tiktoken_litellm_unit: tiktoken 100% lossless roundtrip + html_to_markdown + rank_bm25 + litellm async SSE & exceptions OK", flush=True)

# --- 5B. Autonomous Multi-Turn Coding Agent Loop #1 (OpenAI SSE) ---
proj_oa = pathlib.Path("/tmp/calc_proj")
shutil.rmtree(proj_oa, ignore_errors=True)
proj_oa.mkdir(parents=True)
(proj_oa / "calc.py").write_text(
    "def compute_total(a, b):\n"
    "    return a - b\n\n"
    "if __name__ == '__main__':\n"
    "    assert compute_total(19, 23) == 42, f'got {compute_total(19, 23)}'\n"
    "    print('CALC_OPENAI_PASS_42')\n",
    encoding="utf-8",
)

env_sw = dict(os.environ, MALLOC_OPTIONS="JJ", HOME="/tmp/swival_home_oa", PYTHONPYCACHEPREFIX="/tmp/.pycache-0")
proc_oa = subprocess.run(
    [
        "/usr/local/bin/swival",
        "--provider", "generic",
        "--base-url", f"http://127.0.0.1:{MOCK_PORT}/v1",
        "--model", "gpt-4o",
        "--api-key", "sk-oa-test",
        "--base-dir", str(proj_oa),
        "--commands", "python3",
        "--max-context-tokens", "128000",
        "--no-mcp",
        "--no-skills",
        "--quiet",
        "Fix compute_total in calc.py and verify by running python3 calc.py",
    ],
    env=env_sw,
    capture_output=True,
    text=True,
    timeout=90,
)
assert proc_oa.returncode == 0, f"swival OpenAI loop failed (rc={proc_oa.returncode}):\nSTDOUT: {proc_oa.stdout}\nSTDERR: {proc_oa.stderr}"
assert "OPENAI_AGENT_FIXED_42" in proc_oa.stdout, f"unexpected swival OpenAI stdout: {proc_oa.stdout!r}"
edited_oa = (proj_oa / "calc.py").read_text(encoding="utf-8")
assert "return a + b" in edited_oa and "return a - b" not in edited_oa, f"calc.py was not edited: {edited_oa!r}"
verify_oa = subprocess.run(["/usr/local/bin/python3", str(proj_oa / "calc.py")], capture_output=True, text=True, check=True)
assert "CALC_OPENAI_PASS_42" in verify_oa.stdout
print("[PYAI-PASS] 5b_swival_openai_agent_loop: 4-turn OpenAI SSE autonomous loop (read_file -> edit_file -> run_command python3 calc.py -> exit 0) OK", flush=True)

# --- 5C. Autonomous Multi-Turn Coding Agent Loop #2 (Anthropic /v1/messages SSE) ---
proj_ant = pathlib.Path("/tmp/calc_proj_anthropic")
shutil.rmtree(proj_ant, ignore_errors=True)
proj_ant.mkdir(parents=True)
(proj_ant / "calc.py").write_text(
    "def multiply(x, y):\n"
    "    return x + y\n\n"
    "if __name__ == '__main__':\n"
    "    assert multiply(6, 7) == 42, f'got {multiply(6, 7)}'\n"
    "    print('CALC_ANTHROPIC_PASS_42')\n",
    encoding="utf-8",
)

env_ant = dict(os.environ, MALLOC_OPTIONS="JJ", HOME="/tmp/swival_home_ant", PYTHONPYCACHEPREFIX="/tmp/.pycache-0")
proc_ant = subprocess.run(
    [
        "/usr/local/bin/swival",
        "--provider", "generic",
        "--base-url", f"http://127.0.0.1:{MOCK_PORT}",
        "--model", "anthropic/claude-sonnet-4-5",
        "--api-key", "sk-ant-test",
        "--base-dir", str(proj_ant),
        "--commands", "python3",
        "--max-context-tokens", "200000",
        "--no-mcp",
        "--no-skills",
        "--quiet",
        "Fix multiply in calc.py and verify by running python3 calc.py",
    ],
    env=env_ant,
    capture_output=True,
    text=True,
    timeout=90,
)
assert proc_ant.returncode == 0, f"swival Anthropic loop failed (rc={proc_ant.returncode}):\nSTDOUT: {proc_ant.stdout}\nSTDERR: {proc_ant.stderr}"
assert "ANTHROPIC_AGENT_FIXED_42" in proc_ant.stdout, f"unexpected swival Anthropic stdout: {proc_ant.stdout!r}"
edited_ant = (proj_ant / "calc.py").read_text(encoding="utf-8")
assert "return x * y" in edited_ant and "return x + y" not in edited_ant
verify_ant = subprocess.run(["/usr/local/bin/python3", str(proj_ant / "calc.py")], capture_output=True, text=True, check=True)
assert "CALC_ANTHROPIC_PASS_42" in verify_ant.stdout
print("[PYAI-PASS] 5c_swival_anthropic_agent_loop: 4-turn Anthropic /v1/messages SSE autonomous loop (system + input_schema + tool_use/tool_result + thinking_delta -> exit 0) OK", flush=True)

# --- 5D. Live HTTPS Web Fetch (`httpx.get("https://example.com")` + `swival` `fetch_url` tool) ---
live_resp = httpx.get("https://example.com/", follow_redirects=True, timeout=25.0)
assert live_resp.status_code == 200 and "Example Domain" in live_resp.text, f"httpx live HTTPS failed: {live_resp.status_code}"

proj_fetch = pathlib.Path("/tmp/swival_fetch_proj")
shutil.rmtree(proj_fetch, ignore_errors=True)
proj_fetch.mkdir(parents=True)
proc_fetch = subprocess.run(
    [
        "/usr/local/bin/swival",
        "--provider", "generic",
        "--base-url", f"http://127.0.0.1:{MOCK_PORT}/v1",
        "--model", "gpt-4o",
        "--api-key", "sk-oa-test",
        "--base-dir", str(proj_fetch),
        "--max-context-tokens", "128000",
        "--no-mcp",
        "--no-skills",
        "--quiet",
        "FETCH_EXAMPLE_HTTPS_TASK: fetch https://example.com as markdown",
    ],
    env=env_sw,
    capture_output=True,
    text=True,
    timeout=90,
)
assert proc_fetch.returncode == 0, f"swival fetch_url run failed: {proc_fetch.stderr}"
assert "HTTPS_FETCH_VERIFIED" in proc_fetch.stdout, f"swival fetch_url did not verify Example Domain: {proc_fetch.stdout!r}"
print("[PYAI-PASS] 5d_swival_live_https_fetch: httpx.get('https://example.com') + swival fetch_url (HTML->Markdown over LibreSSL /etc/ssl/cert.pem) OK", flush=True)

# --- 5E. In-Guest `swival` A2A Server (`Starlette` + `uvicorn` + `httpx` over OpenBSD AF_UNIX) ---
async def _verify_a2a_uvicorn_uds() -> None:
    uds_path = "/tmp/swival_a2a.sock"
    if os.path.exists(uds_path):
        os.unlink(uds_path)
    a2a_srv = A2aServer(
        session_kwargs={
            "provider": "generic",
            "base_url": f"http://127.0.0.1:{MOCK_PORT}/v1",
            "model": "gpt-4o",
            "api_key": "sk-oa-test",
            "base_dir": "/tmp/swival_fetch_proj",
        },
        name="obsd-swival-agent",
    )
    uv_cfg = uvicorn.Config(a2a_srv.app, uds=uds_path, log_level="error")
    uv_srv = uvicorn.Server(uv_cfg)
    srv_task = asyncio.create_task(uv_srv.serve())
    try:
        for _ in range(100):
            if os.path.exists(uds_path):
                break
            await asyncio.sleep(0.05)
        assert os.path.exists(uds_path), "uvicorn did not bind /tmp/swival_a2a.sock"

        transport = httpx.AsyncHTTPTransport(uds=uds_path)
        async with httpx.AsyncClient(transport=transport, base_url="http://a2a.local") as client:
            card_r = await client.get("/.well-known/agent-card.json")
            if card_r.status_code == 404:
                card_r = await client.get("/.well-known/agent.json")
            assert card_r.status_code == 200, f"A2A agent card failed: {card_r.status_code}"
            card = card_r.json()
            assert card.get("name") == "obsd-swival-agent", f"unexpected agent card: {card}"

            rpc_r = await client.post(
                "/",
                json={"jsonrpc": "2.0", "id": "req-1", "method": "tasks/list", "params": {}},
            )
            assert rpc_r.status_code == 200 and rpc_r.json().get("id") == "req-1", f"unexpected A2A RPC: {rpc_r.text}"
    finally:
        uv_srv.should_exit = True
        await srv_task

asyncio.run(_verify_a2a_uvicorn_uds())
print("[PYAI-PASS] 5e_swival_a2a_uvicorn_starlette: in-guest uvicorn + Starlette A2A server over OpenBSD AF_UNIX socket OK", flush=True)
PY_SWIVAL_SUITE_EOF

# 6. Interactive 80x24 openpty() `swival --repl` (`prompt_toolkit` + `rich` + `/tools` + `/exit`)
rm -rf /tmp/swival_repl_ws /tmp/swival_repl_home
mkdir -p /tmp/swival_repl_ws /tmp/swival_repl_home
MALLOC_OPTIONS=JJ /usr/local/bin/wave4_ai_python_probe swival-repl-pty /tmp/swival_repl_ws "http://127.0.0.1:__MOCK_PORT__/v1"
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
    exp_minor, _exp_full, _exp_plat = EXPECTED_PYTHON[openbsd_version]
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

    for py_gp in (
        f"/usr/local/bin/python{exp_minor}",
        "/usr/local/bin/python3",
        "/usr/local/bin/python",
    ):
        assert py_gp in by_path, f"[{openbsd_version}] missing python applet guest path in ports-applets.tsv: {py_gp}"

    py_stdlib = lane_dir / f"sysroot/usr/local/lib/python{exp_minor}"
    assert (py_stdlib / "os.py").is_file(), f"[{openbsd_version}] missing staged stdlib {py_stdlib / 'os.py'}"
    for pruned in ("test", "idlelib", "tkinter", "turtledemo", "ensurepip"):
        assert not (py_stdlib / pruned).exists(), f"[{openbsd_version}] unpruned bulky dir {py_stdlib / pruned}"
    pyc_files = list(py_stdlib.rglob("*.pyc"))
    assert not pyc_files, f"[{openbsd_version}] unexpected .pyc files in sysroot: {pyc_files[:5]}"
    libpy_archives = list((lane_dir / "sysroot/usr/local/lib").glob("libpython*.a"))
    assert not libpy_archives, f"[{openbsd_version}] unexpected libpython*.a bloat in sysroot: {libpy_archives}"

    site_dir = py_stdlib / "site-packages"
    for common_pkg in ("wcwidth", "mdurl", "markdown_it", "pygments", "prompt_toolkit", "rich"):
        assert (site_dir / common_pkg).is_dir(), f"[{openbsd_version}] missing site-packages/{common_pkg}"

    if openbsd_version == "8.0":
        swival_bin = lane_dir / "sysroot/usr/local/bin/swival"
        assert swival_bin.is_file(), "[8.0] missing staged /usr/local/bin/swival"
        first_ln = swival_bin.read_text(encoding="utf-8").splitlines()[0]
        assert first_ln == "#!/usr/local/bin/python3", f"[8.0] unexpected swival shebang: {first_ln!r}"
        cert_core = (site_dir / "certifi/core.py").read_text(encoding="utf-8")
        assert "/etc/ssl/cert.pem" in cert_core, "[8.0] certifi/core.py missing /etc/ssl/cert.pem patch"
        for p80 in (
            "swival",
            "tiktoken",
            "litellm",
            "fast_cipher",
            "httpx",
            "httpcore",
            "h11",
            "certifi",
            "sniffio",
            "anyio",
            "idna",
            "starlette",
            "uvicorn",
            "click",
        ):
            assert (site_dir / p80).is_dir(), f"[8.0] missing site-packages/{p80}"
        assert (site_dir / "typing_extensions.py").is_file(), "[8.0] missing typing_extensions.py"
        assert (site_dir / "html_to_markdown.py").is_file(), "[8.0] missing html_to_markdown.py"
        assert (site_dir / "rank_bm25.py").is_file(), "[8.0] missing rank_bm25.py"

    print(
        f"[PYAI-HOST] [{openbsd_version}] host packaging verified: "
        f"python{exp_minor} applet + clean stdlib hygiene"
        + (" + swival-1.0.37 & 18 pure-Python ports" if openbsd_version == "8.0" else "")
    )
    return rows


def prepare_overlay_lane_with_probe(
    openbsd_version: str,
    obsd_root: pathlib.Path,
    lane_dir: pathlib.Path,
    base_rows: List[Tuple[str, str, str, pathlib.Path]],
) -> pathlib.Path:
    overlay_dir = lane_dir / "wave4-ai-python-lane"
    (overlay_dir / "applets").mkdir(parents=True, exist_ok=True)

    sysroot_link = overlay_dir / "sysroot"
    if sysroot_link.is_symlink():
        sysroot_link.unlink()
    if not sysroot_link.exists():
        os.symlink(str((lane_dir / "sysroot").resolve()), str(sysroot_link))

    owners_src = lane_dir / "ports-owners.db"
    owners_dst = overlay_dir / "ports-owners.db"
    if owners_src.is_file():
        owners_dst.write_bytes(owners_src.read_bytes())

    probe_loc = overlay_dir / "applets/wave4_ai_python_probe.o"
    probe_sig_file = overlay_dir / "applets/wave4_ai_python_probe.sig"
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

        with tempfile.TemporaryDirectory(prefix=f"wave4-ai-py-probe-{openbsd_version}-") as td:
            tp = pathlib.Path(td)
            src_c = tp / "wave4_ai_python_probe.c"
            raw_bin = tp / "wave4_ai_python_probe"
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
                    "wave4_ai_python_probe",
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
        f"wave4_ai_python_probe\t/usr/local/bin/wave4_ai_python_probe\tobsd_applet_wave4_ai_python_probe_main\t{probe_loc.resolve()}"
    )
    (overlay_dir / "ports-applets.tsv").write_text("\n".join(tsv_lines) + "\n", encoding="utf-8")
    return overlay_dir


def run_version_suite(openbsd_version: str, obsd_root: pathlib.Path, custom_lane_dir: str = "") -> None:
    if openbsd_version not in EXPECTED_PYTHON:
        raise SystemExit(f"unsupported OpenBSD version: {openbsd_version}")
    exp_minor, exp_full, exp_plat = EXPECTED_PYTHON[openbsd_version]

    lane_dir = (
        pathlib.Path(custom_lane_dir).resolve()
        if custom_lane_dir
        else (REPO_ROOT / "build/openbsd" / openbsd_version / "emulate/emscripten").resolve()
    )
    base_rows = verify_host_packaging(openbsd_version, lane_dir)
    overlay_dir = prepare_overlay_lane_with_probe(openbsd_version, obsd_root, lane_dir, base_rows)

    mock_srv = MockLLMAndEchoServer()
    try:
        guest_script = (
            GUEST_COMMON_SH.replace("__EXP_REL__", openbsd_version)
            .replace("__EXP_MINOR__", exp_minor)
            .replace("__EXP_FULL__", exp_full)
            .replace("__EXP_PLAT__", exp_plat)
            .replace("__MOCK_PORT__", str(mock_srv.port))
        )
        if openbsd_version == "8.0":
            guest_script += "\n" + GUEST_80_SWIVAL_SH.replace("__MOCK_PORT__", str(mock_srv.port))
        guest_script += f'\necho "[PYAI-ALL-OK] OpenBSD {openbsd_version} Wave-4 AI Python suite passed 100%"\n'

        merge_guest_py = REPO_ROOT / "targets/emulate/emscripten/merge_wasm_guest.py"
        with tempfile.NamedTemporaryFile("w", suffix=".sh", prefix=f"wave4_ai_python_{openbsd_version}_", delete=False) as tf:
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
                    "--enable-network",
                    "--script-file",
                    str(script_path),
                    "--timeout-ms",
                    "300000",
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
            raise SystemExit(f"[wave4_ai_python] OpenBSD {openbsd_version} run-guest failed with exit code {proc.returncode}")
        if f"[PYAI-ALL-OK] OpenBSD {openbsd_version}" not in proc.stdout:
            raise SystemExit(f"[wave4_ai_python] OpenBSD {openbsd_version} missing completion banner")

        if openbsd_version == "8.0":
            assert len(mock_srv.openai_records) == 4, (
                f"expected 4 OpenAI agent loop turns, got {len(mock_srv.openai_records)}"
            )
            assert len(mock_srv.anthropic_records) == 4, (
                f"expected 4 Anthropic /v1/messages agent loop turns, got {len(mock_srv.anthropic_records)}"
            )
            ant0 = mock_srv.anthropic_records[0]
            assert ant0["x_api_key"] == "sk-ant-test", f"unexpected Anthropic x-api-key: {ant0['x_api_key']}"
            assert ant0["anthropic_version"] == "2023-06-01", f"unexpected anthropic-version: {ant0['anthropic_version']}"
            assert ant0["system"], "missing Anthropic top-level system prompt"
            assert any("input_schema" in t for t in ant0["tools"]), "missing Anthropic input_schema tools"
            print("[PYAI-HOST] [8.0] verified 4-turn OpenAI SSE & 4-turn Anthropic /v1/messages SSE wire transcripts")
    finally:
        mock_srv.close()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--openbsd-version", default=os.environ.get("OPENBSD_VERSION", "all"))
    ap.add_argument("--libobsdcompat-root", default="")
    ap.add_argument("--ports-lane-dir", default="")
    args = ap.parse_args()

    obsd_root = resolve_obsd_root(args.libobsdcompat_root)
    req = args.openbsd_version.strip()
    versions = ["7.8", "7.9", "8.0"] if req in ("", "all") else [v.strip() for v in req.split(",") if v.strip()]
    for v in versions:
        run_version_suite(v, obsd_root, args.ports_lane_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
