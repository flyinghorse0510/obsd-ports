#!/usr/bin/env python3
"""
tests/wave5_extra_ai_agents.py -- Tri-Release (OpenBSD 7.8 + 7.9 + 8.0) WASM64
End-to-End Verification Suite for Wave-5 (`obsd-ports/extra/` + 3D Matrix +
100% JIT-Free Rust AI Agents):
  1. 3D Matrix Override Unit & Integration Checks across all 15 canonical lanes
     (`(7.8, 7.9, 8.0) x (emulate/{emscripten,wasi,darwin}, translate/{darwin,linux})`),
     `make list-extra`, `audit_extra_ports.py`, `obsd-cargo target-info`, and
     JIT-free symbol audit (`0` `wasmtime`/`cranelift`/`v8`/`deno`/`luajit`/`pcre2_jit`
     symbols in `goose.o`, `forge.o`, `aichat.o`).
  2. `extra/devel/goose` (`goose-1.60.2`): CLI, repeated `execve` (`MALLOC_OPTIONS=JJ`),
     `goose info --check`, multi-turn `developer` agent (`write` + `edit` + `shell`),
     JIT-free `code-mode` (`boa_engine` JS tool orchestration), and SQLite `sessions.db`.
  3. `extra/devel/forgecode` (`forgecode-2.14.0`): `forge` & `forgecode` CLI + zsh
     shell integration, repeated `execve` (`MALLOC_OPTIONS=JJ`), multi-turn coding
     agent (`read` + `fs_search` + `write` + `patch` + `shell`), and SQLite `.forge.db`.
  4. `extra/misc/aichat` (`aichat-0.30.0`): CLI, repeated `execve` (`MALLOC_OPTIONS=JJ`),
     SSE chat, `-c` code extraction, `-e` shell assistant, `--session`, `--rag`
     (`hnsw_rs` vector index + `bm25` query), function-calling & `--agent`,
     80x24 `openpty()` `--repl`, and in-guest `--serve` (`/v1/chat/completions` +
     `/playground` + `/arena`).
  5. Live in-guest `llama-server` (`/tmp/tiny.gguf`) integration: verifies
     `aichat`, `goose`, and `forge` talking live over loopback TCP to in-guest
     `llama-server` inside WASM64 OpenBSD!

Runnable standalone via:
  python3 -I tests/wave5_extra_ai_agents.py --openbsd-version 8.0
  python3 -I tests/wave5_extra_ai_agents.py --openbsd-version 7.9
  python3 -I tests/wave5_extra_ai_agents.py --openbsd-version 7.8
  python3 -I tests/wave5_extra_ai_agents.py --openbsd-version all
"""
from __future__ import annotations

import argparse
import collections
import gzip
import hashlib
import http.server
import importlib.util
import json
import math
import os
import pathlib
import re
import socket
import socketserver
import struct
import subprocess
import sys
import tempfile
import threading
import traceback
from typing import Any, Dict, List, Set, Tuple

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(REPO_ROOT / "tools") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "tools"))

import build_ports as bp  # type: ignore

EXPECTED_TOTAL_PORTS: Dict[str, int] = {
    "7.8": 66,
    "7.9": 67,
    "8.0": 80,
}

EXTRA_PORT_SPECS: Dict[str, Dict[str, Any]] = {
    "devel/forgecode": {
        "pkgname": "forgecode-2.14.0",
        "sym": "forge",
        "obj": "applets/forge.o",
        "paths": ["/usr/local/bin/forge", "/usr/local/bin/forgecode"],
        "svfs_files": [
            "/usr/local/share/forgecode/forge.plugin.zsh",
            "/usr/local/share/forgecode/forge.setup.zsh",
            "/usr/local/share/forgecode/forge.theme.zsh",
        ],
    },
    "devel/goose": {
        "pkgname": "goose-1.60.2",
        "sym": "goose",
        "obj": "applets/goose.o",
        "paths": ["/usr/local/bin/goose"],
        "svfs_files": [],
    },
    "misc/aichat": {
        "pkgname": "aichat-0.30.0",
        "sym": "aichat",
        "obj": "applets/aichat.o",
        "paths": ["/usr/local/bin/aichat"],
        "svfs_files": [
            "/usr/local/share/bash-completion/completions/aichat",
            "/usr/local/share/fish/vendor_completions.d/aichat.fish",
            "/usr/local/share/zsh/site-functions/_aichat",
        ],
    },
}

VALID_VERSIONS = ("7.8", "7.9", "8.0")
VALID_MATRIX_CELLS: Tuple[Tuple[str, str], ...] = (
    ("emulate", "emscripten"),
    ("emulate", "wasi"),
    ("emulate", "darwin"),
    ("translate", "darwin"),
    ("translate", "linux"),
)

FORBIDDEN_JIT_SYMBOL_RE = re.compile(
    r"(wasmtime_|cranelift_|_ZN2v8|v8_isolate|rusty_v8|deno_core|luaJIT_|lj_BC_|pcre2_jit_compile|pcre2_jit_match)"
)

EMBED_KEYWORDS = [
    ("svnp", 0),
    ("0x53564e50", 1),
    ("18080", 2),
    ("protocol", 3),
    ("magic", 4),
    ("checksum", 5),
    ("compute_checksum", 6),
    ("0xcafe_8080", 7),
    ("rust", 8),
    ("pizza", 9),
    ("tomato", 10),
    ("mozzarella", 11),
]


def _embed_text(text: str) -> List[float]:
    low = text.lower()
    vec = [0.01] * 16
    for kw, idx in EMBED_KEYWORDS:
        if kw in low:
            vec[idx] += 3.0
    digest = hashlib.sha256(low.encode("utf-8")).digest()
    for i in range(12, 16):
        vec[i] += (digest[i] / 255.0) * 0.2
    norm = math.sqrt(sum(x * x for x in vec)) or 1.0
    return [round(x / norm, 6) for x in vec]


def _flatten_content(c: Any) -> str:
    if isinstance(c, str):
        return c
    if isinstance(c, list):
        parts = []
        for item in c:
            if isinstance(item, dict):
                if isinstance(item.get("text"), str):
                    parts.append(item["text"])
                elif "content" in item:
                    parts.append(_flatten_content(item["content"]))
        return "\n".join(parts)
    return str(c or "")


def _pick_goose_tool(tool_names: List[str], base: str) -> str:
    if base in tool_names:
        return base
    pref = f"developer__{base}"
    if pref in tool_names:
        return pref
    if base in ("list_functions", "execute_javascript"):
        cpref = f"code_execution__{base}"
        if cpref in tool_names:
            return cpref
    raise KeyError(f"goose tool {base!r} not in {tool_names}")


def _pick_forge_tool(tool_names: List[str], candidates: List[str]) -> str:
    for c in candidates:
        if c in tool_names:
            return c
    for c in candidates:
        for tn in tool_names:
            if tn.lower() == c.lower():
                return tn
    raise KeyError(f"forge tool {candidates!r} not in {tool_names}")


class _ReusableHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def shutdown_request(self, request: Any) -> None:
        try:
            request.shutdown(socket.SHUT_WR)
            request.settimeout(0.2)
            while request.recv(512):
                pass
        except OSError:
            pass
        self.close_request(request)


class Wave5MockOpenAIServer:
    """Host 127.0.0.1 OpenAI + Embeddings HTTP/1.1 & SSE server reached from the
    WASM64 OpenBSD guest over SVNP/1 (`http://127.0.0.1:<port>`)."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.stats: Dict[str, int] = {
            "goose_dev_turns": 0,
            "goose_cm_turns": 0,
            "forge_turns": 0,
            "aichat_chat": 0,
            "aichat_embed": 0,
            "aichat_tools": 0,
            "aichat_rag": 0,
            "aichat_session_recall": 0,
        }
        parent = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, fmt: str, *args: object) -> None:
                return

            def _send_json(self, status: int, obj: Dict[str, Any]) -> None:
                raw = json.dumps(obj).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(raw)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(raw)
                self.wfile.flush()

            def _send_chat_reply(self, is_stream: bool, model: str, content: Any = None, tool_call: Any = None) -> None:
                if not is_stream:
                    msg: Dict[str, Any] = {"role": "assistant"}
                    finish = "stop"
                    if tool_call is not None:
                        call_id, fn_name, fn_args = tool_call
                        arg_str = fn_args if isinstance(fn_args, str) else json.dumps(fn_args)
                        msg["content"] = None
                        msg["tool_calls"] = [
                            {
                                "id": call_id,
                                "type": "function",
                                "function": {"name": fn_name, "arguments": arg_str},
                            }
                        ]
                        finish = "tool_calls"
                    else:
                        msg["content"] = content if content is not None else "OK"
                    self._send_json(
                        200,
                        {
                            "id": "chatcmpl-wave5",
                            "object": "chat.completion",
                            "created": 1730000000,
                            "model": model,
                            "choices": [{"index": 0, "message": msg, "finish_reason": finish}],
                            "usage": {"prompt_tokens": 32, "completion_tokens": 16, "total_tokens": 48},
                        },
                    )
                    return

                frames: List[Dict[str, Any]] = []
                if tool_call is not None:
                    call_id, fn_name, fn_args = tool_call
                    arg_str = fn_args if isinstance(fn_args, str) else json.dumps(fn_args)
                    mid = max(1, len(arg_str) // 2)
                    frames.append(
                        {
                            "id": "chatcmpl-wave5",
                            "object": "chat.completion.chunk",
                            "created": 1730000000,
                            "model": model,
                            "choices": [
                                {
                                    "index": 0,
                                    "delta": {
                                        "role": "assistant",
                                        "tool_calls": [
                                            {
                                                "index": 0,
                                                "id": call_id,
                                                "type": "function",
                                                "function": {"name": fn_name, "arguments": arg_str[:mid]},
                                            }
                                        ],
                                    },
                                    "finish_reason": None,
                                }
                            ],
                        }
                    )
                    if arg_str[mid:]:
                        frames.append(
                            {
                                "id": "chatcmpl-wave5",
                                "object": "chat.completion.chunk",
                                "created": 1730000000,
                                "model": model,
                                "choices": [
                                    {
                                        "index": 0,
                                        "delta": {
                                            "tool_calls": [
                                                {
                                                    "index": 0,
                                                    "function": {"arguments": arg_str[mid:]},
                                                }
                                            ]
                                        },
                                        "finish_reason": None,
                                    }
                                ],
                            }
                        )
                    finish_reason = "tool_calls"
                else:
                    txt = str(content if content is not None else "OK")
                    mid = max(1, len(txt) // 2)
                    frames.append(
                        {
                            "id": "chatcmpl-wave5",
                            "object": "chat.completion.chunk",
                            "created": 1730000000,
                            "model": model,
                            "choices": [{"index": 0, "delta": {"role": "assistant", "content": txt[:mid]}, "finish_reason": None}],
                        }
                    )
                    if txt[mid:]:
                        frames.append(
                            {
                                "id": "chatcmpl-wave5",
                                "object": "chat.completion.chunk",
                                "created": 1730000000,
                                "model": model,
                                "choices": [{"index": 0, "delta": {"content": txt[mid:]}, "finish_reason": None}],
                            }
                        )
                    finish_reason = "stop"

                frames.append(
                    {
                        "id": "chatcmpl-wave5",
                        "object": "chat.completion.chunk",
                        "created": 1730000000,
                        "model": model,
                        "choices": [{"index": 0, "delta": {}, "finish_reason": finish_reason}],
                        "usage": {"prompt_tokens": 32, "completion_tokens": 16, "total_tokens": 48},
                    }
                )
                raw = ("".join(f"data: {json.dumps(f)}\n\n" for f in frames) + "data: [DONE]\n\n").encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream; charset=utf-8")
                self.send_header("Cache-Control", "no-cache")
                self.send_header("Content-Length", str(len(raw)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(raw)
                self.wfile.flush()

            def do_GET(self) -> None:
                if self.path == "/stats":
                    with parent.lock:
                        self._send_json(200, dict(parent.stats))
                    return
                if self.path.startswith("/v1/models") or self.path.startswith("/models"):
                    self._send_json(
                        200,
                        {
                            "object": "list",
                            "data": [
                                {
                                    "id": "gpt-4o",
                                    "name": "GPT-4o Mock",
                                    "object": "model",
                                    "context_length": 128000,
                                    "n_ctx": 128000,
                                    "tools_supported": True,
                                },
                                {
                                    "id": "gpt-mock",
                                    "name": "GPT Mock",
                                    "object": "model",
                                    "context_length": 128000,
                                    "tools_supported": True,
                                },
                            ],
                        },
                    )
                    return
                self._send_json(200, {"ok": True})

            def do_POST(self) -> None:
                try:
                    self._handle_post()
                except Exception as exc:
                    traceback.print_exc()
                    sys.stderr.flush()
                    self._send_json(400, {"error": {"message": str(exc), "type": "invalid_request_error"}})

            def _handle_post(self) -> None:
                length = int(self.headers.get("Content-Length", "0"))
                payload = json.loads(self.rfile.read(length).decode("utf-8"))
                if self.path.endswith("/embeddings"):
                    inp = payload.get("input", [])
                    if isinstance(inp, str):
                        inp = [inp]
                    data = [
                        {"object": "embedding", "index": idx, "embedding": _embed_text(str(txt))}
                        for idx, txt in enumerate(inp)
                    ]
                    with parent.lock:
                        parent.stats["aichat_embed"] += 1
                    self._send_json(
                        200,
                        {
                            "object": "list",
                            "data": data,
                            "model": payload.get("model", "embed-1"),
                            "usage": {"prompt_tokens": 12, "total_tokens": 12},
                        },
                    )
                    return

                is_stream = bool(payload.get("stream", False))
                model = str(payload.get("model", "gpt-4o"))
                messages = payload.get("messages", [])
                tools = payload.get("tools") or []
                tool_names = [t.get("function", {}).get("name", "") for t in tools if isinstance(t, dict)]
                all_text = "\n".join(_flatten_content(m.get("content", "")) for m in messages if isinstance(m, dict))
                user_text = "\n".join(
                    _flatten_content(m.get("content", ""))
                    for m in messages
                    if isinstance(m, dict) and m.get("role") == "user"
                )
                last_user = ""
                for m in reversed(messages):
                    if isinstance(m, dict) and m.get("role") == "user":
                        last_user = _flatten_content(m.get("content", ""))
                        break
                tool_outs = [
                    _flatten_content(m.get("content", ""))
                    for m in messages
                    if isinstance(m, dict) and m.get("role") == "tool"
                ]

                # 1. Goose Developer multi-turn task
                if "GOOSE_DEV_AGENT_TASK" in user_text:
                    with parent.lock:
                        parent.stats["goose_dev_turns"] += 1
                    n = len(tool_outs)
                    if n == 0:
                        self._send_chat_reply(
                            is_stream,
                            model,
                            tool_call=(
                                "call_gdev_1",
                                _pick_goose_tool(tool_names, "write"),
                                {
                                    "path": "/tmp/goose_ws/calc.py",
                                    "content": "BASE = 19\nprint(f'DEV_CALC={BASE + 2}')\n",
                                },
                            ),
                        )
                    elif n == 1:
                        self._send_chat_reply(
                            is_stream,
                            model,
                            tool_call=(
                                "call_gdev_2",
                                _pick_goose_tool(tool_names, "edit"),
                                {
                                    "path": "/tmp/goose_ws/calc.py",
                                    "before": "BASE = 19",
                                    "after": "BASE = 40",
                                },
                            ),
                        )
                    elif n == 2:
                        self._send_chat_reply(
                            is_stream,
                            model,
                            tool_call=(
                                "call_gdev_3",
                                _pick_goose_tool(tool_names, "shell"),
                                {
                                    "command": "cat /tmp/goose_ws/calc.py && /usr/local/bin/python3 /tmp/goose_ws/calc.py",
                                },
                            ),
                        )
                    else:
                        assert "DEV_CALC=42" in tool_outs[-1], f"unexpected goose shell output: {tool_outs[-1]!r}"
                        self._send_chat_reply(is_stream, model, content="GOOSE_DEV_DONE: DEV_CALC=42")
                    return

                # 2. Goose Code-Mode (boa_engine JS) multi-turn task
                if "GOOSE_CODEMODE_AGENT_TASK" in user_text:
                    with parent.lock:
                        parent.stats["goose_cm_turns"] += 1
                    n = len(tool_outs)
                    if n == 0:
                        self._send_chat_reply(
                            is_stream,
                            model,
                            tool_call=("call_gcm_1", _pick_goose_tool(tool_names, "list_functions"), {}),
                        )
                    elif n == 1:
                        write_nm = _pick_goose_tool(tool_names, "write")
                        edit_nm = _pick_goose_tool(tool_names, "edit")
                        shell_nm = _pick_goose_tool(tool_names, "shell")
                        js_code = "\n".join(
                            [
                                "async function run() {",
                                "  const values = [11, 22, 33, 3];",
                                "  const total = values.reduce((acc, x) => acc + x, 0);",
                                f"  await tools.call({json.dumps(write_nm)}, {{",
                                '    path: "/tmp/goose_ws/boa_result.txt",',
                                '    content: "boa_total=" + total + "\\nmode=initial\\n"',
                                "  });",
                                f"  await tools.call({json.dumps(edit_nm)}, {{",
                                '    path: "/tmp/goose_ws/boa_result.txt",',
                                '    before: "mode=initial",',
                                '    after: "mode=boa_verified"',
                                "  });",
                                f"  const sh = await tools.call({json.dumps(shell_nm)}, {{",
                                '    command: "cat /tmp/goose_ws/boa_result.txt"',
                                "  });",
                                '  console.log("BOA_CONSOLE_OK:" + total);',
                                "  return { total, sh };",
                                "}",
                            ]
                        )
                        self._send_chat_reply(
                            is_stream,
                            model,
                            tool_call=("call_gcm_2", _pick_goose_tool(tool_names, "execute_javascript"), {"code": js_code}),
                        )
                    else:
                        assert "BOA_CONSOLE_OK:69" in tool_outs[-1] and "mode=boa_verified" in tool_outs[-1], (
                            f"unexpected boa output: {tool_outs[-1]!r}"
                        )
                        self._send_chat_reply(is_stream, model, content="GOOSE_CODEMODE_DONE: BOA_SUM=69")
                    return

                # 3. ForgeCode 6-turn coding agent task (read -> fs_search -> write -> patch -> shell -> done)
                if "FORGE_AGENT_TASK" in all_text:
                    if not tool_names:
                        self._send_chat_reply(is_stream, model, content="Audit and patch calc.py")
                        return
                    with parent.lock:
                        parent.stats["forge_turns"] += 1
                    n = len(tool_outs)
                    if n == 0:
                        self._send_chat_reply(
                            is_stream,
                            model,
                            tool_call=(
                                "call_fg_1",
                                _pick_forge_tool(tool_names, ["read", "fs_read"]),
                                {"file_path": "/tmp/forge_demo/calc.py"},
                            ),
                        )
                    elif n == 1:
                        self._send_chat_reply(
                            is_stream,
                            model,
                            tool_call=(
                                "call_fg_2",
                                _pick_forge_tool(tool_names, ["fs_search"]),
                                {
                                    "pattern": "MARKER_FORGE_BUG",
                                    "path": "/tmp/forge_demo",
                                    "output_mode": "content",
                                },
                            ),
                        )
                    elif n == 2:
                        # New file creation omits `overwrite: true` so ForgeCode creates `/tmp/forge_demo/notes.txt` directly
                        self._send_chat_reply(
                            is_stream,
                            model,
                            tool_call=(
                                "call_fg_3",
                                _pick_forge_tool(tool_names, ["write", "fs_write"]),
                                {
                                    "file_path": "/tmp/forge_demo/notes.txt",
                                    "content": "ForgeCode audited calc.py on OpenBSD WASM64\n",
                                },
                            ),
                        )
                    elif n == 3:
                        self._send_chat_reply(
                            is_stream,
                            model,
                            tool_call=(
                                "call_fg_4",
                                _pick_forge_tool(tool_names, ["patch", "fs_patch"]),
                                {
                                    "file_path": "/tmp/forge_demo/calc.py",
                                    "old_string": "return a - b",
                                    "new_string": "return a + b",
                                    "replace_all": False,
                                },
                            ),
                        )
                    elif n == 4:
                        self._send_chat_reply(
                            is_stream,
                            model,
                            tool_call=(
                                "call_fg_5",
                                _pick_forge_tool(tool_names, ["shell"]),
                                {
                                    "command": "cat /tmp/forge_demo/notes.txt && /usr/local/bin/python3 /tmp/forge_demo/calc.py",
                                    "cwd": "/tmp/forge_demo",
                                    "description": "Verify notes.txt and patched calc.py result",
                                },
                            ),
                        )
                    else:
                        assert "CALC_RESULT=42" in tool_outs[-1] and "ForgeCode audited calc.py" in tool_outs[-1], (
                            f"unexpected forge shell output: {tool_outs[-1]!r}"
                        )
                        self._send_chat_reply(is_stream, model, content="FORGECODE_AGENT_MISSION_COMPLETE_42")
                    return

                # 4. AIChat routes (tools/agents, RAG, code, shell assistant, session, REPL, --serve)
                with parent.lock:
                    parent.stats["aichat_chat"] += 1

                if tool_outs and (
                    "obsd_calc_tool" in all_text
                    or "deploy_stamp" in all_text
                    or "sonvori-v0.30.0" in tool_outs[-1]
                    or '"sum":42' in tool_outs[-1]
                ):
                    with parent.lock:
                        parent.stats["aichat_tools"] += 1
                    self._send_chat_reply(is_stream, model, content=f"AGENT_TOOL_VERIFIED: {tool_outs[-1]}")
                    return

                if tool_names and ("obsd_calc_tool" in tool_names or "deploy_stamp" in tool_names):
                    if "deploy_stamp" in tool_names:
                        self._send_chat_reply(
                            is_stream,
                            model,
                            tool_call=("call_ag_1", "deploy_stamp", {"tag": "sonvori-v0.30.0"}),
                        )
                    else:
                        self._send_chat_reply(
                            is_stream,
                            model,
                            tool_call=("call_fn_1", "obsd_calc_tool", {"a": 19, "b": 23}),
                        )
                    return

                if "<context>" in last_user and "</context>" in last_user:
                    has_svnp = "0x53564E50" in last_user
                    has_cksum = "0xCAFE_8080" in last_user
                    with parent.lock:
                        parent.stats["aichat_rag"] += 1
                    self._send_chat_reply(is_stream, model, content=f"RAG_GROUNDED_OK svnp={has_svnp} cksum={has_cksum}")
                    return

                if "CODE_MODE_PROMPT" in last_user:
                    self._send_chat_reply(is_stream, model, content="Here is the snippet:\n```sh\necho CODE_EXTRACTED_42\n```\n")
                    return
                if "SHELL_EXEC_PROMPT" in last_user:
                    self._send_chat_reply(is_stream, model, content="echo SHELL_ASSISTANT_UNAME_$(uname -s)")
                    return
                if "What was the codeword?" in last_user and "ORBIT-77" in all_text:
                    with parent.lock:
                        parent.stats["aichat_session_recall"] += 1
                    self._send_chat_reply(is_stream, model, content="SESSION_RECALL_OK: ORBIT-77")
                    return
                if "Remember codeword ORBIT-77" in last_user:
                    self._send_chat_reply(is_stream, model, content="ACK_STORED_ORBIT-77")
                    return
                if "Hello from interactive PTY REPL" in last_user:
                    self._send_chat_reply(is_stream, model, content="PTY_REPL_STREAM_OK")
                    return
                if "SERVE_PROXY_PING" in last_user:
                    self._send_chat_reply(is_stream, model, content="SERVE_PROXY_COMPLETION_OK")
                    return

                self._send_chat_reply(is_stream, model, content="HELLO_STREAM_FROM_OBSD_MOCK")

        self._srv = _ReusableHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self._srv.server_address[1]
        self._thread = threading.Thread(target=self._srv.serve_forever, daemon=True)
        self._thread.start()

    def close(self) -> None:
        try:
            self._srv.shutdown()
            self._srv.server_close()
        except Exception:
            pass


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


def _load_module(name: str, path: pathlib.Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def parse_svfs_paths(svfs_gz: pathlib.Path) -> Set[str]:
    raw = gzip.decompress(svfs_gz.read_bytes())
    hdr = struct.Struct("<IHHI")
    ent = struct.Struct("<BBHIIIHHI")
    magic, ver, _flags, count = hdr.unpack_from(raw, 0)
    assert magic == 0x53564653 and ver == 1, f"bad SVFS header in {svfs_gz}"
    paths: Set[str] = set()
    off = hdr.size
    for _ in range(count):
        _et, _r0, _perm, p_off, p_len, _d_off, _r1, _r2, _d_len = ent.unpack_from(raw, off)
        off += ent.size
        rel = raw[p_off : p_off + p_len].decode("utf-8")
        paths.add("/" + rel)
    return paths


def verify_3d_matrix_unit_and_integration() -> None:
    """Verify 6-layer 3D matrix override precedence, eligibility gates, `obsd-cargo target-info`,
    and all 15 `(OPENBSD_VERSION x COMPAT_BACKEND x COMPAT_PAL)` canonical matrix lanes."""
    with tempfile.TemporaryDirectory(prefix="wave5-matrix-unit-") as td:
        tp = pathlib.Path(td)
        pdir = tp / "devel/synth"
        pdir.mkdir(parents=True, exist_ok=True)
        (pdir / "port.toml").write_text(
            """
port = "devel/synth"
build_style = "cargo"
only_versions = ["7.9", "8.0"]
not_for_pals = ["wasi"]
not_for_targets = ["translate/linux"]
cflags = ["-DBASE=1"]
env = { L1 = "base", OVER = "base" }

[versions."8.0"]
cflags_append = ["-DVER80=1"]
env = { L2 = "ver80", OVER = "ver80" }

[backends.emulate]
cflags_append = ["-DEMULATE=1"]
env = { L3 = "emulate", OVER = "emulate" }
[[backends.emulate.applets]]
sym = "synth"
binary = "/usr/local/bin/synth"

[backends.translate]
applets = []
env = { L3 = "translate", OVER = "translate" }

[pals.darwin]
cflags_append = ["-DDARWIN=1"]
env = { L4 = "darwin", OVER = "darwin" }

[targets."emulate/darwin"]
cflags_append = ["-DEMU_DARWIN=1"]
env = { L5 = "emulate_darwin", OVER = "emulate_darwin" }

[matrix."8.0/emulate/darwin"]
cflags_append = ["-DMATRIX_80_EMU_DARWIN=1"]
env = { L6 = "8.0_emulate_darwin", OVER = "matrix_top" }
""".strip()
            + "\n",
            encoding="utf-8",
        )

        rec_top = bp.load_recipe(pdir, "8.0", ports_root=tp, backend="emulate", pal="darwin", section="extra")
        ok_top, _ = bp.recipe_supports_lane(rec_top, "8.0", backend="emulate", pal="darwin")
        assert ok_top
        assert rec_top["cflags"] == [
            "-DBASE=1",
            "-DVER80=1",
            "-DEMULATE=1",
            "-DDARWIN=1",
            "-DEMU_DARWIN=1",
            "-DMATRIX_80_EMU_DARWIN=1",
        ]
        assert rec_top["env"] == {
            "L1": "base",
            "L2": "ver80",
            "L3": "emulate",
            "L4": "darwin",
            "L5": "emulate_darwin",
            "L6": "8.0_emulate_darwin",
            "OVER": "matrix_top",
        }
        assert len(rec_top["applets"]) == 1 and rec_top["applets"][0]["sym"] == "synth"

        rec_tr = bp.load_recipe(pdir, "8.0", ports_root=tp, backend="translate", pal="darwin", section="extra")
        assert bp.recipe_supports_lane(rec_tr, "8.0", backend="translate", pal="darwin")[0]
        assert rec_tr["applets"] == [] and rec_tr["env"]["OVER"] == "darwin"

        rec_78 = bp.load_recipe(pdir, "7.8", ports_root=tp, backend="emulate", pal="emscripten", section="extra")
        assert not bp.recipe_supports_lane(rec_78, "7.8", backend="emulate", pal="emscripten")[0]

        rec_wasi = bp.load_recipe(pdir, "8.0", ports_root=tp, backend="emulate", pal="wasi", section="extra")
        assert not bp.recipe_supports_lane(rec_wasi, "8.0", backend="emulate", pal="wasi")[0]

        rec_tlin = bp.load_recipe(pdir, "8.0", ports_root=tp, backend="translate", pal="linux", section="extra")
        assert not bp.recipe_supports_lane(rec_tlin, "8.0", backend="translate", pal="linux")[0]

    obsd_cargo = REPO_ROOT / "sdk/bin/obsd-cargo"
    lane_count = 0
    for ver in VALID_VERSIONS:
        for backend, pal in VALID_MATRIX_CELLS:
            lane_count += 1
            for extra_port in ("devel/forgecode", "devel/goose", "misc/aichat"):
                r_loaded = bp.load_recipe(
                    REPO_ROOT / "extra" / extra_port,
                    ver,
                    ports_root=REPO_ROOT / "extra",
                    backend=backend,
                    pal=pal,
                    section="extra",
                )
                if backend == "emulate":
                    assert len(r_loaded["applets"]) == 1, f"[{ver} {backend}/{pal}] expected 1 applet for {extra_port}"
                else:
                    assert r_loaded["applets"] == [], f"[{ver} {backend}/{pal}] expected 0 applets on translate for {extra_port}"

            extra_recs = bp.discover_recipes(
                ver,
                backend=backend,
                pal=pal,
                section="extra",
                include_cross_section_deps=False,
            )
            all_recs = bp.discover_recipes(ver, backend=backend, pal=pal, section="all")
            if (backend, pal) == ("emulate", "emscripten"):
                found_ports = [r["port"] for r in extra_recs]
                assert found_ports == ["devel/forgecode", "devel/goose", "misc/aichat"], (
                    f"[{ver} {backend}/{pal}] unexpected extra recipes: {found_ports}"
                )
                assert len(all_recs) == EXPECTED_TOTAL_PORTS[ver], (
                    f"[{ver} {backend}/{pal}] expected {EXPECTED_TOTAL_PORTS[ver]} total recipes, got {len(all_recs)}"
                )
            elif pal == "darwin":
                assert len(all_recs) == 53, f"[{ver} {backend}/darwin] expected 53 Darwin ports, got {len(all_recs)}"

            tinfo = json.loads(
                subprocess.check_output(
                    [
                        str(obsd_cargo),
                        "target-info",
                        "--openbsd-version",
                        ver,
                        "--backend",
                        backend,
                        "--pal",
                        pal,
                    ],
                    text=True,
                )
            )
            assert tinfo["openbsd_version"] == ver and tinfo["backend"] == backend and tinfo["pal"] == pal
            if (backend, pal) == ("emulate", "emscripten"):
                assert tinfo["target_name"] == "wasm64-unknown-openbsd"
            elif (backend, pal) == ("emulate", "darwin"):
                assert tinfo["target_name"] == "aarch64-apple-ios-sim"
            elif (backend, pal) == ("translate", "darwin"):
                assert tinfo["target_name"] == "aarch64-apple-darwin"

    assert lane_count == 15
    subprocess.run([sys.executable, "-I", str(REPO_ROOT / "tools/audit/audit_extra_ports.py")], check=True)

    # Verify `.data.rel.ro` / `.data.rel.ro.*` -> `.rodata.rel.ro` / `.rodata.rel.ro.*` promotion
    # keeps RELRO vtables & const pointer tables out of per-process mutable `obsd_guest_data`
    obsd_root = bp.resolve_obsd_root_arg("")
    emcc = obsd_root / "deps/emsdk/upstream/emscripten/emcc"
    wasm_ld = obsd_root / "deps/emsdk/upstream/bin/wasm-ld"
    wasm_obj_tool = obsd_root / "tools/build/personalities/openbsd/backends/emulate/wasm_object_tool.py"
    spec_mod = importlib.util.spec_from_file_location("obsd_rust", REPO_ROOT / "sdk/rust/obsd_rust.py")
    assert spec_mod and spec_mod.loader
    obsd_rust_mod = importlib.util.module_from_spec(spec_mod)
    spec_mod.loader.exec_module(obsd_rust_mod)

    with tempfile.TemporaryDirectory(prefix="wave5-relro-check-") as td:
        tp = pathlib.Path(td)
        relro_c = tp / "relro_vtable.c"
        relro_c.write_text(
            "int fn_a(void) { return 40; }\n"
            "int fn_b(void) { return 2; }\n"
            "int (*const VTABLE[2])(void) = { fn_a, fn_b };\n"
            "__attribute__((section(\".data.rel.ro\"))) int (*const SINGLE_FN)(void) = fn_a;\n"
            "int mutable_val = 7;\n"
            "int main(void) { return VTABLE[0]() + VTABLE[1]() + SINGLE_FN() + mutable_val; }\n",
            encoding="utf-8",
        )
        raw_o = tp / "relro.o"
        win_o = tp / "relro_win.o"
        linked_wasm = tp / "relro_out.wasm"
        subprocess.run([str(emcc), "-m64", "-O2", "-fPIC", "-c", str(relro_c), "-o", str(raw_o)], check=True)
        rew_cnt = obsd_rust_mod.rewrite_wasm_relro_segments(raw_o)
        assert rew_cnt == 2, f"expected 2 .data.rel.ro* segments rewritten, got {rew_cnt}"
        subprocess.run(
            [
                sys.executable,
                "-I",
                str(wasm_obj_tool),
                "window-guest",
                "--window-section",
                "obsd_guest_data",
                "--keep-global",
                "main",
                "-i",
                str(raw_o),
                "-o",
                str(win_o),
            ],
            check=True,
        )
        subprocess.run(
            [
                str(wasm_ld),
                "-m",
                "wasm64",
                "--fatal-warnings",
                "--no-entry",
                "--export=main",
                "--experimental-pic",
                str(win_o),
                "-o",
                str(linked_wasm),
            ],
            check=True,
        )

    print("[WAVE5-MATRIX-OK] 6-layer override unit checks, .rodata.rel.ro promotion, audit_extra_ports.py, and all 15 3D matrix lanes verified")


def verify_host_packaging_and_jit_free(
    ver: str,
    obsd_root: pathlib.Path,
    lane_dir: pathlib.Path,
    selected_ports: Set[str],
) -> None:
    list_out = subprocess.check_output(
        ["make", "-C", str(REPO_ROOT), "list-extra", f"OPENBSD_VERSION={ver}"],
        text=True,
    )
    for port_id, spec in EXTRA_PORT_SPECS.items():
        if port_id not in selected_ports:
            continue
        assert port_id in list_out and spec["pkgname"] in list_out and "built" in list_out, (
            f"[{ver}] `make list-extra` missing built entry for {port_id}:\n{list_out}"
        )

    built_json = lane_dir / "built-ports.json"
    assert built_json.is_file(), f"[{ver}] missing {built_json}; run `make package OPENBSD_VERSION={ver}` first"
    records = json.loads(built_json.read_text(encoding="utf-8"))
    by_port = {r["port"]: r for r in records}

    if len(selected_ports) == 3:
        assert len(records) == EXPECTED_TOTAL_PORTS[ver], (
            f"[{ver}] expected {EXPECTED_TOTAL_PORTS[ver]} built ports in {built_json}, got {len(records)}"
        )

    tsv_path = lane_dir / "ports-applets.tsv"
    assert tsv_path.is_file(), f"[{ver}] missing {tsv_path}"
    by_gpath: Dict[str, Tuple[str, str, pathlib.Path]] = {}
    for raw in tsv_path.read_text(encoding="utf-8").splitlines():
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        sym, gpath, entry_sym, obj_rel = s.split("\t")[:4]
        by_gpath[gpath] = (sym, entry_sym, (lane_dir / obj_rel).resolve())

    svfs_paths = parse_svfs_paths(lane_dir / "ports.svfs.gz")
    llvm_nm = obsd_root / "deps/emsdk/upstream/bin/llvm-nm"
    assert llvm_nm.is_file(), f"missing llvm-nm at {llvm_nm}"

    sizes_summary: List[str] = []
    for port_id in sorted(selected_ports):
        spec = EXTRA_PORT_SPECS[port_id]
        assert port_id in by_port, f"[{ver}] {port_id} missing from built-ports.json"
        rec = by_port[port_id]
        assert rec.get("section") == "extra", f"[{ver}] {port_id} section != 'extra'"
        assert rec.get("pkgname") == spec["pkgname"], f"[{ver}] {port_id} unexpected pkgname {rec.get('pkgname')}"
        assert str(rec.get("comment") or "").strip(), f"[{ver}] {port_id} missing comment in built-ports.json"
        assert str(rec.get("descr") or "").strip(), f"[{ver}] {port_id} missing descr in built-ports.json"

        pkg_tgz = lane_dir / "packages" / f"{spec['pkgname']}.tgz"
        assert pkg_tgz.is_file() and pkg_tgz.stat().st_size > 0, f"[{ver}] missing package archive {pkg_tgz}"

        obj_path = (lane_dir / spec["obj"]).resolve()
        assert obj_path.is_file(), f"[{ver}] missing localized applet {obj_path}"

        for gp in spec["paths"]:
            assert gp in by_gpath, f"[{ver}] missing applet path {gp} in ports-applets.tsv"
            assert by_gpath[gp][0] == spec["sym"] and by_gpath[gp][2] == obj_path
            assert gp in svfs_paths, f"[{ver}] missing applet stub {gp} in ports.svfs.gz"

        for sf in spec["svfs_files"]:
            assert sf in svfs_paths, f"[{ver}] missing staged file {sf} in ports.svfs.gz"

        # Strict W^X / WASM64 / iOS JIT-free symbol audit via `llvm-nm`
        nm_out = subprocess.check_output(
            [str(llvm_nm), "-a", str(obj_path)],
            text=True,
            stderr=subprocess.DEVNULL,
        )
        expected_entry = f"obsd_applet_{spec['sym']}_main"
        assert expected_entry in nm_out, f"[{ver}] {obj_path.name} missing localized entry {expected_entry}"
        bad_hits = [ln.strip() for ln in nm_out.splitlines() if FORBIDDEN_JIT_SYMBOL_RE.search(ln)]
        assert not bad_hits, f"[{ver}] JIT symbol leak in {obj_path.name}: {bad_hits[:10]}"

        # Verify 0 unpromoted `.data.rel.ro*` segments in packaged WASM64 applet object
        emulate_tools = obsd_root / "tools/build/personalities/openbsd/backends/emulate"
        if str(emulate_tools) not in sys.path:
            sys.path.insert(0, str(emulate_tools))
        import wasm_object_tool as wot  # type: ignore

        raw_ap = obj_path.read_bytes()
        p_off = 8
        while p_off < len(raw_ap):
            s_id = raw_ap[p_off]
            s_len, b_off = wot.read_uleb(raw_ap, p_off + 1)
            s_end = b_off + s_len
            if s_id == 0:
                nl, np_off = wot.read_uleb(raw_ap, b_off)
                if raw_ap[np_off : np_off + nl] == b"linking":
                    _, sub_p = wot.read_uleb(raw_ap, np_off + nl)
                    while sub_p < s_end:
                        st_id = raw_ap[sub_p]
                        st_len, st_b = wot.read_uleb(raw_ap, sub_p + 1)
                        if st_id == wot.WASM_SEGMENT_INFO:
                            leaked_relro = [
                                sg["name"]
                                for sg in wot.parse_segments(raw_ap[st_b : st_b + st_len])
                                if sg["name"] == ".data.rel.ro" or sg["name"].startswith(".data.rel.ro.")
                            ]
                            assert not leaked_relro, f"[{ver}] {obj_path.name} leaked .data.rel.ro* segments: {leaked_relro[:5]}"
                        sub_p = st_b + st_len
            p_off = s_end

        sizes_summary.append(f"{obj_path.name}={obj_path.stat().st_size / (1024 * 1024):.1f}MiB")

    print(
        f"[WAVE5-HOST-OK] [{ver}] {len(records)} total ports packaged, "
        f"0 JIT symbols across ({', '.join(sizes_summary)})"
    )


GUEST_WAVE5_SCRIPT_TEMPLATE = r"""
set -eu

EXPECTED_REL="__OPENBSD_VERSION__"
MOCK_PORT="__MOCK_PORT__"
RUN_GOOSE="__RUN_GOOSE__"
RUN_FORGE="__RUN_FORGE__"
RUN_AICHAT="__RUN_AICHAT__"
RUN_LLAMA_LIVE="__RUN_LLAMA_LIVE__"

export PYTHONPYCACHEPREFIX=/tmp/.pycache-wave5
export TOKIO_WORKER_THREADS=2

fail() {
    echo "[WAVE5-FAIL] $*" >&2
    exit 1
}

pass() {
    printf '[WAVE5-PASS] %s: %s\n' "$1" "$2"
}

[ "$(uname -s)" = "OpenBSD" ] || fail "expected OpenBSD"
[ "$(uname -r)" = "$EXPECTED_REL" ] || fail "expected OpenBSD $EXPECTED_REL, got $(uname -r)"

cleanup_all() {
    if [ -n "${AICHAT_SERVE_PID:-}" ] && kill -0 "$AICHAT_SERVE_PID" 2>/dev/null; then
        kill -9 "$AICHAT_SERVE_PID" 2>/dev/null || true
    fi
    if [ -n "${LLAMA_SRV_PID:-}" ] && kill -0 "$LLAMA_SRV_PID" 2>/dev/null; then
        kill -15 "$LLAMA_SRV_PID" 2>/dev/null || true
        if [ -n "${LLAMA_PORT:-}" ]; then
            /usr/local/bin/curl -fsS --max-time 1 "http://127.0.0.1:${LLAMA_PORT}/health" >/dev/null 2>&1 || true
        fi
        sleep 0.2
        kill -9 "$LLAMA_SRV_PID" 2>/dev/null || true
    fi
}
trap cleanup_all EXIT

# ==============================================================================
# 2. Goose (`1.60.2`) Verification
# ==============================================================================
if [ "$RUN_GOOSE" = "1" ]; then
    export HOME=/tmp/goose_home
    export XDG_CONFIG_HOME=/tmp/goose_home/.config
    export XDG_DATA_HOME=/tmp/goose_home/.local/share
    export XDG_STATE_HOME=/tmp/goose_home/.local/state
    export GOOSE_TELEMETRY_OFF=1
    export GOOSE_OFFLINE_MODEL_CATALOG=1
    rm -rf /tmp/goose_home /tmp/goose_ws
    mkdir -p "$XDG_CONFIG_HOME/goose" "$XDG_DATA_HOME/goose" "$XDG_STATE_HOME/goose" /tmp/goose_ws

    cat > "$XDG_CONFIG_HOME/goose/config.yaml" <<'EOF'
GOOSE_TELEMETRY_ENABLED: false
GOOSE_MODE: auto
EOF

    v_goose="$(MALLOC_OPTIONS=JJ /usr/local/bin/goose --version)"
    case "$v_goose" in
        *1.60.2*) ;;
        *) fail "unexpected goose --version: $v_goose" ;;
    esac
    /usr/local/bin/goose --help | grep -q "session"
    /usr/local/bin/goose completion bash > /tmp/goose_comp.bash
    [ -s /tmp/goose_comp.bash ] || fail "empty goose completion bash"

    for iter in 1 2 3 4; do
        out_gi="$(MALLOC_OPTIONS=JJ /usr/local/bin/goose info)"
        case "$out_gi" in
            *1.60.2*) ;;
            *) fail "goose repeated execve iter $iter failed: $out_gi" ;;
        esac
    done

    GOOSE_PROVIDER=openai OPENAI_HOST="http://127.0.0.1:${MOCK_PORT}" OPENAI_API_KEY=sk-test GOOSE_MODEL=gpt-4o GOOSE_MODE=auto \
        /usr/local/bin/goose info --check > /tmp/goose_check.txt
    grep -q "openai" /tmp/goose_check.txt
    grep -q "gpt-4o" /tmp/goose_check.txt

    (
        cd /tmp/goose_ws
        MALLOC_OPTIONS=JJ GOOSE_PROVIDER=openai OPENAI_HOST="http://127.0.0.1:${MOCK_PORT}" OPENAI_API_KEY=sk-test GOOSE_MODEL=gpt-4o GOOSE_MODE=auto \
            /usr/local/bin/goose run \
            --name obsd-dev-e2e \
            --with-builtin developer \
            --no-profile \
            --max-turns 8 \
            --text "GOOSE_DEV_AGENT_TASK: create, edit, and run /tmp/goose_ws/calc.py" </dev/null >/tmp/goose_dev.out
    )
    grep -q "GOOSE_DEV_DONE: DEV_CALC=42" /tmp/goose_dev.out || fail "goose developer run failed: $(cat /tmp/goose_dev.out)"
    grep -q "BASE = 40" /tmp/goose_ws/calc.py || fail "goose edit did not update BASE = 40"

    (
        cd /tmp/goose_ws
        MALLOC_OPTIONS=JJ GOOSE_PROVIDER=openai OPENAI_HOST="http://127.0.0.1:${MOCK_PORT}" OPENAI_API_KEY=sk-test GOOSE_MODEL=gpt-4o GOOSE_MODE=auto \
            /usr/local/bin/goose run \
            --name obsd-codemode-e2e \
            --with-builtin developer,code_execution \
            --no-profile \
            --max-turns 8 \
            --text "GOOSE_CODEMODE_AGENT_TASK: run boa_engine JS tool orchestration" </dev/null >/tmp/goose_cm.out
    )
    grep -q "GOOSE_CODEMODE_DONE: BOA_SUM=69" /tmp/goose_cm.out || fail "goose code-mode run failed: $(cat /tmp/goose_cm.out)"
    grep -q "mode=boa_verified" /tmp/goose_ws/boa_result.txt || fail "goose boa_result.txt missing mode=boa_verified"

    MALLOC_OPTIONS=JJ /usr/local/bin/goose session list > /tmp/goose_sessions.txt
    /usr/local/bin/python3 -I - <<'PY_GOOSE_DB'
import pathlib, sqlite3
dbs = list(pathlib.Path("/tmp/goose_home").rglob("*.db"))
assert dbs, "missing goose SQLite sessions.db"
con = sqlite3.connect(str(dbs[0]))
s_cnt = con.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
m_cnt = con.execute("SELECT COUNT(*) FROM messages").fetchone()[0]
con.close()
assert s_cnt >= 2 and m_cnt >= 8, f"unexpected goose db counts: sessions={s_cnt} messages={m_cnt}"
PY_GOOSE_DB
    pass "02_goose_e2e" "goose 1.60.2 CLI, 4x MALLOC_OPTIONS=JJ execve, developer agent, boa_engine code-mode, and SQLite sessions.db OK"
fi

# ==============================================================================
# 3. ForgeCode (`2.14.0`) Verification
# ==============================================================================
if [ "$RUN_FORGE" = "1" ]; then
    export HOME=/tmp/forge_home
    export FORGE_TRACKER=false
    rm -rf /tmp/forge_home /tmp/forge_cfg_a /tmp/forge_cfg_b /tmp/forge_cfg /tmp/forge_demo
    mkdir -p /tmp/forge_home /tmp/forge_cfg_a /tmp/forge_cfg_b /tmp/forge_cfg /tmp/forge_demo

    v_fg1="$(MALLOC_OPTIONS=JJ FORGE_CONFIG=/tmp/forge_cfg_a /usr/local/bin/forge --version)"
    v_fg2="$(MALLOC_OPTIONS=JJ FORGE_CONFIG=/tmp/forge_cfg_b /usr/local/bin/forgecode --version)"
    case "$v_fg1" in
        *"2.14.0"*) ;;
        *) fail "unexpected forge --version: $v_fg1" ;;
    esac
    [ "$v_fg1" = "$v_fg2" ] || fail "forge vs forgecode --version mismatch: '$v_fg1' vs '$v_fg2'"

    /usr/local/bin/forge --help | grep -qi "prompt"
    MALLOC_OPTIONS=JJ /usr/local/bin/forge zsh plugin > /tmp/forge_zsh_plugin.out
    MALLOC_OPTIONS=JJ /usr/local/bin/forge zsh theme > /tmp/forge_zsh_theme.out
    [ -s /tmp/forge_zsh_plugin.out ] && [ -s /tmp/forge_zsh_theme.out ] || fail "forge zsh plugin/theme empty"
    [ -s /usr/local/share/forgecode/forge.plugin.zsh ] || fail "missing /usr/local/share/forgecode/forge.plugin.zsh"
    [ -s /usr/local/share/forgecode/forge.setup.zsh ] || fail "missing /usr/local/share/forgecode/forge.setup.zsh"
    [ -s /usr/local/share/forgecode/forge.theme.zsh ] || fail "missing /usr/local/share/forgecode/forge.theme.zsh"

    cat > /tmp/forge_cfg_a/.forge.toml <<'EOF'
[session]
provider_id = "openai_compatible"
model_id = "gpt-4o"
[updates]
auto_update = false
frequency = "never"
EOF
    cat > /tmp/forge_cfg_b/.forge.toml <<'EOF'
[session]
provider_id = "openai_compatible"
model_id = "gpt-mock"
[updates]
auto_update = false
frequency = "never"
EOF

    MALLOC_OPTIONS=JJ FORGE_CONFIG=/tmp/forge_cfg_a OPENAI_URL="http://127.0.0.1:${MOCK_PORT}/v1" OPENAI_API_KEY=sk-a /usr/local/bin/forge list agent --porcelain > /tmp/fg_agents.txt
    MALLOC_OPTIONS=JJ FORGE_CONFIG=/tmp/forge_cfg_a OPENAI_URL="http://127.0.0.1:${MOCK_PORT}/v1" OPENAI_API_KEY=sk-a /usr/local/bin/forge list tool forge --porcelain > /tmp/fg_tools.txt
    MALLOC_OPTIONS=JJ FORGE_CONFIG=/tmp/forge_cfg_a OPENAI_URL="http://127.0.0.1:${MOCK_PORT}/v1" OPENAI_API_KEY=sk-a /usr/local/bin/forge list provider --porcelain > /tmp/fg_providers.txt
    [ -s /tmp/fg_agents.txt ] && [ -s /tmp/fg_tools.txt ] && [ -s /tmp/fg_providers.txt ] || fail "forge list --porcelain empty"

    # 4x consecutive execve alternating FORGE_CONFIG (verifies LazyLock BASE_PATH + obsd_guest_data banking reset!)
    for iter in 1 2; do
        info_a="$(MALLOC_OPTIONS=JJ FORGE_CONFIG=/tmp/forge_cfg_a OPENAI_URL="http://127.0.0.1:${MOCK_PORT}/v1" OPENAI_API_KEY=sk-a /usr/local/bin/forge info)"
        printf '%s\n' "$info_a" | grep -q "gpt-4o" || fail "forge_cfg_a LazyLock reset failed: $info_a"
        info_b="$(MALLOC_OPTIONS=JJ FORGE_CONFIG=/tmp/forge_cfg_b OPENAI_URL="http://127.0.0.1:${MOCK_PORT}/v1" OPENAI_API_KEY=sk-b /usr/local/bin/forgecode info)"
        printf '%s\n' "$info_b" | grep -q "gpt-mock" || fail "forge_cfg_b LazyLock reset failed: $info_b"
    done

    # 6-turn autonomous coding agent run (read -> fs_search -> write -> patch -> shell -> final)
    cp /tmp/forge_cfg_a/.forge.toml /tmp/forge_cfg/.forge.toml
    cat > /tmp/forge_demo/calc.py <<'EOF'
def compute(a, b):
    # MARKER_FORGE_BUG
    return a - b

if __name__ == "__main__":
    print(f"CALC_RESULT={compute(40, 2)}")
EOF

    MALLOC_OPTIONS=JJ FORGE_CONFIG=/tmp/forge_cfg OPENAI_URL="http://127.0.0.1:${MOCK_PORT}/v1" OPENAI_API_KEY="sk-forge-test" \
        /usr/local/bin/forge -C /tmp/forge_demo -p "FORGE_AGENT_TASK: read, search, document, patch calc.py, and verify via shell" </dev/null >/tmp/forge_agent.out 2>&1 || {
            cat /tmp/forge_agent.out >&2
            fail "forge multi-turn agent exited non-zero"
        }
    grep -q "FORGECODE_AGENT_MISSION_COMPLETE_42" /tmp/forge_agent.out || fail "forge agent missing completion banner: $(cat /tmp/forge_agent.out)"
    [ -s /tmp/forge_demo/notes.txt ] || fail "forge write tool did not create /tmp/forge_demo/notes.txt"
    [ "$(/usr/local/bin/python3 /tmp/forge_demo/calc.py)" = "CALC_RESULT=42" ] || fail "forge patch tool did not fix calc.py"

    # Verify SQLite .forge.db conversation persistence via sqlite3 & CLI
    [ -s /tmp/forge_cfg/.forge.db ] || fail "missing /tmp/forge_cfg/.forge.db"
    FG_CONV_CNT="$(/usr/local/bin/sqlite3 /tmp/forge_cfg/.forge.db 'SELECT COUNT(*) FROM conversations;' 2>/dev/null || /usr/local/bin/python3 -c "import sqlite3; c=sqlite3.connect('/tmp/forge_cfg/.forge.db'); t=[r[0] for r in c.execute(\"SELECT name FROM sqlite_master WHERE type='table'\")]; print(sum(c.execute(f'SELECT COUNT(*) FROM \"{x}\"').fetchone()[0] for x in t if 'conv' in x))")"
    [ "${FG_CONV_CNT:-0}" -ge 1 ] || fail "expected >=1 conversation in .forge.db, got ${FG_CONV_CNT:-0}"
    MALLOC_OPTIONS=JJ FORGE_CONFIG=/tmp/forge_cfg OPENAI_URL="http://127.0.0.1:${MOCK_PORT}/v1" OPENAI_API_KEY="sk-forge-test" \
        /usr/local/bin/forge -C /tmp/forge_demo list conversation --porcelain > /tmp/forge_convs.txt
    [ -s /tmp/forge_convs.txt ] || fail "forge list conversation --porcelain returned empty output"
    pass "03_forgecode_e2e" "forge/forgecode 2.14.0 CLI, zsh integration, 4x MALLOC_OPTIONS=JJ execve, 6-turn read/fs_search/write/patch/shell agent, and SQLite .forge.db OK"
fi

# ==============================================================================
# 4. AIChat (`0.30.0`) Verification
# ==============================================================================
if [ "$RUN_AICHAT" = "1" ]; then
    rm -rf /tmp/aichat_cfg /tmp/aichat_rag_docs /tmp/fn_tool_ran.json /tmp/agent_deploy_stamp.txt
    mkdir -p /tmp/aichat_cfg /tmp/aichat_rag_docs
    cat > /tmp/aichat_cfg/config.yaml <<YAML
model: localmock:gpt-mock
stream: true
save: true
save_session: true
function_calling: true
highlight: false
rag_embedding_model: localmock:embed-1
rag_top_k: 2
rag_chunk_size: 400
rag_chunk_overlap: 20
clients:
  - type: openai-compatible
    name: localmock
    api_base: http://127.0.0.1:${MOCK_PORT}/v1
    api_key: sk-obsd-test
    models:
      - name: gpt-mock
        max_input_tokens: 128000
        supports_function_calling: true
      - name: embed-1
        type: embedding
        default_chunk_size: 400
        max_batch_size: 16
YAML
    export AICHAT_CONFIG_DIR=/tmp/aichat_cfg

    v_ai="$(MALLOC_OPTIONS=JJ /usr/local/bin/aichat --version)"
    case "$v_ai" in
        *"0.30.0"*) ;;
        *) fail "unexpected aichat --version: $v_ai" ;;
    esac
    /usr/local/bin/aichat --help | grep -q -- "--rag"
    /usr/local/bin/aichat --list-roles | grep -q "%shell%"

    for iter in 1 2 3 4 5; do
        i_jj="$(MALLOC_OPTIONS=JJ /usr/local/bin/aichat --info)"
        printf '%s\n' "$i_jj" | grep -q "localmock:gpt-mock" || fail "aichat repeated execve iter $iter failed"
    done

    [ "$(MALLOC_OPTIONS=JJ /usr/local/bin/aichat 'Hello')" = "HELLO_STREAM_FROM_OBSD_MOCK" ] || fail "aichat SSE chat failed"
    [ "$(MALLOC_OPTIONS=JJ /usr/local/bin/aichat -c 'CODE_MODE_PROMPT')" = "echo CODE_EXTRACTED_42" ] || fail "aichat -c failed"
    out_sh="$(MALLOC_OPTIONS=JJ /usr/local/bin/aichat -e 'SHELL_EXEC_PROMPT')"
    [ "$(sh -c "$out_sh")" = "SHELL_ASSISTANT_UNAME_OpenBSD" ] || fail "aichat -e shell assistant failed: $out_sh"

    [ "$(MALLOC_OPTIONS=JJ /usr/local/bin/aichat --session obsd_sess --save-session 'Remember codeword ORBIT-77')" = "ACK_STORED_ORBIT-77" ] || fail "aichat session store failed"
    [ -s /tmp/aichat_cfg/sessions/obsd_sess.yaml ] || fail "missing session yaml"
    [ "$(MALLOC_OPTIONS=JJ /usr/local/bin/aichat --session obsd_sess --save-session 'What was the codeword?')" = "SESSION_RECALL_OK: ORBIT-77" ] || fail "aichat session recall failed"

    # RAG (hnsw_rs + bm25)
    cat > /tmp/aichat_rag_docs/architecture.md <<'DOC1'
# Sonvori Network Protocol (SVNP)
The SVNP bridge uses magic header `0x53564E50` and binds loopback test endpoints on port `18080`.
DOC1
    cat > /tmp/aichat_rag_docs/checksum.rs <<'DOC2'
pub fn compute_checksum() -> u32 { 0xCAFE_8080 }
DOC2
    cat > /tmp/aichat_rag_docs/cooking.md <<'DOC3'
# Neapolitan Pizza
Combine flour, water, salt, yeast, San Marzano tomato sauce, and fresh mozzarella.
DOC3
    mkdir -p /tmp/aichat_cfg/rags
    cat > /tmp/aichat_cfg/rags/obsd_kb.yaml <<'RAG_YAML'
embedding_model: localmock:embed-1
chunk_size: 400
chunk_overlap: 20
reranker_model: null
top_k: 2
batch_size: 16
next_file_id: 0
document_paths:
  - /tmp/aichat_rag_docs/architecture.md
  - /tmp/aichat_rag_docs/checksum.rs
  - /tmp/aichat_rag_docs/cooking.md
files: {}
vectors: {}
RAG_YAML
    rag1="$(MALLOC_OPTIONS=JJ /usr/local/bin/aichat --rag obsd_kb --rebuild-rag 'What svnp magic protocol header and compute_checksum rust constant are used?')"
    printf '%s\n' "$rag1" | grep -q "RAG_GROUNDED_OK svnp=True cksum=True" || fail "aichat --rebuild-rag failed: $rag1"
    rag2="$(MALLOC_OPTIONS=JJ /usr/local/bin/aichat --rag obsd_kb 'Verify svnp magic and compute_checksum')"
    printf '%s\n' "$rag2" | grep -q "RAG_GROUNDED_OK svnp=True cksum=True" || fail "aichat persisted --rag reload failed: $rag2"

    # Function-calling & --agent
    mkdir -p /tmp/aichat_cfg/functions/bin /tmp/aichat_cfg/functions/agents/obsd_ops/bin
    cat > /tmp/aichat_cfg/functions/functions.json <<'FN_JSON'
[{"name":"obsd_calc_tool","description":"Sum two integers","parameters":{"type":"object","properties":{"a":{"type":"integer"},"b":{"type":"integer"}},"required":["a","b"]}}]
FN_JSON
    cat > /tmp/aichat_cfg/functions/bin/obsd_calc_tool <<'FN_SH'
#!/bin/sh
set -e
a_val=$(printf '%s' "$1" | sed -n 's/.*"a":[[:space:]]*\([0-9][0-9]*\).*/\1/p')
b_val=$(printf '%s' "$1" | sed -n 's/.*"b":[[:space:]]*\([0-9][0-9]*\).*/\1/p')
sum_val=$(expr "$a_val" + "$b_val")
printf '{"sum":%s,"os":"OpenBSD"}' "$sum_val" > /tmp/fn_tool_ran.json
cp /tmp/fn_tool_ran.json "$LLM_OUTPUT"
FN_SH
    chmod 755 /tmp/aichat_cfg/functions/bin/obsd_calc_tool
    fn_out="$(MALLOC_OPTIONS=JJ /usr/local/bin/aichat --role %functions% 'Add 19 and 23 using obsd_calc_tool')"
    printf '%s\n' "$fn_out" | grep -q '"sum":42' || fail "aichat function tool failed: $fn_out"

    echo "obsd_ops" > /tmp/aichat_cfg/functions/agents.txt
    cat > /tmp/aichat_cfg/functions/agents/obsd_ops/index.yaml <<'AG_YAML'
name: obsd_ops
description: OpenBSD deployment verification agent
version: 1.0.0
instructions: Use tools to stamp deployments.
AG_YAML
    cat > /tmp/aichat_cfg/functions/agents/obsd_ops/functions.json <<'AG_FN'
[{"name":"deploy_stamp","description":"Stamp deployment","parameters":{"type":"object","properties":{"tag":{"type":"string"}},"required":["tag"]},"agent":true}]
AG_FN
    cat > /tmp/aichat_cfg/functions/agents/obsd_ops/bin/obsd_ops <<'AG_SH'
#!/bin/sh
set -e
tag_val=$(printf '%s' "$2" | sed -n 's/.*"tag":[[:space:]]*"\([^"]*\)".*/\1/p')
printf '%s:%s\n' "$1" "$tag_val" > /tmp/agent_deploy_stamp.txt
printf '{"action":"%s","tag":"%s","stamped":true}' "$1" "$tag_val" > "$LLM_OUTPUT"
AG_SH
    chmod 755 /tmp/aichat_cfg/functions/agents/obsd_ops/bin/obsd_ops
    ag_out="$(MALLOC_OPTIONS=JJ /usr/local/bin/aichat --agent obsd_ops 'Stamp current release')"
    [ "$(cat /tmp/agent_deploy_stamp.txt)" = "deploy_stamp:sonvori-v0.30.0" ] || fail "aichat --agent stamp mismatch"
    printf '%s\n' "$ag_out" | grep -q "sonvori-v0.30.0" || fail "aichat --agent output mismatch: $ag_out"

    # Interactive 80x24 openpty() --repl via OpenBSD CPython pty.openpty() + subprocess.Popen
    /usr/local/bin/python3 -I - <<'PY_AICHAT_PTY'
import errno, fcntl, os, pty, select, struct, subprocess, termios, time

master_fd, slave_fd = pty.openpty()
fcntl.ioctl(slave_fd, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))

env = dict(os.environ)
env["TERM"] = "xterm-256color"
env["AICHAT_CONFIG_DIR"] = "/tmp/aichat_cfg"
env["MALLOC_OPTIONS"] = "JJ"

proc = subprocess.Popen(
    ["/usr/local/bin/aichat"],
    stdin=slave_fd,
    stdout=slave_fd,
    stderr=slave_fd,
    start_new_session=True,
    env=env,
)
os.close(slave_fd)
buf = bytearray()
scan_pos = 0

def answer_queries() -> None:
    global scan_pos
    while scan_pos < len(buf):
        rem = len(buf) - scan_pos
        if rem >= 4 and buf[scan_pos:scan_pos+4] == b"\x1b[6n":
            os.write(master_fd, b"\x1b[1;1R")
            scan_pos += 4
            continue
        if rem >= 6 and buf[scan_pos:scan_pos+6] == b"\x1b]11;?":
            os.write(master_fd, b"\x1b]11;rgb:1e1e/1e1e/1e1e\x1b\\")
            scan_pos += 6
            continue
        if rem >= 6 and buf[scan_pos:scan_pos+6] == b"\x1b]10;?":
            os.write(master_fd, b"\x1b]10;rgb:d0d0/d0d0/d0d0\x1b\\")
            scan_pos += 6
            continue
        scan_pos += 1

def wait_for(needle: bytes, timeout_s: float = 25.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if needle in buf:
            return
        rdy, _, _ = select.select([master_fd], [], [], 0.05)
        if rdy:
            try:
                chunk = os.read(master_fd, 4096)
            except OSError as exc:
                if exc.errno in (errno.EINTR, errno.EAGAIN):
                    continue
                break
            if not chunk:
                break
            buf.extend(chunk)
            answer_queries()
            if needle in buf:
                return
    raise AssertionError(f"PTY timeout waiting for {needle!r}; captured:\n{buf.decode('utf-8', 'replace')}")

try:
    wait_for(b"Welcome to aichat 0.30.0")
    wait_for(b">")
    time.sleep(0.3)
    wait_for(b">")
    os.write(master_fd, b".info\r")
    wait_for(b"config_file")
    wait_for(b"localmock:gpt-mock")
    time.sleep(0.2)
    os.write(master_fd, b"Hello from interactive PTY REPL\r")
    wait_for(b"PTY_REPL_STREAM_OK")
    time.sleep(0.2)
    os.write(master_fd, b".exit\r")
    rc = None
    for _ in range(200):
        rdy, _, _ = select.select([master_fd], [], [], 0.05)
        if rdy:
            try:
                c = os.read(master_fd, 4096)
                if c:
                    buf.extend(c)
                    answer_queries()
            except OSError:
                pass
        rc = proc.poll()
        if rc is not None:
            break
    assert rc == 0, f"bad REPL exit code: {rc}; captured:\n{buf.decode('utf-8', 'replace')}"
finally:
    if proc.poll() is None:
        proc.kill()
        proc.wait()
    try:
        os.close(master_fd)
    except OSError:
        pass
PY_AICHAT_PTY

    # In-Guest HTTP Server (`aichat --serve 127.0.0.1:<free_port>`: /v1/models, /v1/roles, /playground, /arena, /v1/chat/completions JSON + SSE)
    # Note: run with TOKIO_WORKER_THREADS=2 so minimal Web Worker pthreads are used when stopped via SIGKILL
    SERVE_PORT="$(/usr/local/bin/python3 -I -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')"
    TOKIO_WORKER_THREADS=2 MALLOC_OPTIONS=JJ /usr/local/bin/aichat --serve "127.0.0.1:${SERVE_PORT}" </dev/null >/tmp/aichat_serve.log 2>&1 &
    AICHAT_SERVE_PID=$!

    SERVE_PORT="$SERVE_PORT" /usr/local/bin/python3 -I - <<'PY_AICHAT_SERVE'
import json, os, socket, time, urllib.request

sport = int(os.environ["SERVE_PORT"])
base = f"http://127.0.0.1:{sport}"
def http_get(url, timeout=5):
    return urllib.request.urlopen(urllib.request.Request(url, headers={"Connection": "close"}), timeout=timeout)

for _ in range(200):
    try:
        with http_get(f"{base}/v1/models", timeout=2) as r:
            if r.status == 200:
                models = json.loads(r.read().decode("utf-8"))
                break
    except Exception:
        time.sleep(0.1)
else:
    raise SystemExit(f"aichat --serve did not become ready on {base}")

mids = [m.get("id") for m in models.get("data", [])]
assert "default" in mids and "localmock:gpt-mock" in mids, mids

for ep, marker in (("/playground", "playground"), ("/arena", "arena")):
    with http_get(f"{base}{ep}", timeout=5) as r:
        html = r.read().decode("utf-8")
        assert r.status == 200 and "<html" in html.lower() and marker in html.lower(), f"bad {ep}"

with http_get(f"{base}/v1/roles", timeout=5) as r:
    assert r.status == 200 and isinstance(json.loads(r.read().decode("utf-8")).get("data"), list)

req = urllib.request.Request(
    f"{base}/v1/chat/completions",
    data=json.dumps({"model": "default", "stream": False, "messages": [{"role": "user", "content": "SERVE_PROXY_PING"}]}).encode("utf-8"),
    headers={"Content-Type": "application/json", "Connection": "close"},
    method="POST",
)
with urllib.request.urlopen(req, timeout=15) as r:
    comp = json.loads(r.read().decode("utf-8"))
    assert comp["choices"][0]["message"]["content"] == "SERVE_PROXY_COMPLETION_OK", comp

s_sse = socket.create_connection(("127.0.0.1", sport), timeout=15)
s_sse.settimeout(15)
body = json.dumps({"model": "localmock:gpt-mock", "stream": True, "messages": [{"role": "user", "content": "SERVE_PROXY_PING"}]}).encode("utf-8")
s_sse.sendall(
    f"POST /v1/chat/completions HTTP/1.1\r\nHost: 127.0.0.1:{sport}\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {len(body)}\r\n\r\n".encode("utf-8") + body
)
sse_buf = b""
while b"data: [DONE]" not in sse_buf:
    chunk = s_sse.recv(4096)
    if not chunk:
        break
    sse_buf += chunk
s_sse.close()
sse_txt = sse_buf.decode("utf-8", errors="replace")
sse_joined = "".join(
    json.loads(ln[6:]).get("choices", [{}])[0].get("delta", {}).get("content", "")
    for ln in sse_txt.splitlines()
    if ln.startswith("data: {")
)
assert sse_joined == "SERVE_PROXY_COMPLETION_OK" and "data: [DONE]" in sse_txt, sse_txt
PY_AICHAT_SERVE

    kill -9 "$AICHAT_SERVE_PID" 2>/dev/null || true
    AICHAT_SERVE_PID=""
    pass "04_aichat_e2e" "aichat 0.30.0 CLI, 5x MALLOC_OPTIONS=JJ execve, SSE/-c/-e/--session, hnsw_rs --rag, --agent, 80x24 PTY --repl, and --serve (/v1/* + /playground + /arena) OK"
fi

# ==============================================================================
# 5. Live In-Guest `llama-server` (`/tmp/tiny.gguf`) Integration
# ==============================================================================
if [ "$RUN_LLAMA_LIVE" = "1" ]; then
    [ -s /tmp/tiny.gguf ] || fail "missing staged /tmp/tiny.gguf"
    LLAMA_PORT="$(/usr/local/bin/python3 -I -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')"
    /usr/local/bin/llama-server \
        -m /tmp/tiny.gguf \
        --alias tiny \
        --host 127.0.0.1 \
        --port "$LLAMA_PORT" \
        -fa off \
        -sps 0.0 \
        -r "!" \
        --threads-http 4 \
        -t 1 \
        --no-warmup \
        --jinja \
        -np 1 \
        -c 4096 \
        -b 64 \
        -ub 16 \
        -n 3 >/tmp/wave5_llama_srv.log 2>&1 &
    LLAMA_SRV_PID=$!

    LLAMA_READY=0
    _l_try=0
    while [ "$_l_try" -lt 80 ]; do
        if HJSON="$(/usr/local/bin/curl -fsS --max-time 2 "http://127.0.0.1:${LLAMA_PORT}/health" 2>/dev/null)"; then
            if printf '%s' "$HJSON" | grep -q '"ok"'; then
                LLAMA_READY=1
                break
            fi
        fi
        if ! kill -0 "$LLAMA_SRV_PID" 2>/dev/null; then
            fail "llama-server exited prematurely: $(cat /tmp/wave5_llama_srv.log)"
        fi
        sleep 0.25
        _l_try=$((_l_try + 1))
    done
    [ "$LLAMA_READY" = "1" ] || fail "llama-server did not become healthy on 127.0.0.1:${LLAMA_PORT}: $(cat /tmp/wave5_llama_srv.log)"

    # 5a. ForgeCode -> live in-guest llama-server (using native `llama_cpp` provider!)
    rm -rf /tmp/f_home /tmp/f_cfg /tmp/f_ws
    mkdir -p /tmp/f_home /tmp/f_cfg/agents /tmp/f_ws/.forge/agents
    cat > /tmp/f_cfg/agents/quick.md <<'EOF'
---
id: "quick"
title: "Quick Chat"
description: "Concise chat agent for live llama-server verification"
user_prompt: "{{event.value}}"
tool_supported: true
tools: []
max_tokens: 3
max_turns: 1
max_requests_per_turn: 1
reasoning:
  enabled: false
---
Reply briefly.
EOF
    cp /tmp/f_cfg/agents/quick.md /tmp/f_ws/.forge/agents/quick.md
    cat > /tmp/f_ws/conv.json <<'EOF'
{
  "id": "00000000-0000-4000-8000-000000000001",
  "title": "Quick",
  "context": null,
  "metrics": {},
  "metadata": {
    "created_at": "2026-01-01T00:00:00Z",
    "updated_at": null
  }
}
EOF
    cat > /tmp/f_cfg/.forge.toml <<EOF
max_tokens = 3
max_requests_per_turn = 1
tool_supported = true
max_walker_depth = 0

[http]
pool_max_idle_per_host = 0

[reasoning]
enabled = false

[updates]
auto_update = false
frequency = "never"

[session]
provider_id = "llama_cpp"
model_id = "tiny"
EOF
    HOME=/tmp/f_home \
    TOKIO_WORKER_THREADS=2 \
    MALLOC_OPTIONS=JJ \
    FORGE_CONFIG=/tmp/f_cfg \
    FORGE_TRACKER=false \
    LLAMA_CPP_SSL_SCHEME=http \
    LLAMA_CPP_HOST=127.0.0.1 \
    LLAMA_CPP_PORT="${LLAMA_PORT}" \
    LLAMA_CPP_API_KEY="sk-local-llama" \
        /usr/local/bin/forge -C /tmp/f_ws --agent quick --conversation /tmp/f_ws/conv.json -p "hi" </dev/null >/tmp/forge_llama.out 2>&1 || {
            cat /tmp/forge_llama.out >&2
            tail -n 30 /tmp/wave5_llama_srv.log >&2 || true
            fail "forge -> live llama-server exited non-zero"
        }
    grep -q "OpenBSD_WASM64_OK" /tmp/forge_llama.out || fail "forge -> live llama-server missing OpenBSD_WASM64_OK: $(cat /tmp/forge_llama.out)"
    [ -s /tmp/f_cfg/.forge.db ] || fail "forge -> live llama-server missing /tmp/f_cfg/.forge.db"

    # 5b. Goose -> live in-guest llama-server
    rm -rf /tmp/g_l /tmp/g_ws
    mkdir -p /tmp/g_l/.config/goose/custom_providers /tmp/g_l/.local/share/goose /tmp/g_l/.local/state/goose /tmp/g_ws
    printf 'Reply briefly.\n' > /tmp/g_l/sys.txt
    cat > /tmp/g_l/.config/goose/custom_providers/local_llama.json <<EOF
{
  "name": "local_llama",
  "engine": "openai",
  "display_name": "Local Llama",
  "api_key_env": "",
  "base_url": "http://127.0.0.1:${LLAMA_PORT}/v1/chat/completions",
  "dynamic_models": false,
  "models": [
    {
      "name": "tiny",
      "context_limit": 4096,
      "max_tokens": 3,
      "request_params": {
        "cache_prompt": false,
        "tools": [],
        "tool_choice": "auto",
        "stop": ["!"]
      }
    }
  ],
  "headers": {
    "Connection": "close"
  },
  "supports_streaming": true,
  "requires_auth": false,
  "skip_canonical_filtering": true
}
EOF
    (
        cd /tmp/g_ws
        TOKIO_WORKER_THREADS=2 \
        HOME=/tmp/g_l \
        XDG_CONFIG_HOME=/tmp/g_l/.config \
        XDG_DATA_HOME=/tmp/g_l/.local/share \
        XDG_STATE_HOME=/tmp/g_l/.local/state \
        GOOSE_DISABLE_KEYRING=1 \
        GOOSE_DISABLE_SESSION_NAMING=true \
        GOOSE_TELEMETRY_OFF=1 \
        GOOSE_OFFLINE_MODEL_CATALOG=1 \
        GOOSE_SYSTEM_PROMPT_FILE_PATH=/tmp/g_l/sys.txt \
        GOOSE_PROVIDER=local_llama \
        GOOSE_MODEL="tiny" \
        GOOSE_CONTEXT_LIMIT=4096 \
        GOOSE_MAX_TOKENS=3 \
        GOOSE_MODE="chat" \
        MALLOC_OPTIONS=JJ \
            /usr/local/bin/goose run --name quick --no-profile --max-turns 1 --text "hi" </dev/null >/tmp/goose_llama.out 2>&1
    ) || {
        cat /tmp/goose_llama.out >&2
        tail -n 30 /tmp/wave5_llama_srv.log >&2 || true
        fail "goose -> live llama-server exited non-zero"
    }
    grep -q "OpenBSD_WASM64_OK" /tmp/goose_llama.out || fail "goose -> live llama-server missing OpenBSD_WASM64_OK: $(cat /tmp/goose_llama.out)"

    # 5c. AIChat -> live in-guest llama-server
    rm -rf /tmp/ai_l
    mkdir -p /tmp/ai_l
    cat > /tmp/ai_l/config.yaml <<YAML
model: local_llama:tiny
stream: true
max_output_tokens: 3
temperature: 0.0
clients:
  - type: openai-compatible
    name: local_llama
    api_base: http://127.0.0.1:${LLAMA_PORT}/v1
    api_key: sk-local-llama
    patch:
      chat_completions:
        '.*':
          body:
            cache_prompt: false
    models:
      - name: tiny
        max_input_tokens: 4096
YAML
    AI_LLAMA_OUT="$(TOKIO_WORKER_THREADS=2 MALLOC_OPTIONS=JJ AICHAT_CONFIG_DIR=/tmp/ai_l /usr/local/bin/aichat 'hi')"
    printf '%s\n' "$AI_LLAMA_OUT" | grep -q "OpenBSD_WASM64_OK" || fail "aichat -> live llama-server missing OpenBSD_WASM64_OK: $AI_LLAMA_OUT"

    kill -15 "$LLAMA_SRV_PID" 2>/dev/null || true
    /usr/local/bin/curl -fsS --max-time 1 "http://127.0.0.1:${LLAMA_PORT}/health" >/dev/null 2>&1 || true
    sleep 0.2
    kill -9 "$LLAMA_SRV_PID" 2>/dev/null || true
    LLAMA_SRV_PID=""
    pass "05_live_in_guest_llama_server" "forge, goose, and aichat verified live against in-guest llama-server (/tmp/tiny.gguf) inside WASM64 OpenBSD $EXPECTED_REL"
fi

echo "[WAVE5-EXTRA-ALL-OK] OpenBSD $EXPECTED_REL passed 100% of Wave-5 Extra AI Agents & Live llama-server tests!"
"""


WAVE5_FAST_BPE_CORPUS = """<|im_start|>system
Reply briefly.<|im_end|>
<system_information>
<operating_system>openbsd</operating_system>
<current_working_directory>/tmp/f_ws</current_working_directory>
<default_shell>/bin/sh</default_shell>
<home_directory>/tmp/f_home</home_directory>
<file_list>
 - /tmp/f_ws/conv.json
</file_list>
</system_information>
<tool_usage_instructions>
- For maximum efficiency, whenever you need to perform multiple independent operations, invoke all relevant tools (for eg: `patch`, `read`) simultaneously rather than sequentially.
- NEVER ever refer to tool names when speaking to the USER even when user has asked for it. For example, instead of saying 'I need to use the edit_file tool to edit your file', just say 'I will edit your file'.
- If you need to read a file, prefer to read larger sections of the file at once over multiple smaller calls.
</tool_usage_instructions>
<non_negotiable_rules>
- ALWAYS present the result of your work in a neatly structured format (using markdown syntax in your response) to the user at the end of every task.
- Do what has been asked; nothing more, nothing less.
- NEVER create files unless they're absolutely necessary for achieving your goal.
- ALWAYS prefer editing an existing file to creating a new one.
- NEVER create documentation files (\\*.md, \\*.txt, README, CHANGELOG, CONTRIBUTING, etc.) unless explicitly requested by the user. Includes summaries/overviews, architecture docs, migration guides/HOWTOs, or any explanatory file about work just completed. Instead, explain in your reply in the final response or use code comments. "Explicitly requested" means the user asks for a specific document by name or purpose.
- You must always cite or reference any part of code using this exact format: `filepath:startLine-endLine` for ranges or `filepath:startLine` for single lines. Do not use any other format.
- The conversation has unlimited context through automatic summarization, so do not stop until the objective is fully achieved.

  **Good examples:**

  - `src/main.rs:10` (single line)
  - `src/utils/helper.rs:25-30` (range)
  - `lib/core.rs:100-150` (larger range)

  **Bad examples:**

  - "line 10 of main.rs"
  - "see src/main.rs lines 25-30"
  - "check main.rs"
  - "in the helper.rs file around line 25"
  - `crates/app/src/lib.rs` (lines 1-4)

- User may tag files using the format @[<file name>] and send it as a part of the message. Do not attempt to reread those files.
- Only use emojis if the user explicitly requests it. Avoid using emojis in all communication unless asked.
</non_negotiable_rules>
## Skill Instructions:

**CRITICAL**: Before attempting any task, ALWAYS check if a skill exists for it in the available_skills list below. Skills are specialized workflows that must be invoked when their trigger conditions match the user's request.

How skills work:

1. **Invocation**: Use the `skill` tool with just the skill name parameter

   - Example: Call skill tool with `{"name": "mock-calculator"}`
   - No additional arguments needed

2. **Response**: The tool returns the skill's details wrapped in `<skill_details>` containing:

   - `<command path="..."><![CDATA[...]]></command>` - The complete SKILL.md file content with the skill's path
   - `<resource>` tags - List of additional resource files available in the skill directory
   - Includes usage guidelines, instructions, and any domain-specific knowledge

3. **Action**: Read and follow the instructions provided in the skill content
   - The skill instructions will tell you exactly what to do and how to use the resources
   - Some skills provide workflows, others provide reference information
   - Apply the skill's guidance to complete the user's task

Examples of skill invocation:

- To invoke calculator skill: use skill tool with name "calculator"
- To invoke weather skill: use skill tool with name "weather"
- For namespaced skills: use skill tool with name "office-suite:pdf"

Important:

- Only invoke skills listed in `<available_skills>` below
- Do not invoke a skill that is already active/loaded
- Skills are not CLI commands - use the skill tool to load them
- After loading a skill, follow its specific instructions to help the user

<available_skills>
<skill>
<name>create-skill</name>
<description>
Guide for creating effective skills. This skill should be used when users want to create a new skill (or update an existing skill) that extends your capabilities with specialized knowledge, workflows, or tool integrations.
</description>
</skill>
<skill>
<name>execute-plan</name>
<description>
Execute structured task plans with status tracking. Use when the user provides a plan file path in the format `plans/{current-date}-{task-name}-{version}.md` or explicitly asks you to execute a plan file.
</description>
</skill>
<skill>
<name>github-pr-description</name>
<description>
Generate and create pull request descriptions automatically using GitHub CLI. Use when the user asks to create a PR, generate a PR description, make a pull request, or submit changes for review. Analyzes git diff and commit history to create comprehensive, meaningful PR descriptions that explain what changed, why it matters, and how to test it.
</description>
</skill>
</available_skills>
You are goose, a general-purpose AI agent. You have skills and extensions available when needed. Current directory: /tmp/g_ws
<|im_start|>user
hi<|im_end|>
<|im_start|>assistant
"""


def synthesize_wave5_fast_gguf(out_path: pathlib.Path) -> None:
    """Synthesize a deterministic 1-layer Llama GGUF v3 model (`n_ctx = 8192`) with
    true bottom-up SentencePiece binary-merge BPE scores so multi-kilobyte agent
    system prompts tokenize compactly inside WASM64 OpenBSD."""
    n_embd, n_head, n_head_kv, n_ff = 32, 2, 2, 64
    special = ["<unk>", "<s>", "</s>", "<|im_end|>", "<|im_start|>"]
    byte_toks = [f"<0x{b:02X}>" for b in range(256)]
    ok_tok = "\u2581OpenBSD_WASM64_OK!"

    sp_text = ("\u2581" + WAVE5_FAST_BPE_CORPUS).replace(" ", "\u2581")
    base_chars = list(
        dict.fromkeys(
            list(sp_text)
            + list(
                "\n\r\t\u2581abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789?.,!:-_/<>=\"'()[]{}#*`@+$%^&~|\\;"
            )
        )
    )

    tokens = list(special) + list(byte_toks) + [ok_tok] + [c for c in base_chars if c not in special]
    scores = [0.0] * 5 + [-50000.0] * 256 + [-40000.0] + [-30000.0] * (len(tokens) - 262)
    seen = set(tokens)

    seq = list(sp_text)
    for step in range(1, 2401):
        counts = collections.Counter(
            (a, b)
            for a, b in zip(seq, seq[1:])
            if len(a) + len(b) <= 96 and "\n" not in a[1:] and "\n" not in b[:-1]
        )
        if not counts:
            break
        (a, b), _freq = counts.most_common(1)[0]
        merged = a + b
        if merged not in seen:
            tokens.append(merged)
            scores.append(-float(step))
            seen.add(merged)
        new_seq: List[str] = []
        i = 0
        n_s = len(seq)
        while i < n_s:
            if i + 1 < n_s and seq[i] == a and seq[i + 1] == b:
                new_seq.append(merged)
                i += 2
            else:
                new_seq.append(seq[i])
                i += 1
        seq = new_seq
        if len(seq) <= 90:
            break

    n_vocab = len(tokens)
    ok_idx = tokens.index(ok_tok)
    ttypes = [2, 3, 3, 3, 3] + ([6] * 256) + ([1] * (n_vocab - 261))
    chat_tmpl = (
        "{% for message in messages %}"
        "{{ '<|im_start|>' + message['role'] + '\\n' + (message['content'] if message['content'] is string else '') + '<|im_end|>\\n' }}"
        "{% endfor %}"
        "{% if add_generation_prompt %}{{ '<|im_start|>assistant\\n' }}{% endif %}"
    )

    def gs(s: str) -> bytes:
        b = s.encode("utf-8")
        return struct.pack("<Q", len(b)) + b

    kvs = [
        gs("general.architecture") + struct.pack("<I", 8) + gs("llama"),
        gs("general.name") + struct.pack("<I", 8) + gs("tiny-wave5-llama"),
        gs("general.file_type") + struct.pack("<II", 4, 0),
        gs("llama.vocab_size") + struct.pack("<II", 4, n_vocab),
        gs("llama.context_length") + struct.pack("<II", 4, 8192),
        gs("llama.embedding_length") + struct.pack("<II", 4, n_embd),
        gs("llama.block_count") + struct.pack("<II", 4, 1),
        gs("llama.feed_forward_length") + struct.pack("<II", 4, n_ff),
        gs("llama.attention.head_count") + struct.pack("<II", 4, n_head),
        gs("llama.attention.head_count_kv") + struct.pack("<II", 4, n_head_kv),
        gs("llama.attention.layer_norm_rms_epsilon") + struct.pack("<If", 6, 1e-5),
        gs("llama.rope.dimension_count") + struct.pack("<II", 4, n_embd // n_head),
        gs("llama.rope.freq_base") + struct.pack("<If", 6, 10000.0),
        gs("tokenizer.ggml.model") + struct.pack("<I", 8) + gs("llama"),
        gs("tokenizer.ggml.tokens") + struct.pack("<IIQ", 9, 8, len(tokens)) + b"".join(gs(x) for x in tokens),
        gs("tokenizer.ggml.scores") + struct.pack("<IIQ", 9, 6, len(scores)) + struct.pack(f"<{len(scores)}f", *scores),
        gs("tokenizer.ggml.token_type") + struct.pack("<IIQ", 9, 5, len(ttypes)) + struct.pack(f"<{len(ttypes)}i", *ttypes),
        gs("tokenizer.ggml.bos_token_id") + struct.pack("<II", 4, 1),
        gs("tokenizer.ggml.eos_token_id") + struct.pack("<II", 4, 2),
        gs("tokenizer.ggml.eot_token_id") + struct.pack("<II", 4, 3),
        gs("tokenizer.ggml.unknown_token_id") + struct.pack("<II", 4, 0),
        gs("tokenizer.ggml.add_bos_token") + struct.pack("<IB", 7, 1),
        gs("tokenizer.chat_template") + struct.pack("<I", 8) + gs(chat_tmpl),
    ]
    tok_embd = [
        1.0 if d == 0 else 0.03 * math.sin(0.17 * (t + 1) * (d + 1))
        for t in range(n_vocab)
        for d in range(n_embd)
    ]
    out_w = [
        (-6.0 if t < 261 else (4.0 if t == ok_idx else 0.1))
        if d == 0
        else 0.01 * math.cos(0.13 * (t + 1) * (d + 1))
        for t in range(n_vocab)
        for d in range(n_embd)
    ]
    smat = lambda a, b, sd: [0.01 * math.sin(sd + 0.01 * i) for i in range(a * b)]
    tensors = [
        ("token_embd.weight", (n_embd, n_vocab), tok_embd),
        ("output_norm.weight", (n_embd,), [1.0] * n_embd),
        ("output.weight", (n_embd, n_vocab), out_w),
        ("blk.0.attn_norm.weight", (n_embd,), [1.0] * n_embd),
        ("blk.0.attn_q.weight", (n_embd, n_embd), smat(n_embd, n_embd, 0.1)),
        ("blk.0.attn_k.weight", (n_embd, n_embd), smat(n_embd, n_embd, 0.2)),
        ("blk.0.attn_v.weight", (n_embd, n_embd), smat(n_embd, n_embd, 0.3)),
        ("blk.0.attn_output.weight", (n_embd, n_embd), smat(n_embd, n_embd, 0.4)),
        ("blk.0.ffn_norm.weight", (n_embd,), [1.0] * n_embd),
        ("blk.0.ffn_gate.weight", (n_embd, n_ff), smat(n_embd, n_ff, 0.5)),
        ("blk.0.ffn_down.weight", (n_ff, n_embd), smat(n_ff, n_embd, 0.6)),
        ("blk.0.ffn_up.weight", (n_embd, n_ff), smat(n_embd, n_ff, 0.7)),
    ]
    t_infos, t_blobs, off = [], [], 0
    for name, dims, vals in tensors:
        raw = struct.pack(f"<{len(vals)}f", *vals)
        raw_p = raw + (b"\x00" * ((32 - (len(raw) % 32)) % 32))
        t_infos.append(
            gs(name)
            + struct.pack("<I", len(dims))
            + b"".join(struct.pack("<Q", d) for d in dims)
            + struct.pack("<IQ", 0, off)
        )
        t_blobs.append(raw_p)
        off += len(raw_p)
    hdr = b"GGUF" + struct.pack("<IQQ", 3, len(tensors), len(kvs)) + b"".join(kvs) + b"".join(t_infos)
    out_path.write_bytes(hdr + (b"\x00" * ((32 - (len(hdr) % 32)) % 32)) + b"".join(t_blobs))


def run_guest_suite(
    ver: str,
    obsd_root: pathlib.Path,
    lane_dir: pathlib.Path,
    selected_ports: Set[str],
    timeout_ms: int,
) -> None:
    mwg = _load_module("merge_wasm_guest", REPO_ROOT / "targets/emulate/emscripten/merge_wasm_guest.py")
    w4_ggml = _load_module("wave4_ai_ggml", REPO_ROOT / "tests/wave4_ai_ggml.py")

    runtime_mjs, table_tsv, node_bin = mwg.build_and_cache_test_runtime(obsd_root, ver, lane_dir)
    raw_tsv = table_tsv.read_bytes()
    table_digest = hashlib.sha256(raw_tsv).hexdigest()
    applet_paths = sorted({ln.split("\t")[0] for ln in raw_tsv.decode("utf-8").splitlines() if ln.strip()})

    src_root = obsd_root / "vendor/openbsd/versions" / ver / "src"
    test_dir = lane_dir / "test-runtime"
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

    for cert_cand in (
        src_root / "lib/libcrypto/cert.pem",
        pathlib.Path("/etc/ssl/certs/ca-certificates.crt"),
        pathlib.Path("/etc/ssl/cert.pem"),
    ):
        if cert_cand.is_file():
            staged_files.append(("/etc/ssl/cert.pem", str(cert_cand), 0o444))
            break

    for rel_ti in ("d/dumb", "x/xterm", "x/xterm-256color", "v/vt100"):
        for base_ti in ("/usr/share/terminfo", "/lib/terminfo"):
            cand = pathlib.Path(base_ti) / rel_ti
            if cand.is_file():
                staged_files.append((f"/usr/share/terminfo/{rel_ti}", str(cand), 0o444))
                break

    mock_srv = Wave5MockOpenAIServer()
    try:
        run_all_three = len(selected_ports) == 3
        script_text = (
            GUEST_WAVE5_SCRIPT_TEMPLATE.replace("__OPENBSD_VERSION__", ver)
            .replace("__MOCK_PORT__", str(mock_srv.port))
            .replace("__RUN_GOOSE__", "1" if "devel/goose" in selected_ports else "0")
            .replace("__RUN_FORGE__", "1" if "devel/forgecode" in selected_ports else "0")
            .replace("__RUN_AICHAT__", "1" if "misc/aichat" in selected_ports else "0")
            .replace("__RUN_LLAMA_LIVE__", "1" if run_all_three else "0")
        )

        with tempfile.TemporaryDirectory(prefix=f"wave5-extra-guest-{ver}-") as td:
            tp = pathlib.Path(td)
            tiny_gguf = tp / "tiny.gguf"
            synthesize_wave5_fast_gguf(tiny_gguf)
            staged_files.append(("/tmp/tiny.gguf", str(tiny_gguf), 0o644))

            runner_mjs = tp / "run_svnp_full.mjs"
            cfg_json = tp / "config.json"
            runner_mjs.write_text(w4_ggml.NODE_SVNP_FULL_MJS, encoding="utf-8")
            cfg_json.write_text(
                json.dumps(
                    {
                        "tableDigest": table_digest,
                        "appletPaths": applet_paths,
                        "sysrootUsrLocal": str(lane_dir / "sysroot/usr/local"),
                        "stagedFiles": staged_files,
                        "scriptText": script_text,
                        "enableSvnp": True,
                        "timeoutMs": timeout_ms,
                    }
                ),
                encoding="utf-8",
            )

            proc = subprocess.run(
                [node_bin, str(runner_mjs), str(runtime_mjs), str(cfg_json)],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
    finally:
        mock_srv.close()

    sys.stdout.write(proc.stdout)
    sys.stdout.flush()
    if proc.returncode != 0:
        raise SystemExit(f"[wave5_extra_ai_agents] OpenBSD {ver} guest suite failed with exit code {proc.returncode}")
    if f"[WAVE5-EXTRA-ALL-OK] OpenBSD {ver}" not in proc.stdout:
        raise SystemExit(f"[wave5_extra_ai_agents] OpenBSD {ver} missing completion banner")


def _parse_selected_ports(raw_port: str) -> Set[str]:
    if not raw_port.strip():
        return set(EXTRA_PORT_SPECS.keys())
    out: Set[str] = set()
    for item in raw_port.split(","):
        norm = item.strip().strip("/")
        if norm.startswith("extra/"):
            norm = norm[len("extra/") :]
        if norm in EXTRA_PORT_SPECS:
            out.add(norm)
        else:
            raise SystemExit(f"unsupported extra port filter '{item}' (expected one of {sorted(EXTRA_PORT_SPECS)})")
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--openbsd-version", default=os.environ.get("OPENBSD_VERSION", "all"))
    ap.add_argument("--libobsdcompat-root", default="")
    ap.add_argument("--ports-lane-dir", default="")
    ap.add_argument("--port", default="")
    ap.add_argument("--timeout-ms", type=int, default=540000)
    args = ap.parse_args()

    obsd_root = resolve_obsd_root(args.libobsdcompat_root)
    selected_ports = _parse_selected_ports(args.port)

    req = args.openbsd_version.strip()
    versions = ["7.8", "7.9", "8.0"] if req in ("", "all") else [v.strip() for v in req.split(",") if v.strip()]

    verify_3d_matrix_unit_and_integration()

    for ver in versions:
        if ver not in EXPECTED_TOTAL_PORTS:
            raise SystemExit(f"unsupported OpenBSD version: {ver}")
        lane_dir = (
            pathlib.Path(args.ports_lane_dir).resolve()
            if args.ports_lane_dir
            else (REPO_ROOT / "build/openbsd" / ver / "emulate/emscripten").resolve()
        )
        verify_host_packaging_and_jit_free(ver, obsd_root, lane_dir, selected_ports)
        run_guest_suite(ver, obsd_root, lane_dir, selected_ports, args.timeout_ms)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
