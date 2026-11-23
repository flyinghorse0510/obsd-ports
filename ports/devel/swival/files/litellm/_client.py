"""
litellm._client -- Live HTTP/HTTPS streaming SSE & non-streaming completion
driver for OpenAI / OpenAI-compatible (OpenRouter, Groq, DeepSeek, xAI, Mistral,
Ollama, LM Studio, llama-server, vLLM), Anthropic Claude (`/v1/messages`), and
Google Gemini (`/v1beta/openai/chat/completions`).
"""
from __future__ import annotations

import json
import os
import time
import uuid
from typing import Any, AsyncIterator, Dict, Iterator, List, Optional, Sequence, Tuple, Union

import httpx

from .exceptions import (
    APIConnectionError,
    AuthenticationError,
    Timeout,
    raise_mapped_http_error,
)
from .types.utils import (
    ChatCompletionMessageToolCall,
    Choices,
    Delta,
    Function,
    Message,
    ModelResponse,
    StreamingChoices,
    Usage,
    _LiteModel,
)
from .utils import stream_chunk_builder

_OPENAI_COMPAT_DEFAULTS: Dict[str, Tuple[str, str]] = {
    "openai": ("https://api.openai.com/v1", "OPENAI_API_KEY"),
    "chatgpt": ("https://api.openai.com/v1", "CHATGPT_API_KEY"),
    "openrouter": ("https://openrouter.ai/api/v1", "OPENROUTER_API_KEY"),
    "groq": ("https://api.groq.com/openai/v1", "GROQ_API_KEY"),
    "deepseek": ("https://api.deepseek.com/v1", "DEEPSEEK_API_KEY"),
    "xai": ("https://api.x.ai/v1", "XAI_API_KEY"),
    "mistral": ("https://api.mistral.com/v1", "MISTRAL_API_KEY"),
    "huggingface": ("https://router.huggingface.co/v1", "HF_TOKEN"),
    "ollama": ("http://127.0.0.1:11434/v1", "OLLAMA_API_KEY"),
    "ollama_chat": ("http://127.0.0.1:11434/v1", "OLLAMA_API_KEY"),
    "lm_studio": ("http://127.0.0.1:1234/v1", "LM_STUDIO_API_KEY"),
    "hosted_vllm": ("http://127.0.0.1:8000/v1", "HOSTED_VLLM_API_KEY"),
    "custom_openai": ("http://127.0.0.1:8080/v1", "OPENAI_API_KEY"),
    "gemini": ("https://generativelanguage.googleapis.com/v1beta/openai", "GEMINI_API_KEY"),
    "google": ("https://generativelanguage.googleapis.com/v1beta/openai", "GEMINI_API_KEY"),
}


def _resolve_route(
    model: str,
    api_base: Optional[str],
    api_key: Optional[str],
    custom_llm_provider: Optional[str],
) -> Tuple[str, str, str, str]:
    """Return `(protocol, endpoint_url, resolved_key, wire_model)`.
    `protocol` is either `'anthropic'` or `'openai'`.
    """
    raw_model = (model or "").strip()
    prov = (custom_llm_provider or "").strip().lower()

    # Unwrap `openai/anthropic/...` or `openai/gemini/...` emitted by swival `--provider generic`
    if raw_model.startswith("openai/anthropic/"):
        raw_model = raw_model[len("openai/") :]
    elif raw_model.startswith("openai/gemini/"):
        raw_model = raw_model[len("openai/") :]

    if not prov and "/" in raw_model:
        prefix, rest = raw_model.split("/", 1)
        p_low = prefix.lower()
        if p_low in _OPENAI_COMPAT_DEFAULTS or p_low == "anthropic":
            prov = p_low
            wire_model = rest
        else:
            prov = "openai"
            wire_model = raw_model
    elif prov and raw_model.startswith(f"{prov}/"):
        wire_model = raw_model[len(prov) + 1 :]
    else:
        wire_model = raw_model

    # Detect native Anthropic Claude routing
    is_anthropic = (
        prov == "anthropic"
        or (
            wire_model.startswith("claude-")
            and prov in ("", "openai")
            and (
                (api_base and ("anthropic.com" in api_base or api_base.rstrip("/").endswith("/messages")))
                or (not api_base and bool(os.environ.get("ANTHROPIC_API_KEY")))
            )
        )
    )

    if is_anthropic:
        key = (
            api_key
            if (api_key and api_key != "none")
            else (os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("OPENAI_API_KEY") or "")
        )
        base = (api_base or os.environ.get("ANTHROPIC_API_BASE") or "https://api.anthropic.com").rstrip("/")
        if base.endswith("/v1/messages") or base.endswith("/messages"):
            endpoint = base
        elif base.endswith("/v1"):
            endpoint = f"{base}/messages"
        else:
            endpoint = f"{base}/v1/messages"
        return "anthropic", endpoint, key, wire_model

    if not prov:
        prov = "openai"

    default_base, key_env = _OPENAI_COMPAT_DEFAULTS.get(prov, ("https://api.openai.com/v1", "OPENAI_API_KEY"))
    if prov in ("gemini", "google"):
        env_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY") or os.environ.get("OPENAI_API_KEY") or ""
    elif prov == "openai":
        env_key = os.environ.get("OPENAI_API_KEY") or ""
        default_base = os.environ.get("OPENAI_API_BASE") or os.environ.get("OPENAI_BASE_URL") or default_base
    elif prov == "ollama" or prov == "ollama_chat":
        env_key = os.environ.get(key_env) or "ollama"
        if os.environ.get("OLLAMA_API_BASE"):
            default_base = os.environ["OLLAMA_API_BASE"].rstrip("/") + "/v1"
    else:
        env_key = os.environ.get(key_env) or os.environ.get("OPENAI_API_KEY") or ""

    resolved_key = api_key if (api_key is not None and api_key != "") else env_key
    base = (api_base or default_base).rstrip("/")
    if base.endswith("/chat/completions"):
        endpoint = base
    elif any(base.endswith(seg) for seg in ("/v1", "/v2", "/v3", "/v4", "/openai")):
        endpoint = f"{base}/chat/completions"
    else:
        endpoint = f"{base}/v1/chat/completions"

    return "openai", endpoint, resolved_key, wire_model


def _clean_openai_messages(messages: Sequence[Any]) -> List[Dict[str, Any]]:
    cleaned: List[Dict[str, Any]] = []
    for m in messages:
        d = m.model_dump(exclude_none=True) if isinstance(m, _LiteModel) else dict(m)
        d.pop("_swival_synthetic", None)
        d.pop("provider_specific_fields", None)
        d.pop("function_call", None)
        if "tool_calls" in d and not d["tool_calls"]:
            d.pop("tool_calls", None)
        if d.get("role") == "assistant" and d.get("tool_calls") and "content" not in d:
            d["content"] = None
        cleaned.append(d)
    return cleaned


def _build_openai_payload(
    wire_model: str,
    messages: Sequence[Any],
    stream: bool,
    kwargs: Dict[str, Any],
) -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "model": wire_model,
        "messages": _clean_openai_messages(messages),
        "stream": bool(stream),
    }
    for key in (
        "tools",
        "tool_choice",
        "parallel_tool_calls",
        "max_tokens",
        "max_completion_tokens",
        "temperature",
        "top_p",
        "stop",
        "seed",
        "presence_penalty",
        "frequency_penalty",
        "response_format",
        "reasoning_effort",
        "user",
    ):
        val = kwargs.get(key)
        if val is not None:
            payload[key] = val

    extra_body = kwargs.get("extra_body")
    if isinstance(extra_body, dict):
        for ek, ev in extra_body.items():
            payload[ek] = ev
    return payload


def _parse_json_safe(raw: Any) -> Dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str) and raw.strip():
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            return {"_raw": raw}
    return {}


def _build_anthropic_payload(
    wire_model: str,
    messages: Sequence[Any],
    stream: bool,
    kwargs: Dict[str, Any],
) -> Dict[str, Any]:
    system_blocks: List[Dict[str, Any]] = []
    inject_sys_cache = False
    for pt in kwargs.get("cache_control_injection_points") or ():
        if isinstance(pt, dict) and pt.get("role") == "system":
            inject_sys_cache = True

    anth_msgs: List[Dict[str, Any]] = []
    for raw_m in messages:
        m = raw_m.model_dump(exclude_none=True) if isinstance(raw_m, _LiteModel) else dict(raw_m)
        role = m.get("role")
        content = m.get("content")

        if role == "system":
            if isinstance(content, str) and content:
                blk: Dict[str, Any] = {"type": "text", "text": content}
                if inject_sys_cache:
                    blk["cache_control"] = {"type": "ephemeral"}
                system_blocks.append(blk)
            elif isinstance(content, list):
                for part in content:
                    if isinstance(part, dict) and part.get("type") == "text":
                        system_blocks.append({"type": "text", "text": str(part.get("text", ""))})
            continue

        if role == "tool":
            tr_block = {
                "type": "tool_result",
                "tool_use_id": str(m.get("tool_call_id") or ""),
                "content": str(content if content is not None else ""),
            }
            if anth_msgs and anth_msgs[-1]["role"] == "user" and isinstance(anth_msgs[-1]["content"], list):
                anth_msgs[-1]["content"].append(tr_block)
            else:
                anth_msgs.append({"role": "user", "content": [tr_block]})
            continue

        if role == "assistant":
            blocks: List[Dict[str, Any]] = []
            if isinstance(content, str) and content:
                blocks.append({"type": "text", "text": content})
            elif isinstance(content, list):
                for p in content:
                    if isinstance(p, dict) and p.get("type") == "text" and p.get("text"):
                        blocks.append({"type": "text", "text": str(p["text"])})
            for tc in m.get("tool_calls") or ():
                fn = tc.get("function", {}) if isinstance(tc, dict) else {}
                blocks.append(
                    {
                        "type": "tool_use",
                        "id": str(tc.get("id") or f"toolu_{uuid.uuid4().hex[:16]}"),
                        "name": str(fn.get("name") or ""),
                        "input": _parse_json_safe(fn.get("arguments")),
                    }
                )
            if not blocks:
                blocks.append({"type": "text", "text": " "})
            if anth_msgs and anth_msgs[-1]["role"] == "assistant":
                prev_c = anth_msgs[-1]["content"]
                if isinstance(prev_c, str):
                    anth_msgs[-1]["content"] = [{"type": "text", "text": prev_c}, *blocks]
                else:
                    prev_c.extend(blocks)
            else:
                anth_msgs.append({"role": "assistant", "content": blocks})
            continue

        # Default: user message
        u_blocks: List[Dict[str, Any]] = []
        if isinstance(content, str):
            u_blocks.append({"type": "text", "text": content or " "})
        elif isinstance(content, list):
            for p in content:
                if isinstance(p, dict):
                    if p.get("type") == "text":
                        u_blocks.append({"type": "text", "text": str(p.get("text", ""))})
                    elif p.get("type") == "image_url":
                        url_str = str((p.get("image_url") or {}).get("url") or "")
                        if url_str.startswith("data:") and ";base64," in url_str:
                            header, b64 = url_str.split(";base64,", 1)
                            media_type = header[len("data:") :] or "image/png"
                            u_blocks.append(
                                {
                                    "type": "image",
                                    "source": {"type": "base64", "media_type": media_type, "data": b64},
                                }
                            )
        if not u_blocks:
            u_blocks.append({"type": "text", "text": " "})
        if anth_msgs and anth_msgs[-1]["role"] == "user":
            prev_u = anth_msgs[-1]["content"]
            if isinstance(prev_u, list):
                prev_u.extend(u_blocks)
            else:
                anth_msgs[-1]["content"] = [{"type": "text", "text": str(prev_u)}, *u_blocks]
        else:
            anth_msgs.append({"role": "user", "content": u_blocks})

    payload: Dict[str, Any] = {
        "model": wire_model,
        "messages": anth_msgs,
        "max_tokens": int(kwargs.get("max_tokens") or 4096),
        "stream": bool(stream),
    }
    if system_blocks:
        payload["system"] = system_blocks

    raw_tools = kwargs.get("tools")
    tc_opt = kwargs.get("tool_choice")
    if raw_tools and tc_opt != "none":
        anth_tools: List[Dict[str, Any]] = []
        for t in raw_tools:
            fn = t.get("function", t) if isinstance(t, dict) else {}
            schema = fn.get("parameters") or {"type": "object", "properties": {}}
            anth_tools.append(
                {
                    "name": fn.get("name", ""),
                    "description": fn.get("description", ""),
                    "input_schema": schema,
                }
            )
        payload["tools"] = anth_tools
        if tc_opt == "auto":
            payload["tool_choice"] = {"type": "auto"}
        elif tc_opt in ("required", "any"):
            payload["tool_choice"] = {"type": "any"}
        elif isinstance(tc_opt, dict) and tc_opt.get("type") == "function":
            fn_name = (tc_opt.get("function") or {}).get("name")
            if fn_name:
                payload["tool_choice"] = {"type": "tool", "name": fn_name}

    for k in ("temperature", "top_p"):
        if kwargs.get(k) is not None:
            payload[k] = kwargs[k]
    if kwargs.get("stop") is not None:
        stops = kwargs["stop"]
        payload["stop_sequences"] = [stops] if isinstance(stops, str) else list(stops)

    extra_body = kwargs.get("extra_body")
    if isinstance(extra_body, dict):
        for ek, ev in extra_body.items():
            payload[ek] = ev
    return payload


def _map_anthropic_stop_reason(reason: Optional[str], has_tools: bool = False) -> str:
    if reason == "tool_use" or (reason is None and has_tools):
        return "tool_calls"
    if reason == "max_tokens":
        return "length"
    return "stop"


def _parse_anthropic_json_response(data: Dict[str, Any], wire_model: str) -> ModelResponse:
    text_parts: List[str] = []
    thinking_parts: List[str] = []
    tool_calls: List[ChatCompletionMessageToolCall] = []

    for blk in data.get("content") or ():
        if not isinstance(blk, dict):
            continue
        btype = blk.get("type")
        if btype == "text":
            text_parts.append(str(blk.get("text", "")))
        elif btype == "thinking":
            thinking_parts.append(str(blk.get("thinking", "")))
        elif btype == "tool_use":
            inp = blk.get("input")
            args_str = json.dumps(inp) if not isinstance(inp, str) else inp
            tool_calls.append(
                ChatCompletionMessageToolCall(
                    id=str(blk.get("id") or f"toolu_{uuid.uuid4().hex[:12]}"),
                    type="function",
                    function=Function(name=str(blk.get("name") or ""), arguments=args_str),
                )
            )

    content_val: Optional[str] = "".join(text_parts) if text_parts else (None if tool_calls else "")
    msg_kw: Dict[str, Any] = {
        "role": "assistant",
        "content": content_val,
        "tool_calls": tool_calls or None,
    }
    if thinking_parts:
        msg_kw["reasoning_content"] = "".join(thinking_parts)

    u_raw = data.get("usage") or {}
    in_tok = int(u_raw.get("input_tokens") or 0)
    cache_read = int(u_raw.get("cache_read_input_tokens") or 0)
    cache_create = int(u_raw.get("cache_creation_input_tokens") or 0)
    out_tok = int(u_raw.get("output_tokens") or 0)
    prompt_total = in_tok + cache_read + cache_create

    usage = Usage(
        prompt_tokens=prompt_total,
        completion_tokens=out_tok,
        total_tokens=prompt_total + out_tok,
        cache_read_input_tokens=cache_read,
        cache_creation_input_tokens=cache_create,
    )
    finish_reason = _map_anthropic_stop_reason(data.get("stop_reason"), has_tools=bool(tool_calls))

    return ModelResponse(
        id=data.get("id") or f"msg_{uuid.uuid4().hex[:20]}",
        model=data.get("model") or wire_model,
        choices=[Choices(index=0, message=Message(**msg_kw), finish_reason=finish_reason)],
        usage=usage,
        stream=False,
    )


def _parse_openai_json_response(data: Dict[str, Any], wire_model: str) -> ModelResponse:
    if isinstance(data, dict) and "error" in data and "choices" not in data:
        raise_mapped_http_error(400, json.dumps(data), "openai", wire_model)
    return ModelResponse(
        id=data.get("id"),
        choices=data.get("choices") or [],
        created=data.get("created"),
        model=data.get("model") or wire_model,
        object=data.get("object") or "chat.completion",
        system_fingerprint=data.get("system_fingerprint"),
        usage=data.get("usage"),
        stream=False,
    )


class _AnthropicSSEState:
    def __init__(self, wire_model: str) -> None:
        self.resp_id = f"msg_{uuid.uuid4().hex[:20]}"
        self.model = wire_model
        self.created = int(time.time())
        self.input_tokens = 0
        self.cache_read = 0
        self.cache_create = 0
        self.output_tokens = 0
        self.tool_call_counter = 0
        self.block_to_tc_idx: Dict[int, int] = {}
        self.block_had_initial_input: Set[int] = set()  # type: ignore[name-defined]

    def feed_event(self, event_name: str, data_str: str) -> Optional[ModelResponse]:
        if not data_str or data_str == "[DONE]":
            return None
        payload = json.loads(data_str)
        etype = payload.get("type") or event_name

        if etype == "error":
            raise_mapped_http_error(400, data_str, "anthropic", self.model)

        if etype == "message_start":
            msg = payload.get("message") or {}
            self.resp_id = msg.get("id") or self.resp_id
            self.model = msg.get("model") or self.model
            u = msg.get("usage") or {}
            self.input_tokens = int(u.get("input_tokens") or 0)
            self.cache_read = int(u.get("cache_read_input_tokens") or 0)
            self.cache_create = int(u.get("cache_creation_input_tokens") or 0)
            return ModelResponse(
                id=self.resp_id,
                created=self.created,
                model=self.model,
                choices=[StreamingChoices(index=0, delta=Delta(role="assistant", content=""), finish_reason=None)],
                stream=True,
            )

        if etype == "content_block_start":
            b_idx = int(payload.get("index") or 0)
            blk = payload.get("content_block") or {}
            btype = blk.get("type")
            if btype == "tool_use":
                tc_idx = self.tool_call_counter
                self.tool_call_counter += 1
                self.block_to_tc_idx[b_idx] = tc_idx
                init_inp = blk.get("input")
                init_args = json.dumps(init_inp) if (isinstance(init_inp, dict) and init_inp) else ""
                if init_args:
                    self.block_had_initial_input.add(b_idx)
                tc = ChatCompletionMessageToolCall(
                    index=tc_idx,
                    id=str(blk.get("id") or f"toolu_{tc_idx}"),
                    type="function",
                    function=Function(name=str(blk.get("name") or ""), arguments=init_args),
                )
                return ModelResponse(
                    id=self.resp_id,
                    created=self.created,
                    model=self.model,
                    choices=[StreamingChoices(index=0, delta=Delta(tool_calls=[tc]), finish_reason=None)],
                    stream=True,
                )
            if btype == "text" and blk.get("text"):
                return ModelResponse(
                    id=self.resp_id,
                    created=self.created,
                    model=self.model,
                    choices=[StreamingChoices(index=0, delta=Delta(content=str(blk["text"])), finish_reason=None)],
                    stream=True,
                )
            return None

        if etype == "content_block_delta":
            b_idx = int(payload.get("index") or 0)
            d = payload.get("delta") or {}
            dtype = d.get("type")
            if dtype == "text_delta":
                return ModelResponse(
                    id=self.resp_id,
                    created=self.created,
                    model=self.model,
                    choices=[StreamingChoices(index=0, delta=Delta(content=str(d.get("text", ""))), finish_reason=None)],
                    stream=True,
                )
            if dtype == "thinking_delta":
                return ModelResponse(
                    id=self.resp_id,
                    created=self.created,
                    model=self.model,
                    choices=[
                        StreamingChoices(
                            index=0,
                            delta=Delta(reasoning_content=str(d.get("thinking", ""))),
                            finish_reason=None,
                        )
                    ],
                    stream=True,
                )
            if dtype == "input_json_delta":
                if b_idx in self.block_had_initial_input:
                    return None
                tc_idx = self.block_to_tc_idx.get(b_idx, 0)
                part = str(d.get("partial_json", ""))
                tc = ChatCompletionMessageToolCall(
                    index=tc_idx,
                    id=None,
                    type="function",
                    function=Function(name=None, arguments=part),
                )
                return ModelResponse(
                    id=self.resp_id,
                    created=self.created,
                    model=self.model,
                    choices=[StreamingChoices(index=0, delta=Delta(tool_calls=[tc]), finish_reason=None)],
                    stream=True,
                )
            return None

        if etype == "message_delta":
            d = payload.get("delta") or {}
            u = payload.get("usage") or {}
            if u.get("output_tokens") is not None:
                self.output_tokens = int(u["output_tokens"])
            fin = _map_anthropic_stop_reason(d.get("stop_reason"), has_tools=(self.tool_call_counter > 0))
            prompt_tot = self.input_tokens + self.cache_read + self.cache_create
            usage = Usage(
                prompt_tokens=prompt_tot,
                completion_tokens=self.output_tokens,
                total_tokens=prompt_tot + self.output_tokens,
                cache_read_input_tokens=self.cache_read,
                cache_creation_input_tokens=self.cache_create,
            )
            return ModelResponse(
                id=self.resp_id,
                created=self.created,
                model=self.model,
                choices=[StreamingChoices(index=0, delta=Delta(), finish_reason=fin)],
                usage=usage,
                stream=True,
            )
        return None


def _parse_openai_sse_data(data_str: str, wire_model: str) -> Optional[ModelResponse]:
    s = data_str.strip()
    if not s or s == "[DONE]":
        return None
    payload = json.loads(s)
    if isinstance(payload, dict) and "error" in payload and "choices" not in payload:
        raise_mapped_http_error(400, s, "openai", wire_model)
    return ModelResponse(
        id=payload.get("id"),
        choices=payload.get("choices") or [],
        created=payload.get("created"),
        model=payload.get("model") or wire_model,
        object="chat.completion.chunk",
        system_fingerprint=payload.get("system_fingerprint"),
        usage=payload.get("usage"),
        stream=True,
    )


def _iter_sse_events_from_lines(lines: Iterator[str]) -> Iterator[Tuple[str, str]]:
    event_name = ""
    data_lines: List[str] = []
    for raw_line in lines:
        line = raw_line.rstrip("\r\n")
        if not line:
            if data_lines:
                yield event_name, "\n".join(data_lines)
                event_name = ""
                data_lines = []
            continue
        if line.startswith(":"):
            continue
        if line.startswith("event:"):
            event_name = line[len("event:") :].strip()
        elif line.startswith("data:"):
            data_lines.append(line[len("data:") :].lstrip(" "))
    if data_lines:
        yield event_name, "\n".join(data_lines)


def _prepare_request(
    model: str,
    messages: Sequence[Any],
    stream: bool,
    kwargs: Dict[str, Any],
) -> Tuple[str, str, Dict[str, str], Dict[str, Any], str, float]:
    api_base = kwargs.get("api_base") or kwargs.get("base_url")
    api_key = kwargs.get("api_key")
    custom_prov = kwargs.get("custom_llm_provider")
    protocol, endpoint, resolved_key, wire_model = _resolve_route(model, api_base, api_key, custom_prov)

    headers: Dict[str, str] = {"Content-Type": "application/json"}
    if stream:
        headers["Accept"] = "text/event-stream"

    if protocol == "anthropic":
        if not resolved_key and "127.0.0.1" not in endpoint and "localhost" not in endpoint:
            raise AuthenticationError(
                "Missing ANTHROPIC_API_KEY for Anthropic model call",
                llm_provider="anthropic",
                model=model,
                status_code=401,
            )
        if resolved_key:
            headers["x-api-key"] = resolved_key
        headers["anthropic-version"] = "2023-06-01"
        body = _build_anthropic_payload(wire_model, messages, stream, kwargs)
    else:
        if resolved_key and resolved_key != "none":
            headers["Authorization"] = f"Bearer {resolved_key}"
        body = _build_openai_payload(wire_model, messages, stream, kwargs)

    extra_headers = kwargs.get("extra_headers") or kwargs.get("headers")
    if isinstance(extra_headers, dict):
        for hk, hv in extra_headers.items():
            if hv is not None:
                headers[str(hk)] = str(hv)

    timeout_val = float(kwargs.get("timeout") or 600.0)
    return protocol, endpoint, headers, body, wire_model, timeout_val


def _stream_sync(
    protocol: str,
    endpoint: str,
    headers: Dict[str, str],
    body: Dict[str, Any],
    wire_model: str,
    timeout_val: float,
    orig_model: str,
) -> Iterator[ModelResponse]:
    try:
        with httpx.Client(timeout=timeout_val, follow_redirects=True) as client:
            with client.stream("POST", endpoint, headers=headers, json=body) as resp:
                if resp.status_code >= 400:
                    err_bytes = resp.read()
                    raise_mapped_http_error(
                        resp.status_code,
                        err_bytes.decode("utf-8", errors="replace"),
                        protocol,
                        orig_model,
                        response=resp,
                    )
                ctype = (resp.headers.get("content-type") or "").lower()
                if "application/json" in ctype and "event-stream" not in ctype:
                    raw_body = resp.read().decode("utf-8", errors="replace")
                    data = json.loads(raw_body)
                    full = (
                        _parse_anthropic_json_response(data, wire_model)
                        if protocol == "anthropic"
                        else _parse_openai_json_response(data, wire_model)
                    )
                    ch0 = full.choices[0]
                    msg = ch0.message
                    yield ModelResponse(
                        id=full.id,
                        created=full.created,
                        model=full.model,
                        choices=[
                            StreamingChoices(
                                index=0,
                                delta=Delta(
                                    role=msg.role,
                                    content=msg.content,
                                    tool_calls=msg.tool_calls,
                                    reasoning_content=getattr(msg, "reasoning_content", None),
                                ),
                                finish_reason=ch0.finish_reason,
                            )
                        ],
                        usage=full.usage,
                        stream=True,
                    )
                    return

                anth_state = _AnthropicSSEState(wire_model) if protocol == "anthropic" else None
                for ev_name, data_str in _iter_sse_events_from_lines(resp.iter_lines()):
                    if data_str.strip() == "[DONE]":
                        break
                    chunk = (
                        anth_state.feed_event(ev_name, data_str)
                        if anth_state is not None
                        else _parse_openai_sse_data(data_str, wire_model)
                    )
                    if chunk is not None:
                        yield chunk
    except httpx.TimeoutException as exc:
        raise Timeout(str(exc), llm_provider=protocol, model=orig_model, status_code=408) from exc
    except httpx.HTTPError as exc:
        raise APIConnectionError(str(exc), llm_provider=protocol, model=orig_model, status_code=500) from exc


def completion(
    model: str,
    messages: Sequence[Any] = (),
    *,
    stream: bool = False,
    **kwargs: Any,
) -> Union[ModelResponse, Iterator[ModelResponse]]:
    protocol, endpoint, headers, body, wire_model, timeout_val = _prepare_request(
        model, messages, stream, kwargs
    )
    if stream:
        return _stream_sync(protocol, endpoint, headers, body, wire_model, timeout_val, model)

    try:
        with httpx.Client(timeout=timeout_val, follow_redirects=True) as client:
            resp = client.post(endpoint, headers=headers, json=body)
    except httpx.TimeoutException as exc:
        raise Timeout(str(exc), llm_provider=protocol, model=model, status_code=408) from exc
    except httpx.HTTPError as exc:
        raise APIConnectionError(str(exc), llm_provider=protocol, model=model, status_code=500) from exc

    if resp.status_code >= 400:
        raise_mapped_http_error(resp.status_code, resp.text, protocol, model, response=resp)

    ctype = (resp.headers.get("content-type") or "").lower()
    text_body = resp.text
    if "text/event-stream" in ctype or text_body.lstrip().startswith(("data:", "event:")):
        anth_state = _AnthropicSSEState(wire_model) if protocol == "anthropic" else None
        sse_chunks: List[ModelResponse] = []
        for ev_name, data_str in _iter_sse_events_from_lines(iter(text_body.splitlines())):
            if data_str.strip() == "[DONE]":
                break
            ch = (
                anth_state.feed_event(ev_name, data_str)
                if anth_state is not None
                else _parse_openai_sse_data(data_str, wire_model)
            )
            if ch is not None:
                sse_chunks.append(ch)
        return stream_chunk_builder(sse_chunks, messages=messages)

    data = resp.json()
    if protocol == "anthropic":
        return _parse_anthropic_json_response(data, wire_model)
    return _parse_openai_json_response(data, wire_model)


async def _stream_async(
    protocol: str,
    endpoint: str,
    headers: Dict[str, str],
    body: Dict[str, Any],
    wire_model: str,
    timeout_val: float,
    orig_model: str,
) -> AsyncIterator[ModelResponse]:
    try:
        async with httpx.AsyncClient(timeout=timeout_val, follow_redirects=True) as client:
            async with client.stream("POST", endpoint, headers=headers, json=body) as resp:
                if resp.status_code >= 400:
                    err_bytes = await resp.aread()
                    raise_mapped_http_error(
                        resp.status_code,
                        err_bytes.decode("utf-8", errors="replace"),
                        protocol,
                        orig_model,
                        response=resp,
                    )
                anth_state = _AnthropicSSEState(wire_model) if protocol == "anthropic" else None
                event_name = ""
                data_lines: List[str] = []

                async def _flush_event(ev: str, dlines: List[str]) -> Optional[ModelResponse]:
                    d_str = "\n".join(dlines)
                    if d_str.strip() == "[DONE]":
                        return None
                    return (
                        anth_state.feed_event(ev, d_str)
                        if anth_state is not None
                        else _parse_openai_sse_data(d_str, wire_model)
                    )

                async for raw_line in resp.aiter_lines():
                    line = raw_line.rstrip("\r\n")
                    if not line:
                        if data_lines:
                            if "\n".join(data_lines).strip() == "[DONE]":
                                data_lines = []
                                break
                            ch = await _flush_event(event_name, data_lines)
                            event_name = ""
                            data_lines = []
                            if ch is not None:
                                yield ch
                        continue
                    if line.startswith(":"):
                        continue
                    if line.startswith("event:"):
                        event_name = line[len("event:") :].strip()
                    elif line.startswith("data:"):
                        data_lines.append(line[len("data:") :].lstrip(" "))
                if data_lines and "\n".join(data_lines).strip() != "[DONE]":
                    ch = await _flush_event(event_name, data_lines)
                    if ch is not None:
                        yield ch
    except httpx.TimeoutException as exc:
        raise Timeout(str(exc), llm_provider=protocol, model=orig_model, status_code=408) from exc
    except httpx.HTTPError as exc:
        raise APIConnectionError(str(exc), llm_provider=protocol, model=orig_model, status_code=500) from exc


async def acompletion(
    model: str,
    messages: Sequence[Any] = (),
    *,
    stream: bool = False,
    **kwargs: Any,
) -> Union[ModelResponse, AsyncIterator[ModelResponse]]:
    protocol, endpoint, headers, body, wire_model, timeout_val = _prepare_request(
        model, messages, stream, kwargs
    )
    if stream:
        return _stream_async(protocol, endpoint, headers, body, wire_model, timeout_val, model)

    try:
        async with httpx.AsyncClient(timeout=timeout_val, follow_redirects=True) as client:
            resp = await client.post(endpoint, headers=headers, json=body)
    except httpx.TimeoutException as exc:
        raise Timeout(str(exc), llm_provider=protocol, model=model, status_code=408) from exc
    except httpx.HTTPError as exc:
        raise APIConnectionError(str(exc), llm_provider=protocol, model=model, status_code=500) from exc

    if resp.status_code >= 400:
        raise_mapped_http_error(resp.status_code, resp.text, protocol, model, response=resp)

    ctype = (resp.headers.get("content-type") or "").lower()
    text_body = resp.text
    if "text/event-stream" in ctype or text_body.lstrip().startswith(("data:", "event:")):
        anth_state = _AnthropicSSEState(wire_model) if protocol == "anthropic" else None
        sse_chunks: List[ModelResponse] = []
        for ev_name, data_str in _iter_sse_events_from_lines(iter(text_body.splitlines())):
            if data_str.strip() == "[DONE]":
                break
            ch = (
                anth_state.feed_event(ev_name, data_str)
                if anth_state is not None
                else _parse_openai_sse_data(data_str, wire_model)
            )
            if ch is not None:
                sse_chunks.append(ch)
        return stream_chunk_builder(sse_chunks, messages=messages)

    data = resp.json()
    if protocol == "anthropic":
        return _parse_anthropic_json_response(data, wire_model)
    return _parse_openai_json_response(data, wire_model)
