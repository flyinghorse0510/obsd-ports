"""
litellm.utils -- Model metadata registry, capabilities, server discovery, and
`stream_chunk_builder` reassembly for OpenBSD WASM64.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence
import httpx
import tiktoken

from .types.utils import (
    ChatCompletionMessageToolCall,
    Choices,
    Function,
    Message,
    ModelResponse,
    Usage,
)


def _entry(
    provider: str,
    max_input: int,
    max_output: int = 16384,
    *,
    mode: str = "chat",
    tools: bool = True,
    vision: bool = True,
    caching: bool = False,
    in_cost: float = 0.0,
    out_cost: float = 0.0,
) -> Dict[str, Any]:
    return {
        "litellm_provider": provider,
        "mode": mode,
        "max_tokens": max_output,
        "max_input_tokens": max_input,
        "max_output_tokens": max_output,
        "supports_function_calling": tools,
        "supports_vision": vision,
        "supports_prompt_caching": caching,
        "input_cost_per_token": in_cost / 1_000_000.0,
        "output_cost_per_token": out_cost / 1_000_000.0,
    }


model_cost: Dict[str, Dict[str, Any]] = {
    # OpenAI & ChatGPT
    "gpt-4o": _entry("openai", 128000, 16384, caching=True, in_cost=2.5, out_cost=10.0),
    "gpt-4o-mini": _entry("openai", 128000, 16384, caching=True, in_cost=0.15, out_cost=0.6),
    "gpt-4.1": _entry("openai", 1047576, 32768, caching=True, in_cost=2.0, out_cost=8.0),
    "gpt-4.1-mini": _entry("openai", 1047576, 32768, caching=True, in_cost=0.4, out_cost=1.6),
    "gpt-4.1-nano": _entry("openai", 1047576, 32768, caching=True, in_cost=0.1, out_cost=0.4),
    "gpt-5": _entry("openai", 400000, 128000, caching=True, in_cost=1.25, out_cost=10.0),
    "gpt-5-mini": _entry("openai", 400000, 128000, caching=True, in_cost=0.25, out_cost=2.0),
    "o3": _entry("openai", 200000, 100000, caching=True, in_cost=2.0, out_cost=8.0),
    "o4-mini": _entry("openai", 200000, 100000, caching=True, in_cost=1.1, out_cost=4.4),
    "chatgpt/gpt-5": _entry("chatgpt", 400000, 128000, mode="responses", caching=True),
    "chatgpt/gpt-5-mini": _entry("chatgpt", 400000, 128000, mode="responses", caching=True),
    "chatgpt/gpt-5.5": _entry("chatgpt", 400000, 128000, mode="responses", caching=True),
    # Anthropic Claude
    "claude-sonnet-4-6": _entry("anthropic", 200000, 64000, caching=True, in_cost=3.0, out_cost=15.0),
    "claude-opus-4-6": _entry("anthropic", 200000, 64000, caching=True, in_cost=15.0, out_cost=75.0),
    "claude-sonnet-4-5": _entry("anthropic", 200000, 64000, caching=True, in_cost=3.0, out_cost=15.0),
    "claude-sonnet-4-5-20250929": _entry("anthropic", 200000, 64000, caching=True, in_cost=3.0, out_cost=15.0),
    "claude-opus-4-5": _entry("anthropic", 200000, 32000, caching=True, in_cost=15.0, out_cost=75.0),
    "claude-haiku-4-5": _entry("anthropic", 200000, 64000, caching=True, in_cost=1.0, out_cost=5.0),
    "claude-sonnet-4-20250514": _entry("anthropic", 200000, 64000, caching=True, in_cost=3.0, out_cost=15.0),
    "claude-3-7-sonnet-latest": _entry("anthropic", 200000, 64000, caching=True, in_cost=3.0, out_cost=15.0),
    "claude-3-5-sonnet-latest": _entry("anthropic", 200000, 8192, caching=True, in_cost=3.0, out_cost=15.0),
    "claude-3-5-haiku-latest": _entry("anthropic", 200000, 8192, caching=True, in_cost=0.8, out_cost=4.0),
    # Google Gemini
    "gemini/gemini-2.5-pro": _entry("gemini", 1048576, 65536, caching=True, in_cost=1.25, out_cost=10.0),
    "gemini/gemini-2.5-flash": _entry("gemini", 1048576, 65536, caching=True, in_cost=0.3, out_cost=2.5),
    "gemini/gemini-2.0-flash": _entry("gemini", 1048576, 8192, caching=True, in_cost=0.1, out_cost=0.4),
    "gemini/gemini-3.1-pro": _entry("gemini", 1048576, 65536, caching=True, in_cost=1.25, out_cost=10.0),
    # DeepSeek / Groq / xAI / Mistral
    "deepseek/deepseek-chat": _entry("deepseek", 128000, 8192, vision=False, caching=True, in_cost=0.27, out_cost=1.1),
    "deepseek/deepseek-reasoner": _entry("deepseek", 128000, 32768, vision=False, caching=True, in_cost=0.55, out_cost=2.19),
    "xai/grok-3": _entry("xai", 131072, 16384, vision=True, in_cost=3.0, out_cost=15.0),
    "mistral/mistral-large-latest": _entry("mistral", 128000, 16384, vision=False, in_cost=2.0, out_cost=6.0),
}

# Populate prefixed aliases (`openai/gpt-4o`, `anthropic/claude-*`, `openrouter/...`)
for _k, _v in list(model_cost.items()):
    if "/" not in _k:
        _prov = _v["litellm_provider"]
        model_cost.setdefault(f"{_prov}/{_k}", dict(_v))
        model_cost.setdefault(f"openrouter/{_prov}/{_k}", {**_v, "litellm_provider": "openrouter"})


def register_model(model_cost_dict: Dict[str, Dict[str, Any]]) -> None:
    if isinstance(model_cost_dict, dict):
        for k, v in model_cost_dict.items():
            if isinstance(v, dict):
                model_cost[k] = dict(v)


def _lookup_model_entry(model: str, custom_llm_provider: Optional[str] = None) -> Optional[Dict[str, Any]]:
    if not model:
        return None
    candidates = [model]
    if custom_llm_provider and not model.startswith(f"{custom_llm_provider}/"):
        candidates.insert(0, f"{custom_llm_provider}/{model}")
    if "/" in model:
        _, rest = model.split("/", 1)
        candidates.append(rest)
        if "/" in rest:
            candidates.append(rest.split("/", 1)[1])
    for cand in candidates:
        hit = model_cost.get(cand)
        if hit is not None:
            return dict(hit, key=cand)
    return None


def get_model_info(model: str, custom_llm_provider: Optional[str] = None) -> Dict[str, Any]:
    hit = _lookup_model_entry(model, custom_llm_provider=custom_llm_provider)
    if hit is not None:
        return hit
    raise ValueError(f"Model {model!r} is not registered in litellm.model_cost")


def get_max_tokens(model: str) -> Optional[int]:
    hit = _lookup_model_entry(model)
    if hit is None:
        return None
    return hit.get("max_output_tokens") or hit.get("max_tokens") or hit.get("max_input_tokens")


def supports_vision(model: str, custom_llm_provider: Optional[str] = None) -> bool:
    hit = _lookup_model_entry(model, custom_llm_provider=custom_llm_provider)
    if hit is not None:
        return bool(hit.get("supports_vision", False))
    low = (model or "").lower()
    return any(tag in low for tag in ("gpt-4o", "gpt-4.1", "gpt-5", "claude-3", "claude-sonnet-4", "claude-opus-4", "gemini", "vl", "vision"))


def supports_function_calling(model: str, custom_llm_provider: Optional[str] = None) -> bool:
    hit = _lookup_model_entry(model, custom_llm_provider=custom_llm_provider)
    if hit is not None:
        return bool(hit.get("supports_function_calling", True))
    return True


def supports_prompt_caching(model: str, custom_llm_provider: Optional[str] = None) -> bool:
    hit = _lookup_model_entry(model, custom_llm_provider=custom_llm_provider)
    if hit is not None:
        return bool(hit.get("supports_prompt_caching", False))
    low = (model or "").lower()
    return "claude" in low or "anthropic" in low or "gemini" in low


def get_valid_models(
    check_provider_endpoint: bool = False,
    custom_llm_provider: Optional[str] = None,
    api_base: Optional[str] = None,
    api_key: Optional[str] = None,
) -> List[str]:
    if check_provider_endpoint and api_base:
        base = api_base.rstrip("/")
        url = f"{base}/models" if base.endswith(("/v1", "/v4", "/openai")) else f"{base}/v1/models"
        headers: Dict[str, str] = {}
        if api_key and api_key != "none":
            headers["Authorization"] = f"Bearer {api_key}"
        try:
            with httpx.Client(timeout=5.0) as client:
                resp = client.get(url, headers=headers)
                if resp.status_code == 200:
                    payload = resp.json()
                    items = payload.get("data") if isinstance(payload, dict) else payload
                    if isinstance(items, list):
                        ids = [str(it["id"]) for it in items if isinstance(it, dict) and it.get("id")]
                        if ids:
                            return ids
        except Exception:
            return []
    if custom_llm_provider:
        prefix = f"{custom_llm_provider}/"
        return sorted(k[len(prefix) :] for k in model_cost if k.startswith(prefix))
    return sorted(model_cost.keys())


def _count_text_tokens(text: str) -> int:
    if not text:
        return 0
    try:
        return len(tiktoken.get_encoding("cl100k_base").encode_ordinary(text))
    except Exception:
        return max(1, len(text) // 4)


def _estimate_messages_tokens(messages: Optional[Sequence[Any]]) -> int:
    if not messages:
        return 0
    total = 0
    for m in messages:
        total += 4
        content = m.get("content") if isinstance(m, dict) else getattr(m, "content", None)
        if isinstance(content, str):
            total += _count_text_tokens(content)
        elif isinstance(content, list):
            for part in content:
                if isinstance(part, dict) and part.get("type") == "text":
                    total += _count_text_tokens(str(part.get("text", "")))
        tcs = m.get("tool_calls") if isinstance(m, dict) else getattr(m, "tool_calls", None)
        if tcs:
            for tc in tcs:
                fn = tc.get("function") if isinstance(tc, dict) else getattr(tc, "function", None)
                if fn:
                    nm = fn.get("name") if isinstance(fn, dict) else getattr(fn, "name", "")
                    ar = fn.get("arguments") if isinstance(fn, dict) else getattr(fn, "arguments", "")
                    total += _count_text_tokens(str(nm or "")) + _count_text_tokens(str(ar or ""))
    return total


def stream_chunk_builder(
    chunks: Sequence[Any],
    messages: Optional[Sequence[Any]] = None,
) -> ModelResponse:
    """Reassemble streamed `ModelResponse` chunks into a complete `ModelResponse`."""
    resp_id: Optional[str] = None
    model_name: str = ""
    created_ts: Optional[int] = None
    sys_fp: Optional[str] = None
    final_usage: Optional[Usage] = None

    # Per-choice state keyed by choice.index
    by_choice: Dict[int, Dict[str, Any]] = {}

    for chunk in chunks or ():
        if chunk is None:
            continue
        cid = chunk.get("id") if isinstance(chunk, dict) else getattr(chunk, "id", None)
        if cid and not resp_id:
            resp_id = cid
        cmod = chunk.get("model") if isinstance(chunk, dict) else getattr(chunk, "model", None)
        if cmod:
            model_name = cmod
        ccreated = chunk.get("created") if isinstance(chunk, dict) else getattr(chunk, "created", None)
        if ccreated is not None and created_ts is None:
            created_ts = int(ccreated)
        cfp = chunk.get("system_fingerprint") if isinstance(chunk, dict) else getattr(chunk, "system_fingerprint", None)
        if cfp:
            sys_fp = cfp

        u = chunk.get("usage") if isinstance(chunk, dict) else getattr(chunk, "usage", None)
        if u:
            final_usage = u if isinstance(u, Usage) else Usage(**dict(u))

        c_choices = chunk.get("choices") if isinstance(chunk, dict) else getattr(chunk, "choices", None)
        if not c_choices:
            continue

        for ch in c_choices:
            c_idx = int((ch.get("index") if isinstance(ch, dict) else getattr(ch, "index", 0)) or 0)
            state = by_choice.setdefault(
                c_idx,
                {
                    "role": "assistant",
                    "content_parts": [],
                    "reasoning_parts": [],
                    "tool_calls": {},  # tc_index -> dict
                    "finish_reason": None,
                },
            )
            fin = ch.get("finish_reason") if isinstance(ch, dict) else getattr(ch, "finish_reason", None)
            if fin:
                state["finish_reason"] = fin

            delta = ch.get("delta") if isinstance(ch, dict) else getattr(ch, "delta", None)
            if delta is None:
                continue

            d_role = delta.get("role") if isinstance(delta, dict) else getattr(delta, "role", None)
            if d_role:
                state["role"] = d_role

            d_content = delta.get("content") if isinstance(delta, dict) else getattr(delta, "content", None)
            if d_content:
                state["content_parts"].append(str(d_content))

            d_rc = delta.get("reasoning_content") if isinstance(delta, dict) else getattr(delta, "reasoning_content", None)
            if not d_rc:
                d_rc = delta.get("reasoning") if isinstance(delta, dict) else getattr(delta, "reasoning", None)
            if d_rc:
                state["reasoning_parts"].append(str(d_rc))

            d_tcs = delta.get("tool_calls") if isinstance(delta, dict) else getattr(delta, "tool_calls", None)
            if d_tcs:
                for pos, tc in enumerate(d_tcs):
                    raw_idx = tc.get("index") if isinstance(tc, dict) else getattr(tc, "index", None)
                    tc_idx = int(raw_idx) if raw_idx is not None else pos
                    slot = state["tool_calls"].setdefault(
                        tc_idx,
                        {
                            "id": None,
                            "type": "function",
                            "name_parts": [],
                            "arg_parts": [],
                            "extra_content": None,
                        },
                    )
                    tc_id = tc.get("id") if isinstance(tc, dict) else getattr(tc, "id", None)
                    if tc_id:
                        slot["id"] = tc_id
                    tc_type = tc.get("type") if isinstance(tc, dict) else getattr(tc, "type", None)
                    if tc_type:
                        slot["type"] = tc_type
                    tc_extra = tc.get("extra_content") if isinstance(tc, dict) else getattr(tc, "extra_content", None)
                    if tc_extra is not None:
                        slot["extra_content"] = tc_extra

                    fn = tc.get("function") if isinstance(tc, dict) else getattr(tc, "function", None)
                    if fn is not None:
                        fn_name = fn.get("name") if isinstance(fn, dict) else getattr(fn, "name", None)
                        if fn_name:
                            slot["name_parts"].append(str(fn_name))
                        fn_args = fn.get("arguments") if isinstance(fn, dict) else getattr(fn, "arguments", None)
                        if fn_args:
                            slot["arg_parts"].append(str(fn_args))

    assembled_choices: List[Choices] = []
    comp_text_for_est: List[str] = []

    if not by_choice:
        assembled_choices.append(Choices(index=0, message=Message(content="", role="assistant"), finish_reason="stop"))
    else:
        for c_idx in sorted(by_choice.keys()):
            st = by_choice[c_idx]
            content_str: Optional[str] = "".join(st["content_parts"]) if st["content_parts"] else None
            reasoning_str: Optional[str] = "".join(st["reasoning_parts"]) if st["reasoning_parts"] else None
            if content_str:
                comp_text_for_est.append(content_str)
            if reasoning_str:
                comp_text_for_est.append(reasoning_str)

            built_tcs: Optional[List[ChatCompletionMessageToolCall]] = None
            if st["tool_calls"]:
                built_tcs = []
                for idx_k in sorted(st["tool_calls"].keys()):
                    slot = st["tool_calls"][idx_k]
                    nm = "".join(slot["name_parts"])
                    args_s = "".join(slot["arg_parts"])
                    comp_text_for_est.append(nm + args_s)
                    tc_kw: Dict[str, Any] = {
                        "id": slot["id"] or f"call_{idx_k}",
                        "type": slot["type"] or "function",
                        "function": Function(name=nm, arguments=args_s),
                    }
                    if slot["extra_content"] is not None:
                        tc_kw["extra_content"] = slot["extra_content"]
                    built_tcs.append(ChatCompletionMessageToolCall(**tc_kw))

            if content_str is None and not built_tcs:
                content_str = ""

            msg_kw: Dict[str, Any] = {
                "role": st["role"] or "assistant",
                "content": content_str,
                "tool_calls": built_tcs,
            }
            if reasoning_str is not None:
                msg_kw["reasoning_content"] = reasoning_str

            fin_reason = st["finish_reason"] or ("tool_calls" if built_tcs else "stop")
            assembled_choices.append(
                Choices(index=c_idx, message=Message(**msg_kw), finish_reason=fin_reason)
            )

    if final_usage is None:
        p_tok = _estimate_messages_tokens(messages)
        c_tok = _count_text_tokens(" ".join(comp_text_for_est))
        final_usage = Usage(prompt_tokens=p_tok, completion_tokens=c_tok, total_tokens=p_tok + c_tok)

    return ModelResponse(
        id=resp_id,
        choices=assembled_choices,
        created=created_ts,
        model=model_name,
        object="chat.completion",
        system_fingerprint=sys_fp,
        usage=final_usage,
        stream=False,
    )
