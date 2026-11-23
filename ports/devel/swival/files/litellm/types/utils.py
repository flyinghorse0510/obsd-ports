"""
litellm.types.utils -- OpenAI / LiteLLM Pydantic-compatible response models.

Note: `_LiteModel` deliberately does NOT subclass `dict` so `isinstance(obj, dict)`
is `False` (matching Pydantic `BaseModel` expectations in `swival/agent.py`), while
providing full attribute access, dict subscripting/mapping helpers, and recursive
`.model_dump(exclude_none=...)` / `.dict()` / `.json()` serialization.
"""
from __future__ import annotations

import json
import time
import uuid
from typing import Any, Dict, Iterator, List, Optional


def _dump_value(val: Any, *, exclude_none: bool = False) -> Any:
    if isinstance(val, _LiteModel):
        return val.model_dump(exclude_none=exclude_none)
    if isinstance(val, list):
        return [_dump_value(item, exclude_none=exclude_none) for item in val]
    if isinstance(val, tuple):
        return [_dump_value(item, exclude_none=exclude_none) for item in val]
    if isinstance(val, dict):
        out: Dict[str, Any] = {}
        for k, v in val.items():
            if exclude_none and v is None:
                continue
            out[k] = _dump_value(v, exclude_none=exclude_none)
        return out
    return val


class _LiteModel:
    def __init__(self, **kwargs: Any) -> None:
        for k, v in kwargs.items():
            setattr(self, k, v)

    @classmethod
    def model_construct(cls, _fields_set: Any = None, **values: Any) -> "_LiteModel":
        del _fields_set
        return cls(**values)

    def __getitem__(self, key: str) -> Any:
        try:
            return getattr(self, key)
        except AttributeError as exc:
            raise KeyError(key) from exc

    def __setitem__(self, key: str, value: Any) -> None:
        setattr(self, key, value)

    def __contains__(self, key: object) -> bool:
        return isinstance(key, str) and hasattr(self, key)

    def get(self, key: str, default: Any = None) -> Any:
        return getattr(self, key, default)

    def keys(self) -> Iterator[str]:
        return iter(self.__dict__.keys())

    def items(self) -> Iterator[tuple[str, Any]]:
        return iter(self.__dict__.items())

    def values(self) -> Iterator[Any]:
        return iter(self.__dict__.values())

    def model_dump(self, *, exclude_none: bool = False, **kwargs: Any) -> Dict[str, Any]:
        del kwargs
        out: Dict[str, Any] = {}
        for k, v in self.__dict__.items():
            if k.startswith("_"):
                continue
            if exclude_none and v is None:
                continue
            out[k] = _dump_value(v, exclude_none=exclude_none)
        return out

    def dict(self, *, exclude_none: bool = False, **kwargs: Any) -> Dict[str, Any]:
        return self.model_dump(exclude_none=exclude_none, **kwargs)

    def model_dump_json(self, *, exclude_none: bool = False, **kwargs: Any) -> str:
        del kwargs
        return json.dumps(self.model_dump(exclude_none=exclude_none))

    def json(self, *, exclude_none: bool = False, **kwargs: Any) -> str:
        return self.model_dump_json(exclude_none=exclude_none, **kwargs)

    def __repr__(self) -> str:
        fields = ", ".join(f"{k}={v!r}" for k, v in self.__dict__.items() if not k.startswith("_"))
        return f"{self.__class__.__name__}({fields})"


class Function(_LiteModel):
    def __init__(self, name: Optional[str] = None, arguments: str = "", **kwargs: Any) -> None:
        super().__init__(name=name, arguments=arguments if arguments is not None else "", **kwargs)


class ChatCompletionMessageToolCall(_LiteModel):
    def __init__(
        self,
        id: Optional[str] = None,
        type: str = "function",
        function: Optional[Function | Dict[str, Any]] = None,
        index: Optional[int] = None,
        **kwargs: Any,
    ) -> None:
        if isinstance(function, dict):
            fn_obj = Function(
                name=function.get("name"),
                arguments=function.get("arguments", ""),
                **{k: v for k, v in function.items() if k not in ("name", "arguments")},
            )
        elif isinstance(function, Function):
            fn_obj = function
        elif function is None:
            fn_obj = Function()
        else:
            fn_obj = Function(
                name=getattr(function, "name", None),
                arguments=getattr(function, "arguments", ""),
            )
        init_kw: Dict[str, Any] = {
            "id": id,
            "type": type or "function",
            "function": fn_obj,
        }
        if index is not None:
            init_kw["index"] = index
        init_kw.update(kwargs)
        super().__init__(**init_kw)


def _coerce_tool_calls(raw_tcs: Any) -> Optional[List[ChatCompletionMessageToolCall]]:
    if not raw_tcs:
        return None
    out: List[ChatCompletionMessageToolCall] = []
    for tc in raw_tcs:
        if isinstance(tc, ChatCompletionMessageToolCall):
            out.append(tc)
        elif isinstance(tc, dict):
            out.append(ChatCompletionMessageToolCall(**tc))
        else:
            fn = getattr(tc, "function", None)
            out.append(
                ChatCompletionMessageToolCall(
                    id=getattr(tc, "id", None),
                    type=getattr(tc, "type", "function"),
                    function=Function(
                        name=getattr(fn, "name", None) if fn else None,
                        arguments=getattr(fn, "arguments", "") if fn else "",
                    ),
                    index=getattr(tc, "index", None),
                )
            )
    return out


class Message(_LiteModel):
    def __init__(
        self,
        content: Optional[str] = None,
        role: str = "assistant",
        tool_calls: Optional[List[Any]] = None,
        function_call: Optional[Any] = None,
        reasoning_content: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        coerced_tcs = _coerce_tool_calls(tool_calls)
        init_kw: Dict[str, Any] = {
            "role": role or "assistant",
            "content": content,
            "tool_calls": coerced_tcs,
            "function_call": function_call,
        }
        if reasoning_content is not None:
            init_kw["reasoning_content"] = reasoning_content
        init_kw.update(kwargs)
        super().__init__(**init_kw)


class Delta(_LiteModel):
    def __init__(
        self,
        content: Optional[str] = None,
        role: Optional[str] = None,
        tool_calls: Optional[List[Any]] = None,
        function_call: Optional[Any] = None,
        reasoning_content: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        coerced_tcs = _coerce_tool_calls(tool_calls)
        init_kw: Dict[str, Any] = {
            "content": content,
            "role": role,
            "tool_calls": coerced_tcs,
            "function_call": function_call,
        }
        if reasoning_content is not None:
            init_kw["reasoning_content"] = reasoning_content
        init_kw.update(kwargs)
        super().__init__(**init_kw)


class Choices(_LiteModel):
    def __init__(
        self,
        finish_reason: Optional[str] = "stop",
        index: int = 0,
        message: Optional[Message | Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> None:
        if isinstance(message, dict):
            msg_obj = Message(**message)
        elif isinstance(message, Message):
            msg_obj = message
        elif message is None:
            msg_obj = Message()
        else:
            msg_obj = Message(
                content=getattr(message, "content", None),
                role=getattr(message, "role", "assistant"),
                tool_calls=getattr(message, "tool_calls", None),
                reasoning_content=getattr(message, "reasoning_content", None),
            )
        super().__init__(finish_reason=finish_reason, index=index, message=msg_obj, **kwargs)


class StreamingChoices(_LiteModel):
    def __init__(
        self,
        finish_reason: Optional[str] = None,
        index: int = 0,
        delta: Optional[Delta | Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> None:
        if isinstance(delta, dict):
            delta_obj = Delta(**delta)
        elif isinstance(delta, Delta):
            delta_obj = delta
        elif delta is None:
            delta_obj = Delta()
        else:
            delta_obj = Delta(
                content=getattr(delta, "content", None),
                role=getattr(delta, "role", None),
                tool_calls=getattr(delta, "tool_calls", None),
                reasoning_content=getattr(delta, "reasoning_content", None),
            )
        super().__init__(finish_reason=finish_reason, index=index, delta=delta_obj, **kwargs)


class PromptTokensDetailsWrapper(_LiteModel):
    def __init__(self, cached_tokens: int = 0, **kwargs: Any) -> None:
        super().__init__(cached_tokens=int(cached_tokens or 0), **kwargs)


class CompletionTokensDetailsWrapper(_LiteModel):
    def __init__(self, reasoning_tokens: int = 0, **kwargs: Any) -> None:
        super().__init__(reasoning_tokens=int(reasoning_tokens or 0), **kwargs)


class Usage(_LiteModel):
    def __init__(
        self,
        prompt_tokens: int = 0,
        completion_tokens: int = 0,
        total_tokens: Optional[int] = None,
        prompt_tokens_details: Optional[Any] = None,
        completion_tokens_details: Optional[Any] = None,
        cache_creation_input_tokens: int = 0,
        cache_read_input_tokens: int = 0,
        **kwargs: Any,
    ) -> None:
        pt = int(prompt_tokens or 0)
        ct = int(completion_tokens or 0)
        tt = int(total_tokens) if total_tokens is not None else (pt + ct)
        if isinstance(prompt_tokens_details, dict):
            ptd = PromptTokensDetailsWrapper(**prompt_tokens_details)
        elif isinstance(prompt_tokens_details, PromptTokensDetailsWrapper):
            ptd = prompt_tokens_details
        elif cache_read_input_tokens:
            ptd = PromptTokensDetailsWrapper(cached_tokens=int(cache_read_input_tokens))
        else:
            ptd = PromptTokensDetailsWrapper(cached_tokens=0)

        if isinstance(completion_tokens_details, dict):
            ctd = CompletionTokensDetailsWrapper(**completion_tokens_details)
        elif isinstance(completion_tokens_details, CompletionTokensDetailsWrapper):
            ctd = completion_tokens_details
        else:
            ctd = CompletionTokensDetailsWrapper(reasoning_tokens=0)

        super().__init__(
            prompt_tokens=pt,
            completion_tokens=ct,
            total_tokens=tt,
            prompt_tokens_details=ptd,
            completion_tokens_details=ctd,
            cache_creation_input_tokens=int(cache_creation_input_tokens or 0),
            cache_read_input_tokens=int(cache_read_input_tokens or 0),
            **kwargs,
        )


class ModelResponse(_LiteModel):
    def __init__(
        self,
        id: Optional[str] = None,
        choices: Optional[List[Any]] = None,
        created: Optional[int] = None,
        model: Optional[str] = None,
        object: Optional[str] = None,
        system_fingerprint: Optional[str] = None,
        usage: Optional[Usage | Dict[str, Any]] = None,
        stream: bool = False,
        **kwargs: Any,
    ) -> None:
        resp_id = id or f"chatcmpl-{uuid.uuid4().hex[:24]}"
        created_ts = int(created) if created is not None else int(time.time())
        obj_kind = object or ("chat.completion.chunk" if stream else "chat.completion")

        parsed_choices: List[Any] = []
        for idx, ch in enumerate(choices or []):
            if isinstance(ch, (Choices, StreamingChoices)):
                parsed_choices.append(ch)
            elif isinstance(ch, dict):
                if stream or "delta" in ch:
                    parsed_choices.append(StreamingChoices(**ch))
                else:
                    parsed_choices.append(Choices(**ch))
            else:
                parsed_choices.append(ch)
        if not parsed_choices and not stream:
            parsed_choices.append(Choices(index=0, message=Message(content=""), finish_reason="stop"))

        if isinstance(usage, dict):
            usage_obj: Optional[Usage] = Usage(**usage)
        elif isinstance(usage, Usage):
            usage_obj = usage
        elif usage is None and not stream:
            usage_obj = Usage()
        else:
            usage_obj = None

        init_kw: Dict[str, Any] = {
            "id": resp_id,
            "choices": parsed_choices,
            "created": created_ts,
            "model": model or "",
            "object": obj_kind,
            "system_fingerprint": system_fingerprint,
        }
        if usage_obj is not None:
            init_kw["usage"] = usage_obj
        init_kw.update(kwargs)
        super().__init__(**init_kw)
