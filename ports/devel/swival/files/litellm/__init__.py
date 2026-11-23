"""
Pure-Python `litellm` runtime (`1.90.2`) for OpenBSD WASM64 (`devel/swival`).

Supports live HTTP/HTTPS streaming SSE & non-streaming completions and multi-turn
tool calling across OpenAI & OpenAI-compatible APIs (`openai/*`, `openrouter/*`,
`groq/*`, `deepseek/*`, `xai/*`, `mistral/*`, `ollama/*`, `lm_studio/*`,
`hosted_vllm/*`, `custom_openai/*`, `huggingface/*`, local `llama-server`),
Anthropic Claude (`anthropic/*`, `claude-*` -> `/v1/messages`), and Google Gemini
(`gemini/*` -> `/v1beta/openai/chat/completions`).
"""
from __future__ import annotations

from . import exceptions, llms, responses, types, utils
from ._client import acompletion, completion
from .exceptions import (
    APIConnectionError,
    APIError,
    AuthenticationError,
    BadRequestError,
    ContentPolicyViolationError,
    ContextWindowExceededError,
    InternalServerError,
    JSONSchemaValidationError,
    NotFoundError,
    PermissionDeniedError,
    RateLimitError,
    ServiceUnavailableError,
    Timeout,
    UnprocessableEntityError,
    UnsupportedParamsError,
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
)
from .utils import (
    get_max_tokens,
    get_model_info,
    get_valid_models,
    model_cost,
    register_model,
    stream_chunk_builder,
    supports_function_calling,
    supports_prompt_caching,
    supports_vision,
)

__version__ = "1.90.2"

suppress_debug_info: bool = True
drop_params: bool = True
modify_params: bool = False
set_verbose: bool = False

__all__ = [
    "__version__",
    "completion",
    "acompletion",
    "stream_chunk_builder",
    "get_max_tokens",
    "get_model_info",
    "get_valid_models",
    "register_model",
    "supports_vision",
    "supports_function_calling",
    "supports_prompt_caching",
    "model_cost",
    "suppress_debug_info",
    "drop_params",
    "modify_params",
    "set_verbose",
    "exceptions",
    "types",
    "utils",
    "llms",
    "responses",
    "ModelResponse",
    "Choices",
    "StreamingChoices",
    "Message",
    "Delta",
    "ChatCompletionMessageToolCall",
    "Function",
    "Usage",
    "APIError",
    "BadRequestError",
    "ContextWindowExceededError",
    "ContentPolicyViolationError",
    "AuthenticationError",
    "PermissionDeniedError",
    "NotFoundError",
    "Timeout",
    "RateLimitError",
    "InternalServerError",
    "APIConnectionError",
    "ServiceUnavailableError",
    "UnprocessableEntityError",
    "UnsupportedParamsError",
    "JSONSchemaValidationError",
]
