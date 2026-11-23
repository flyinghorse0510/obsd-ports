"""
litellm.exceptions -- Complete LiteLLM exception hierarchy for OpenBSD WASM64.
"""
from __future__ import annotations

import json
import re
from typing import Any, Optional


class APIError(Exception):
    def __init__(
        self,
        message: str = "",
        llm_provider: Optional[str] = None,
        model: Optional[str] = None,
        status_code: Optional[int] = None,
        response: Any = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(message)
        self.message = str(message)
        self.llm_provider = llm_provider
        self.model = model
        if status_code is not None:
            self.status_code = int(status_code)
        elif not hasattr(self, "status_code"):
            self.status_code = 500
        self.response = response
        self._provider_retries = 0
        for k, v in kwargs.items():
            setattr(self, k, v)


class BadRequestError(APIError):
    status_code = 400


class ContextWindowExceededError(BadRequestError):
    status_code = 400


class ContentPolicyViolationError(BadRequestError):
    status_code = 400


class UnsupportedParamsError(BadRequestError):
    status_code = 400


class JSONSchemaValidationError(BadRequestError):
    status_code = 400


class AuthenticationError(APIError):
    status_code = 401


class PermissionDeniedError(APIError):
    status_code = 403


class NotFoundError(APIError):
    status_code = 404


class Timeout(APIError):
    status_code = 408


class UnprocessableEntityError(APIError):
    status_code = 422


class RateLimitError(APIError):
    status_code = 429


class InternalServerError(APIError):
    status_code = 500


class APIConnectionError(APIError):
    status_code = 500


class ServiceUnavailableError(APIError):
    status_code = 503


_CONTEXT_ERROR_RE = re.compile(
    r"context_length_exceeded|context window|maximum context length|"
    r"prompt is too long|too many tokens|max_tokens.*exceed|"
    r"exceeds the model's maximum context|input length.*exceeds",
    re.IGNORECASE,
)

_CONTENT_POLICY_RE = re.compile(
    r"content_policy_violation|content management policy|safety system|blocked by safety",
    re.IGNORECASE,
)


def extract_error_message(body_text: str) -> tuple[str, str]:
    """Return `(message, code_or_type)` extracted from JSON or plain error body."""
    if not body_text:
        return "empty error response", ""
    try:
        parsed = json.loads(body_text)
        if isinstance(parsed, dict):
            err = parsed.get("error")
            if isinstance(err, dict):
                msg = str(err.get("message") or body_text)
                code = str(err.get("code") or err.get("type") or "")
                return msg, code
            if isinstance(err, str):
                return err, str(parsed.get("type") or "")
            if "message" in parsed:
                return str(parsed["message"]), str(parsed.get("type") or parsed.get("code") or "")
    except Exception:
        pass
    return body_text.strip(), ""


def raise_mapped_http_error(
    status_code: int,
    body_text: str,
    llm_provider: str,
    model: str,
    response: Any = None,
) -> "None":
    msg, err_code = extract_error_message(body_text)
    full_msg = f"{llm_provider} HTTP {status_code}: {msg}"
    combined = f"{err_code} {msg}"

    if status_code == 413 or (status_code in (400, 422) and _CONTEXT_ERROR_RE.search(combined)):
        raise ContextWindowExceededError(
            full_msg, llm_provider=llm_provider, model=model, status_code=status_code, response=response
        )
    if status_code in (400, 422) and _CONTENT_POLICY_RE.search(combined):
        raise ContentPolicyViolationError(
            full_msg, llm_provider=llm_provider, model=model, status_code=status_code, response=response
        )
    if status_code == 400:
        raise BadRequestError(
            full_msg, llm_provider=llm_provider, model=model, status_code=400, response=response
        )
    if status_code == 401:
        raise AuthenticationError(
            full_msg, llm_provider=llm_provider, model=model, status_code=401, response=response
        )
    if status_code == 403:
        raise PermissionDeniedError(
            full_msg, llm_provider=llm_provider, model=model, status_code=403, response=response
        )
    if status_code == 404:
        raise NotFoundError(
            full_msg, llm_provider=llm_provider, model=model, status_code=404, response=response
        )
    if status_code in (408, 504):
        raise Timeout(
            full_msg, llm_provider=llm_provider, model=model, status_code=status_code, response=response
        )
    if status_code == 422:
        raise BadRequestError(
            full_msg, llm_provider=llm_provider, model=model, status_code=422, response=response
        )
    if status_code == 429:
        raise RateLimitError(
            full_msg, llm_provider=llm_provider, model=model, status_code=429, response=response
        )
    if status_code in (502, 503, 529):
        raise ServiceUnavailableError(
            full_msg, llm_provider=llm_provider, model=model, status_code=status_code, response=response
        )
    if 500 <= status_code < 600:
        raise InternalServerError(
            full_msg, llm_provider=llm_provider, model=model, status_code=status_code, response=response
        )
    raise APIError(
        full_msg, llm_provider=llm_provider, model=model, status_code=status_code, response=response
    )
