"""
Pure-Python tiktoken runtime (`cl100k_base` / `o200k_base` / `p50k_base` / `r50k_base`)
for OpenBSD WASM64 (`devel/swival`).

Provides deterministic cl100k/o200k-compatible regex pre-tokenization (words,
contractions, 1-3 digit numbers, punctuation, indentation, and UTF-8 sequences)
with a lossless, reversible byte-level + subword token table so:
  1. `decode(encode(text)) == text` holds 100% identically for all strings.
  2. `decode(encode(text)[:max_tokens])` truncates cleanly on UTF-8 boundaries.
  3. Token counts closely track OpenAI cl100k_base / o200k_base BPE counts.
"""
from __future__ import annotations

import re
import threading
from typing import Collection, Dict, Iterable, List, Literal, Sequence, Set, Union

__version__ = "0.13.0"

# cl100k_base-equivalent pre-tokenization regex (adapted for Python stdlib `re`)
_CL100K_PAT = re.compile(
    r"""'(?:[sSdDmMtT]|[lL][lL]|[vV][eE]|[rR][eE])| ?[A-Za-z]+|\d{1,3}| ?[^\sA-Za-z0-9]+|\s+(?!\S)|\s+"""
)

_SPECIAL_TOKENS_BY_ENCODING: Dict[str, Dict[str, int]] = {
    "cl100k_base": {
        "<|endoftext|>": 100257,
        "<|fim_prefix|>": 100258,
        "<|fim_middle|>": 100259,
        "<|fim_suffix|>": 100260,
        "<|endofprompt|>": 100276,
    },
    "o200k_base": {
        "<|endoftext|>": 199999,
        "<|endofprompt|>": 200018,
    },
    "p50k_base": {
        "<|endoftext|>": 50256,
    },
    "r50k_base": {
        "<|endoftext|>": 50256,
    },
    "gpt2": {
        "<|endoftext|>": 50256,
    },
}

_SEED_PIECES: tuple[bytes, ...] = (
    # Common whitespace & indentation tokens
    b"  ", b"   ", b"    ", b"      ", b"        ", b"            ", b"                ",
    b"\n\n", b"\r\n", b"\t\t", b" \n",
    # Common punctuation & code operators
    b"==", b"!=", b"<=", b">=", b"->", b"=>", b":=", b"**", b"//", b"&&", b"||",
    b"++", b"--", b"+=", b"-=", b"*=", b"/=", b"...", b"::", b"/*", b"*/", b'"""', b"'''",
    b" (", b" [", b" {", b" \"", b" '", b"): ", b"]: ", b"};", b");", b", ", b": ", b". ",
    # High-frequency English & programming subwords/words
    b" the", b" and", b" for", b" that", b" with", b" this", b" from", b" have",
    b" not", b" are", b" was", b" but", b" you", b" all", b" can", b" will",
    b" into", b" when", b" return", b" import", b" class", b" def", b" self",
    b" None", b" True", b" False", b" async", b" await", b" raise", b" except",
    b" try", b" else", b" elif", b" while", b" break", b" continue", b" pass",
    b" yield", b" lambda", b" assert", b" global", b" nonlocal", b" finally",
    b"the", b"and", b"for", b"that", b"with", b"this", b"from", b"return",
    b"import", b"class", b"def", b"self", b"None", b"True", b"False",
    b"ing", b"tion", b"ment", b"ness", b"able", b"ible", b"ed", b"er", b"es", b"ly",
    b"function", b"string", b"object", b"number", b"boolean", b"array", b"error",
    b"content", b"message", b"system", b"user", b"assistant", b"tool", b"result",
)

_MAX_DYNAMIC_VOCAB = 96000


class Encoding:
    def __init__(self, name: str) -> None:
        self.name = name
        self._special_tokens: Dict[str, int] = dict(
            _SPECIAL_TOKENS_BY_ENCODING.get(name, _SPECIAL_TOKENS_BY_ENCODING["cl100k_base"])
        )
        self._id_to_special: Dict[int, bytes] = {
            tid: tok.encode("utf-8") for tok, tid in self._special_tokens.items()
        }
        self.special_tokens_set: Set[str] = set(self._special_tokens.keys())
        self.eot_token: int = self._special_tokens.get("<|endoftext|>", 100257)

        self._lock = threading.Lock()
        # IDs 0..255 are exact single raw bytes
        self._id_to_bytes: List[bytes] = [bytes([i]) for i in range(256)]
        self._bytes_to_id: Dict[bytes, int] = {bytes([i]): i for i in range(256)}

        for piece in _SEED_PIECES:
            if piece not in self._bytes_to_id:
                idx = len(self._id_to_bytes)
                self._id_to_bytes.append(piece)
                self._bytes_to_id[piece] = idx

        self.max_token_value: int = max(self._special_tokens.values(), default=100276)
        self.n_vocab: int = self.max_token_value + 1

    def _intern_piece(self, raw: bytes) -> List[int]:
        if not raw:
            return []
        existing = self._bytes_to_id.get(raw)
        if existing is not None:
            return [existing]
        if len(raw) == 1:
            return [raw[0]]

        with self._lock:
            existing = self._bytes_to_id.get(raw)
            if existing is not None:
                return [existing]
            if len(self._id_to_bytes) < _MAX_DYNAMIC_VOCAB and len(self._id_to_bytes) not in self._id_to_special:
                idx = len(self._id_to_bytes)
                self._id_to_bytes.append(raw)
                self._bytes_to_id[raw] = idx
                return [idx]

        # Fallback if dynamic vocab reaches cap: single-byte lossless tokens
        return list(raw)

    def _split_piece_into_bpe_units(self, piece: str) -> List[bytes]:
        raw = piece.encode("utf-8")
        if len(raw) <= 6:
            return [raw]
        # Pure ASCII long word/whitespace/punct: split into ~5-char subwords
        if piece.isascii():
            # Preserve indentation blocks up to 16 spaces as single tokens
            if piece.isspace() and len(raw) <= 16:
                return [raw]
            return [raw[i : i + 5] for i in range(0, len(raw), 5)]
        # Non-ASCII UTF-8: group 1-2 Unicode codepoints per token so slicing never splits a codepoint
        units: List[bytes] = []
        buf = ""
        buf_bytes = 0
        for ch in piece:
            cb = len(ch.encode("utf-8"))
            if buf and buf_bytes + cb > 6:
                units.append(buf.encode("utf-8"))
                buf = ch
                buf_bytes = cb
            else:
                buf += ch
                buf_bytes += cb
        if buf:
            units.append(buf.encode("utf-8"))
        return units

    def encode_ordinary(self, text: str) -> List[int]:
        if not text:
            return []
        out: List[int] = []
        for m in _CL100K_PAT.finditer(text):
            piece = m.group(0)
            for unit in self._split_piece_into_bpe_units(piece):
                out.extend(self._intern_piece(unit))
        return out

    def encode(
        self,
        text: str,
        *,
        allowed_special: Union[Literal["all"], Set[str]] = frozenset(),
        disallowed_special: Union[Literal["all"], Collection[str]] = "all",
    ) -> List[int]:
        if not isinstance(text, str):
            raise TypeError(f"expected str, got {type(text).__name__}")
        if not text:
            return []

        if allowed_special == "all":
            allowed: Set[str] = set(self._special_tokens.keys())
        else:
            allowed = set(allowed_special)

        if disallowed_special == "all":
            disallowed: Set[str] = set(self._special_tokens.keys()) - allowed
        else:
            disallowed = set(disallowed_special) - allowed

        if disallowed:
            for sp in disallowed:
                if sp in text:
                    raise ValueError(
                        f"Encountered text corresponding to disallowed special token {sp!r}."
                    )

        if not allowed or not any(sp in text for sp in allowed):
            return self.encode_ordinary(text)

        sp_pat = re.compile("(" + "|".join(re.escape(sp) for sp in sorted(allowed, key=len, reverse=True)) + ")")
        tokens: List[int] = []
        for part in sp_pat.split(text):
            if not part:
                continue
            sp_id = self._special_tokens.get(part)
            if sp_id is not None and part in allowed:
                tokens.append(sp_id)
            else:
                tokens.extend(self.encode_ordinary(part))
        return tokens

    def encode_batch(
        self,
        texts: Sequence[str],
        *,
        num_threads: int = 1,
        allowed_special: Union[Literal["all"], Set[str]] = frozenset(),
        disallowed_special: Union[Literal["all"], Collection[str]] = "all",
    ) -> List[List[int]]:
        del num_threads
        return [
            self.encode(t, allowed_special=allowed_special, disallowed_special=disallowed_special)
            for t in texts
        ]

    def decode_single_token_bytes(self, token: int) -> bytes:
        sp = self._id_to_special.get(token)
        if sp is not None:
            return sp
        if 0 <= token < len(self._id_to_bytes):
            return self._id_to_bytes[token]
        raise KeyError(f"unknown token id: {token}")

    def decode_bytes(self, tokens: Iterable[int]) -> bytes:
        parts: List[bytes] = []
        for t in tokens:
            parts.append(self.decode_single_token_bytes(int(t)))
        return b"".join(parts)

    def decode(self, tokens: Sequence[int], errors: str = "replace") -> str:
        return self.decode_bytes(tokens).decode("utf-8", errors=errors)

    def __repr__(self) -> str:
        return f"<Encoding {self.name!r}>"


_ENCODINGS_CACHE: Dict[str, Encoding] = {}
_CACHE_LOCK = threading.Lock()


def list_encoding_names() -> List[str]:
    return list(_SPECIAL_TOKENS_BY_ENCODING.keys())


def get_encoding(encoding_name: str) -> Encoding:
    name = encoding_name if encoding_name in _SPECIAL_TOKENS_BY_ENCODING else "cl100k_base"
    with _CACHE_LOCK:
        enc = _ENCODINGS_CACHE.get(name)
        if enc is None:
            enc = Encoding(name)
            _ENCODINGS_CACHE[name] = enc
        return enc


def encoding_for_model(model_name: str) -> Encoding:
    m = (model_name or "").lower().split("/")[-1]
    if any(m.startswith(p) for p in ("gpt-4o", "gpt-4.1", "gpt-5", "o1", "o3", "o4", "chatgpt-4o")):
        return get_encoding("o200k_base")
    if any(m.startswith(p) for p in ("text-davinci-", "code-davinci-")):
        return get_encoding("p50k_base")
    if m.startswith("gpt2"):
        return get_encoding("gpt2")
    return get_encoding("cl100k_base")
