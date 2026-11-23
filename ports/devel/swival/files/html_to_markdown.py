"""
Pure-Python `html_to_markdown` converter for OpenBSD WASM64 (`devel/swival`).
Implements `convert(html_str, **kwargs) -> ConversionResult(content=...)` using
Python's stdlib `html.parser` with clean Markdown rendering of headings, links,
lists, code blocks, inline formatting, blockquotes, and tables.
"""
from __future__ import annotations

import html
import html.parser
import re
from dataclasses import dataclass
from typing import List, Optional, Tuple


@dataclass
class ConversionResult:
    content: str

    def __str__(self) -> str:
        return self.content


_SKIP_TAGS = frozenset({"script", "style", "noscript", "svg", "head", "template"})
_HEADING_TAGS = {"h1": 1, "h2": 2, "h3": 3, "h4": 4, "h5": 5, "h6": 6}


class _MarkdownConverter(html.parser.HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=False)
        self._out: List[str] = []
        self._skip_depth = 0
        self._pre_depth = 0
        self._code_depth = 0
        self._list_stack: List[Tuple[str, int]] = []
        self._link_stack: List[Tuple[str, List[str]]] = []
        self._in_table_row = False
        self._table_cells: List[List[str]] = []
        self._table_header_row = False
        self._blockquote_depth = 0

    def _emit(self, text: str) -> None:
        if self._skip_depth > 0:
            return
        if self._link_stack:
            self._link_stack[-1][1].append(text)
        elif self._in_table_row and self._table_cells:
            self._table_cells[-1].append(text)
        else:
            self._out.append(text)

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        t = tag.lower()
        if t in _SKIP_TAGS:
            self._skip_depth += 1
            return
        if self._skip_depth > 0:
            return
        attr_map = {k.lower(): (v or "") for k, v in attrs}

        if t in _HEADING_TAGS:
            lvl = _HEADING_TAGS[t]
            self._emit(f"\n\n{'#' * lvl} ")
        elif t in ("p", "div", "section", "article", "main", "header", "footer"):
            self._emit("\n\n")
        elif t == "br":
            self._emit("  \n")
        elif t == "hr":
            self._emit("\n\n---\n\n")
        elif t == "blockquote":
            self._blockquote_depth += 1
            self._emit("\n\n> ")
        elif t == "pre":
            self._pre_depth += 1
            self._emit("\n\n```\n")
        elif t == "code":
            self._code_depth += 1
            if self._pre_depth == 0:
                self._emit("`")
        elif t in ("strong", "b"):
            self._emit("**")
        elif t in ("em", "i"):
            self._emit("*")
        elif t in ("ul", "ol"):
            self._list_stack.append((t, 0))
            self._emit("\n")
        elif t == "li":
            indent = "  " * max(0, len(self._list_stack) - 1)
            if self._list_stack and self._list_stack[-1][0] == "ol":
                kind, idx = self._list_stack[-1]
                idx += 1
                self._list_stack[-1] = (kind, idx)
                self._emit(f"\n{indent}{idx}. ")
            else:
                self._emit(f"\n{indent}- ")
        elif t == "a":
            href = attr_map.get("href", "").strip()
            self._link_stack.append((href, []))
        elif t == "img":
            alt = attr_map.get("alt", "").strip()
            src = attr_map.get("src", "").strip()
            if src:
                self._emit(f"![{alt}]({src})")
        elif t == "tr":
            self._in_table_row = True
            self._table_cells = []
            self._table_header_row = False
        elif t in ("th", "td") and self._in_table_row:
            if t == "th":
                self._table_header_row = True
            self._table_cells.append([])

    def handle_endtag(self, tag: str) -> None:
        t = tag.lower()
        if t in _SKIP_TAGS:
            self._skip_depth = max(0, self._skip_depth - 1)
            return
        if self._skip_depth > 0:
            return

        if t in _HEADING_TAGS:
            self._emit("\n\n")
        elif t in ("p", "div", "section", "article", "main"):
            self._emit("\n\n")
        elif t == "blockquote":
            self._blockquote_depth = max(0, self._blockquote_depth - 1)
            self._emit("\n\n")
        elif t == "pre":
            self._pre_depth = max(0, self._pre_depth - 1)
            self._emit("\n```\n\n")
        elif t == "code":
            if self._pre_depth == 0:
                self._emit("`")
            self._code_depth = max(0, self._code_depth - 1)
        elif t in ("strong", "b"):
            self._emit("**")
        elif t in ("em", "i"):
            self._emit("*")
        elif t in ("ul", "ol"):
            if self._list_stack:
                self._list_stack.pop()
            self._emit("\n")
        elif t == "a" and self._link_stack:
            href, chunks = self._link_stack.pop()
            label = re.sub(r"\s+", " ", "".join(chunks)).strip()
            if href and label:
                self._emit(f"[{label}]({href})")
            elif label:
                self._emit(label)
        elif t == "tr" and self._in_table_row:
            self._in_table_row = False
            if self._table_cells:
                cells = [re.sub(r"\s+", " ", "".join(c)).strip() for c in self._table_cells]
                self._out.append("\n| " + " | ".join(cells) + " |")
                if self._table_header_row:
                    self._out.append("\n| " + " | ".join("---" for _ in cells) + " |")
            self._table_cells = []

    def handle_data(self, data: str) -> None:
        if self._skip_depth > 0:
            return
        if self._pre_depth > 0:
            self._emit(data)
        else:
            collapsed = re.sub(r"[ \t\r\n]+", " ", data)
            self._emit(collapsed)

    def handle_entityref(self, name: str) -> None:
        if self._skip_depth == 0:
            self._emit(html.unescape(f"&{name};"))

    def handle_charref(self, name: str) -> None:
        if self._skip_depth == 0:
            self._emit(html.unescape(f"&#{name};"))

    def get_markdown(self) -> str:
        raw = "".join(self._out)
        lines = [ln.rstrip() for ln in raw.splitlines()]
        cleaned = "\n".join(lines)
        cleaned = re.sub(r"\n{3,}", "\n\n", cleaned)
        return cleaned.strip()


def convert(html_input: str, **kwargs: object) -> ConversionResult:
    del kwargs
    parser = _MarkdownConverter()
    parser.feed(html_input or "")
    parser.close()
    return ConversionResult(content=parser.get_markdown())


def convert_to_markdown(html_input: str, **kwargs: object) -> str:
    return convert(html_input, **kwargs).content
