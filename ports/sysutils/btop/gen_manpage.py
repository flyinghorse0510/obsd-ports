#!/usr/bin/env python3
"""Convert btop's pandoc/lowdown manpage.md into roff man(7) btop.1."""
from __future__ import annotations

import pathlib
import re
import sys


def fmt_inline(text: str) -> str:
    s = text.replace("\\-\\-", "--").replace("\\-", "-")
    s = re.sub(r"\*\*([^*]+)\*\*", lambda m: f"\\fB{m.group(1)}\\fR", s)
    s = re.sub(r"_([^_]+)_", lambda m: f"\\fI{m.group(1)}\\fR", s)
    return s.replace("--", "\\-\\-")


def main() -> int:
    src = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
    dst = pathlib.Path(sys.argv[2])
    lines = src.splitlines()
    date_str = "2025-05-01"
    start = 0
    for idx, ln in enumerate(lines[:5]):
        if ln.startswith("%"):
            start = idx + 1
            val = ln[1:].strip()
            if re.match(r"^\d{4}-\d{2}-\d{2}$", val):
                date_str = val
    out = [f'.TH BTOP 1 "{date_str}" "btop++" "User Commands"']
    i = start
    while i < len(lines):
        ln = lines[i].rstrip()
        if not ln:
            i += 1
            continue
        if ln.startswith("# "):
            out.append(f'.SH "{ln[2:].strip()}"')
            i += 1
            continue
        if i + 1 < len(lines) and lines[i + 1].startswith(":"):
            out.append(".TP")
            out.append(fmt_inline(ln))
            desc = [lines[i + 1][1:].strip()]
            i += 2
            while i < len(lines) and lines[i].startswith("  "):
                desc.append(lines[i].strip())
                i += 1
            out.append(fmt_inline(" ".join(desc)))
            continue
        para = [ln]
        i += 1
        while i < len(lines) and lines[i].strip() and not lines[i].startswith("# ") and not (
            i + 1 < len(lines) and lines[i + 1].startswith(":")
        ):
            para.append(lines[i].strip())
            i += 1
        out.append(".PP")
        out.append(fmt_inline(" ".join(para)))
    dst.write_text("\n".join(out) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
