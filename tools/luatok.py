"""Minimal Lua 5.1 tokenizer, good enough to slice Luraph's flattened output.

Luraph emits one enormous line of source with no newlines and no comments, so
any analysis that needs to isolate a single handler has to parse rather than
regex. This is deliberately small: it understands long brackets, quoted strings,
and the block structure needed to find the `end` that closes a function.

It is not a validating parser. It will not tell you a script is invalid; it only
answers "where does this function end".

Key subtlety handled here: `for ... do` and `while ... do` open a block twice if
counted naively (`for` then `do`), so `do` is context-sensitive -- it closes a
pending header rather than opening a new block.
"""
from __future__ import annotations

import re

TOK = re.compile(r"""
    (?P<ws>\s+)
  | (?P<ls>\[(?P<lseq>=*)\[)
  | (?P<dstr>"(?:[^"\\]|\\.)*")
  | (?P<sstr>'(?:[^'\\]|\\.)*')
  | (?P<num>\d+\.?\d*(?:[eE][-+]?\d+)?|\.\d+)
  | (?P<name>[A-Za-z_]\w*)
  | (?P<op>\.\.\.|\.\.|==|~=|<=|>=|\+=|-=|\*=|/=|//=|%=|&=|\|=|\^=|<<|>>|>>=|[^\s])
""", re.VERBOSE)


def tokens(s: str):
    """Yield (kind, value, start, end) with offsets relative to `s`."""
    i, n = 0, len(s)
    while i < n:
        m = TOK.match(s, i)
        if not m:
            i += 1
            continue
        kind = m.lastgroup
        if kind == "ls":
            eq = m.group("lseq")
            close = "]" + eq + "]"
            e = s.find(close, m.end())
            if e < 0:
                raise ValueError("unterminated long string")
            yield ("longstr", s[m.end():e], m.start(), e + len(close))
            i = e + len(close)
            continue
        if kind == "ws":
            i = m.end()
            continue
        yield (kind, m.group(kind), m.start(), m.end())
        i = m.end()


def slice_function(s: str, start: int) -> tuple[str, int]:
    """`start` indexes the `function` keyword. Return (source, end_index)."""
    stack = ["blk"]
    for kind, v, a, b in tokens(s[start:]):
        if kind != "name":
            continue
        if v in ("function", "if", "repeat"):
            stack.append("blk")
        elif v in ("for", "while"):
            stack.append("hdr")
        elif v == "do":
            if stack[-1] == "hdr":
                stack[-1] = "blk"
            else:
                stack.append("blk")
        elif v == "until":
            if len(stack) > 1:
                stack.pop()
        elif v == "end":
            if len(stack) > 1:
                stack.pop()
                if len(stack) == 1:
                    return s[start:start + b], start + b
    raise ValueError("unterminated function")


def find_function(s: str, name: str):
    """Return (source, start, end) for `NAME=function(...)`, or None."""
    pat = re.compile(r"(?<![A-Za-z0-9_])" + re.escape(name) + r"\s*=\s*function\b")
    m = pat.search(s)
    if not m:
        return None
    src, end = slice_function(s, m.end() - len("function"))
    return src, m.start(), end


def find_assignment_value(s: str, name: str):
    """Return (source, start, end) for `NAME={...}` table constructor, or None."""
    pat = re.compile(r"(?<![A-Za-z0-9_])" + re.escape(name) + r"\s*=\s*\{")
    m = pat.search(s)
    if not m:
        return None
    i = m.end() - 1
    depth = 0
    for kind, v, a, b in tokens(s[i:]):
        if kind == "op":
            if v == "{":
                depth += 1
            elif v == "}":
                depth -= 1
                if depth == 0:
                    return s[i:i + b], m.start(), i + b
    return None