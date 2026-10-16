#!/usr/bin/env python3
"""Recover the third-interpreter state map and static successor graph.

This is source-only analysis. It does not execute the protected target.

For this Luraph v15 sample the `c[B.ep]` closure built by handler `B:T` contains
an unrolled binary-search dispatcher on `t`. The tool parses the nested `if/end`
structure instead of inferring ranges from threshold runs, then maps every state
to its exact micro-handler. It also follows the micro-handler's own branch on the
current state parameter and extracts the possible next-state constants.

Runtime-dependent conditions are conservatively unioned. Therefore a successor
edge means "statically possible", not "observed at runtime".
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

TARGET_SHA256 = "02dc0c6a922796ad4773cbd051745225e4d6bf84d61c9b8c666be71b57f58443"


@dataclass
class Tok:
    val: str
    start: int
    end: int


@dataclass
class Simple:
    a: int
    b: int


@dataclass
class Branch:
    ca: int
    cb: int
    body: list


@dataclass
class IfStmt:
    a: int
    branches: list[Branch]
    else_body: Optional[list]
    b: int


def lex(src: str, start: int = 0, end: Optional[int] = None) -> list[Tok]:
    if end is None:
        end = len(src)
    out: list[Tok] = []
    i = start
    while i < end:
        c = src[i]
        if c.isspace():
            i += 1
            continue
        if src.startswith("--", i):
            # line comment; the protected payload is one minified source line
            j = src.find("\n", i + 2, end)
            i = end if j < 0 else j + 1
            continue
        if c in ("'", '"'):
            q = c
            j = i + 1
            while j < end:
                if src[j] == "\\":
                    j += 2
                    continue
                if src[j] == q:
                    j += 1
                    break
                j += 1
            out.append(Tok(src[i:j], i, j))
            i = j
            continue
        if c == "[":
            m = re.match(r"\[(=*)\[", src[i:end])
            if m:
                close = "]" + m.group(1) + "]"
                j = src.find(close, i + len(m.group(0)), end)
                j = end if j < 0 else j + len(close)
                out.append(Tok(src[i:j], i, j))
                i = j
                continue
        if c.isalpha() or c == "_":
            j = i + 1
            while j < end and (src[j].isalnum() or src[j] == "_"):
                j += 1
            out.append(Tok(src[i:j], i, j))
            i = j
            continue
        if c.isdigit():
            j = i + 1
            while j < end and (src[j].isalnum() or src[j] in ".xX"):
                j += 1
            out.append(Tok(src[i:j], i, j))
            i = j
            continue
        matched = False
        for op in ("<=", ">=", "==", "~=", "..", "::"):
            if src.startswith(op, i):
                out.append(Tok(op, i, i + len(op)))
                i += len(op)
                matched = True
                break
        if matched:
            continue
        out.append(Tok(c, i, i + 1))
        i += 1
    return out


def slice_named_function(src: str, name: str) -> str:
    pat = re.compile(rf"(?<![A-Za-z0-9_]){re.escape(name)}=function\(")
    hits = list(pat.finditer(src))
    if len(hits) != 1:
        raise ValueError(f"expected one `{name}=function(`, got {len(hits)}")
    start = hits[0].start()
    tt = lex(src, start, min(len(src), start + 100_000))
    fi = next((i for i, t in enumerate(tt) if t.val == "function"), None)
    if fi is None:
        raise ValueError(f"no function token for {name}")

    stack: list[str] = []
    awaiting_do = 0
    for i in range(fi, len(tt)):
        v = tt[i].val
        if v == "function":
            stack.append("end")
        elif v == "if":
            stack.append("end")
        elif v in ("while", "for"):
            stack.append("end")
            awaiting_do += 1
        elif v == "do":
            if awaiting_do:
                awaiting_do -= 1
            else:
                stack.append("end")
        elif v == "repeat":
            stack.append("until")
        elif v == "until":
            if stack and stack[-1] == "until":
                stack.pop()
        elif v == "end":
            if not stack or stack[-1] != "end":
                raise ValueError(f"unbalanced end while slicing {name}")
            stack.pop()
            if not stack:
                return src[start:tt[i].end]
    raise ValueError(f"unterminated function {name}")


class Parser:
    def __init__(self, toks: list[Tok]):
        self.t = toks
        self.i = 0

    def block(self, stops: set[str]) -> list:
        out = []
        while self.i < len(self.t) and self.t[self.i].val not in stops:
            if self.t[self.i].val == "if":
                out.append(self.if_stmt())
            else:
                out.append(self.simple(stops))
        return out

    def simple(self, stops: set[str]) -> Simple:
        st = self.i
        par = br = brace = 0
        while self.i < len(self.t):
            v = self.t[self.i].val
            if v == "(":
                par += 1
            elif v == ")":
                par = max(0, par - 1)
            elif v == "[":
                br += 1
            elif v == "]":
                br = max(0, br - 1)
            elif v == "{":
                brace += 1
            elif v == "}":
                brace = max(0, brace - 1)
            if par == br == brace == 0:
                if v == ";":
                    self.i += 1
                    return Simple(st, self.i)
                if self.i > st and v in stops:
                    return Simple(st, self.i)
            self.i += 1
        return Simple(st, self.i)

    def if_stmt(self) -> IfStmt:
        st = self.i
        if self.t[self.i].val != "if":
            raise AssertionError
        self.i += 1
        branches: list[Branch] = []
        while True:
            ca = self.i
            while self.i < len(self.t) and self.t[self.i].val != "then":
                self.i += 1
            if self.i >= len(self.t):
                raise ValueError("if without then")
            cb = self.i
            self.i += 1
            body = self.block({"elseif", "else", "end"})
            branches.append(Branch(ca, cb, body))
            if self.i < len(self.t) and self.t[self.i].val == "elseif":
                self.i += 1
                continue
            break
        else_body = None
        if self.i < len(self.t) and self.t[self.i].val == "else":
            self.i += 1
            else_body = self.block({"end"})
        if self.i >= len(self.t) or self.t[self.i].val != "end":
            raise ValueError("if without matching end")
        self.i += 1
        if self.i < len(self.t) and self.t[self.i].val == ";":
            self.i += 1
        return IfStmt(st, branches, else_body, self.i)


def text(toks: list[Tok], a: int, b: int) -> str:
    return "".join(t.val for t in toks[a:b])


def parse_body(fn_src: str) -> tuple[list[Tok], list]:
    tt = lex(fn_src)
    fi = next(i for i, t in enumerate(tt) if t.val == "function")
    oi = next(i for i in range(fi + 1, len(tt)) if tt[i].val == "(")
    depth = 0
    close = None
    for i in range(oi, len(tt)):
        if tt[i].val == "(":
            depth += 1
        elif tt[i].val == ")":
            depth -= 1
            if depth == 0:
                close = i
                break
    if close is None:
        raise ValueError("function signature has no closing paren")
    p = Parser(tt)
    p.i = close + 1
    body = p.block({"end"})
    return tt, body


def branch_threshold(br: Branch, toks: list[Tok], var: str = "t") -> Optional[int]:
    vals = [x.val for x in toks[br.ca:br.cb] if x.val not in ("(", ")")]
    if len(vals) == 3 and vals[0] == var and vals[1] == "<=" and vals[2].isdigit():
        return int(vals[2])
    return None


def first_handler(stmt: Simple, toks: list[Tok]) -> Optional[str]:
    part = toks[stmt.a:stmt.b]
    for i in range(len(part) - 3):
        if (part[i].val == "B" and part[i + 1].val == ":" and
                re.fullmatch(r"[A-Za-z_]\w*", part[i + 2].val) and
                part[i + 3].val == "("):
            return part[i + 2].val
    return None


def dispatch_leaf(stmts: list, toks: list[Tok], state: int) -> tuple[str, Simple]:
    for st in stmts:
        if isinstance(st, Simple):
            h = first_handler(st, toks)
            if h:
                return h, st
        else:
            thresholds = [branch_threshold(b, toks, "t") for b in st.branches]
            if any(x is None for x in thresholds):
                raise ValueError("non-t conditional occurs before dispatch leaf")
            chosen = None
            for b, n in zip(st.branches, thresholds):
                if state <= n:
                    chosen = b.body
                    break
            if chosen is None:
                chosen = st.else_body
            if chosen is None:
                continue
            try:
                return dispatch_leaf(chosen, toks, state)
            except LookupError:
                pass
    raise LookupError(state)


def call_args(stmt: Simple, toks: list[Tok], handler: str) -> list[str]:
    part = toks[stmt.a:stmt.b]
    for i in range(len(part) - 3):
        if part[i].val == "B" and part[i + 1].val == ":" and part[i + 2].val == handler and part[i + 3].val == "(":
            args: list[list[Tok]] = []
            cur: list[Tok] = []
            depth = 0
            j = i + 4
            while j < len(part):
                v = part[j].val
                if v in ("(", "[", "{"):
                    depth += 1
                    cur.append(part[j])
                elif v in (")", "]", "}"):
                    if v == ")" and depth == 0:
                        if cur:
                            args.append(cur)
                        break
                    depth -= 1
                    cur.append(part[j])
                elif v == "," and depth == 0:
                    args.append(cur)
                    cur = []
                else:
                    cur.append(part[j])
                j += 1
            return ["".join(x.val for x in a) for a in args]
    raise ValueError(f"call to {handler} not found")


