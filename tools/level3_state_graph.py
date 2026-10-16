#!/usr/bin/env python3
"""Recover exact level-3 state ranges and a source-derived successor graph.

Source-only; does not execute the protected target. Runtime-dependent branches
are conservatively unioned, so successor reachability is an over-approximation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Optional

from level3_parse import (Branch, IfStmt, Parser, Simple, Tok, call_args, dispatch_leaf,
                          first_handler, lex, parse_body, slice_named_function, text)

TARGET_SHA256 = "02dc0c6a922796ad4773cbd051745225e4d6bf84d61c9b8c666be71b57f58443"

def function_params(src: str, name: str) -> list[str]:
    m = re.search(rf"(?<![A-Za-z0-9_]){re.escape(name)}=function\(([^)]*)\)", src)
    if not m:
        raise ValueError(f"signature missing for {name}")
    return [x.strip() for x in m.group(1).split(",") if x.strip()]


def eval_cond(cond: str, formal: str, state: int) -> Optional[bool]:
    c = cond.replace("(", "").replace(")", "")
    if c == formal:
        return bool(state)
    forms = [
        (rf"{re.escape(formal)}<=(-?\d+)", lambda n: state <= n),
        (rf"{re.escape(formal)}<(-?\d+)", lambda n: state < n),
        (rf"{re.escape(formal)}>=(-?\d+)", lambda n: state >= n),
        (rf"{re.escape(formal)}>(-?\d+)", lambda n: state > n),
        (rf"{re.escape(formal)}==(-?\d+)", lambda n: state == n),
        (rf"(-?\d+)<={re.escape(formal)}", lambda n: n <= state),
        (rf"(-?\d+)<{re.escape(formal)}", lambda n: n < state),
        (rf"notnot{re.escape(formal)}>=(-?\d+)", lambda n: state >= n),
        (rf"notnot(-?\d+)<={re.escape(formal)}", lambda n: n <= state),
    ]
    for pat, fn in forms:
        m = re.fullmatch(pat, c)
        if m:
            return fn(int(m.group(1)))
    return None


def possible_bodies(st: IfStmt, toks: list[Tok], formal: str, state: int,
                    formal_live: bool = True) -> list[Optional[list]]:
    out: list[Optional[list]] = []
    can_continue = True
    for br in st.branches:
        if not can_continue:
            break
        # A micro-handler may shadow/reassign the formal that originally carried
        # the dispatcher state. Once that happens, a later `if formal ...`
        # is runtime data, not a test of the original state. Treat it as unknown.
        ev = eval_cond(text(toks, br.ca, br.cb), formal, state) if formal_live else None
        if ev is True:
            out.append(br.body)
            can_continue = False
        elif ev is False:
            pass
        else:
            out.append(br.body)  # condition may be true
            # false path continues to later elseif/else
    if can_continue:
        out.append(st.else_body)  # None means fallthrough
    return out


def return_list(stmt: Simple, toks: list[Tok]) -> Optional[list[str]]:
    part = toks[stmt.a:stmt.b]
    try:
        ri = next(i for i, x in enumerate(part) if x.val == "return")
    except StopIteration:
        return None
    args: list[str] = []
    cur: list[Tok] = []
    par = br = brace = 0
    for x in part[ri + 1:]:
        v = x.val
        if v == "(": par += 1
        elif v == ")": par -= 1
        elif v == "[": br += 1
        elif v == "]": br -= 1
        elif v == "{": brace += 1
        elif v == "}": brace -= 1
        if par == br == brace == 0 and v in (",", ";"):
            if cur or v == ",":
                args.append("".join(y.val for y in cur).strip())
                cur = []
            if v == ";":
                break
        else:
            cur.append(x)
    if cur:
        args.append("".join(y.val for y in cur).strip())
    return args


def simple_rebinds_formal(stmt: Simple, toks: list[Tok], formal: str) -> bool:
    """Conservatively detect rebinding/shadowing of the state-carrying formal.

    We only need sound successor over-approximation. A bare formal on the
    top-level LHS of an assignment means subsequent tests of that name are no
    longer safe to evaluate from the original dispatcher state. Indexed/member
    assignments such as `formal[1]=...` do not rebind the variable itself.
    """
    part = toks[stmt.a:stmt.b]
    par = br = brace = 0
    eq = None
    for i, x in enumerate(part):
        v = x.val
        if v == "(": par += 1
        elif v == ")": par -= 1
        elif v == "[": br += 1
        elif v == "]": br -= 1
        elif v == "{": brace += 1
        elif v == "}": brace -= 1
        elif v == "=" and par == br == brace == 0:
            eq = i
            break
    if eq is None:
        return False

    par = br = brace = 0
    lhs = part[:eq]
    for i, x in enumerate(lhs):
        v = x.val
        if v == "(": par += 1
        elif v == ")": par -= 1
        elif v == "[": br += 1
        elif v == "]": br -= 1
        elif v == "{": brace += 1
        elif v == "}": brace -= 1
        elif v == formal and par == br == brace == 0:
            nxt = lhs[i + 1].val if i + 1 < len(lhs) else None
            if nxt in ("[", ".", ":"):
                continue
            return True
    return False


def reachable_returns(stmts: list, toks: list[Tok], formal: str, state: int,
                      formal_live: bool = True) -> tuple[list[list[str]], set[bool]]:
    """Return possible returns and state-formal liveness for fallthrough paths.

    `formal_live=True` means the formal still denotes the original dispatcher
    state. Once a statement shadows/reassigns it, later conditions on the same
    spelling are runtime-dependent and must be unioned rather than evaluated
    from `state`.
    """
    returns: list[list[str]] = []
    active: set[bool] = {formal_live}
    for st in stmts:
        if not active:
            break
        next_active: set[bool] = set()
        for live in active:
            if isinstance(st, Simple):
                r = return_list(st, toks)
                if r is not None:
                    returns.append(r)
                else:
                    next_active.add(live and not simple_rebinds_formal(st, toks, formal))
            else:
                for body in possible_bodies(st, toks, formal, state, live):
                    if body is None:
                        next_active.add(live)
                    else:
                        rr, ff = reachable_returns(body, toks, formal, state, live)
                        returns.extend(rr)
                        next_active |= ff
        active = next_active
    return returns, active


def constant_options(expr: str) -> Optional[set[int]]:
    if re.fullmatch(r"-?\d+", expr):
        return {int(expr)}
    m = re.search(r"and(-?\d+)or(-?\d+)$", expr)
    if m:
        return {int(m.group(1)), int(m.group(2))}
    return None


def compress(states: list[dict]) -> list[dict]:
    out: list[dict] = []
    lo = states[0]["state"]
    hi = lo
    handler = states[0]["handler"]
    for row in states[1:]:
        if row["handler"] == handler and row["state"] == hi + 1:
            hi = row["state"]
            continue
        out.append({"lo": lo, "hi": hi, "handler": handler})
        lo = hi = row["state"]
        handler = row["handler"]
    out.append({"lo": lo, "hi": hi, "handler": handler})
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("script", type=Path)
    ap.add_argument("--json", type=Path, default=None)
    ap.add_argument("--allow-foreign-sha", action="store_true")
    args = ap.parse_args()

    raw = args.script.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != TARGET_SHA256 and not args.allow_foreign_sha:
        raise SystemExit(f"FAIL: target SHA mismatch: {digest}")
    src = raw.decode("utf-8")

    T = slice_named_function(src, "T")
    marker = "while a do if t<="
    p = T.find(marker)
    if p < 0:
        raise SystemExit("FAIL: third-interpreter dispatch not found in B:T")
    if_start = T.find("if t<=", p)
    dispatch_src = T[if_start:]
    dt = lex(dispatch_src)
    parser = Parser(dt)
    root = parser.if_stmt()

    # Discover handler names from a generous state scan. The final dispatcher
    # branch is open-ended, so this scan is only for handler census; the real
    # state maximum is derived from successor constants below.
    discovered: dict[int, tuple[str, Simple]] = {}
    for state in range(0, 512):
        discovered[state] = dispatch_leaf([root], dt, state)
    handlers = sorted({h for h, _ in discovered.values()})
    if len(handlers) != 73:
        raise SystemExit(f"FAIL: expected 73 micro-handlers, got {len(handlers)}")

    # Map each handler's call argument carrying current t to the corresponding
    # formal parameter in the handler definition.
    state_formal: dict[str, str] = {}
    leaf_lhs: dict[str, str] = {}
    for handler in handlers:
        state = next(s for s, (h, _) in discovered.items() if h == handler)
        _, leaf = discovered[state]
        args2 = call_args(leaf, dt, handler)
        idx = [i for i, a in enumerate(args2) if a == "t"]
        params = function_params(src, handler)
        if len(idx) != 1 or len(params) != len(args2) + 1:
            raise SystemExit(f"FAIL: cannot map current-state parameter for {handler}")
        state_formal[handler] = params[idx[0] + 1]
        leaf_text = text(dt, leaf.a, leaf.b)
        call_pos = leaf_text.find("=B:" + handler)
        if call_pos < 0:
            raise SystemExit(f"FAIL: cannot find call assignment for {handler}")
        leaf_lhs[handler] = leaf_text[:call_pos]

    up_wrapper = (
        "o,T,X,J,u,j,Z,q,A,k,y,r=B:up(t,w,W,H,L,x,V,S,K,F,s,O);"
        "if o==1 then t,V,K,S,L,w,H,F,x,W,O=T,X,J,u,j,Z,q,A,k,y,r;"
        "elseif o==2 then return V;end;"
    )
    if up_wrapper not in T:
        raise SystemExit("FAIL: special B:up wrapper semantics changed")

    # Preparse every handler and collect all possible first-return constants.
    parsed: dict[str, tuple[list[Tok], list]] = {}
    raw_successor_constants: set[int] = set()
    for handler in handlers:
        hs = slice_named_function(src, handler)
        ht, hb = parse_body(hs)
        parsed[handler] = (ht, hb)
        # Try a wide sample of state values; branch conditions on the current
        # state are tiny and this catches all return forms while remaining
        # independent of the eventual state-domain maximum.
        for state in range(0, 512):
            rr, fall = reachable_returns(hb, ht, state_formal[handler], state)
            if fall:
                continue
            for ret in rr:
                if not ret:
                    continue
                # Normal closure leaves assign the handler's first return to t.
                # B:up is the one verified exception: first return is control
                # code o; second return becomes t when o==1, o==2 terminates.
                if handler == "up":
                    ctrl = constant_options(ret[0])
                    if ctrl is None:
                        raise SystemExit(f"FAIL: unresolved up control: {ret[0]}")
                    if 1 in ctrl:
                        if len(ret) < 2:
                            raise SystemExit("FAIL: up returns control=1 without next state")
                        nxt = constant_options(ret[1])
                        if nxt is None:
                            raise SystemExit(f"FAIL: unresolved up successor: {ret[1]}")
                        raw_successor_constants |= nxt
                    if not ctrl <= {1, 2}:
                        raise SystemExit(f"FAIL: unexpected up controls: {sorted(ctrl)}")
                else:
                    nxt = constant_options(ret[0])
                    if nxt is None:
                        raise SystemExit(f"FAIL: unresolved successor in {handler}: {ret[0]}")
                    raw_successor_constants |= nxt

    max_state = max(raw_successor_constants)
    if min(raw_successor_constants) < 0:
        raise SystemExit("FAIL: negative next state")

    rows: list[dict] = []
    for state in range(max_state + 1):
        handler, leaf = dispatch_leaf([root], dt, state)
        ht, hb = parsed[handler]
        rr, fall = reachable_returns(hb, ht, state_formal[handler], state)
        if fall:
            raise SystemExit(f"FAIL: handler {handler} state {state} may fall through")
        next_states: set[int] = set()
        terminal = False
        raw_returns: list = []
        if handler == "up":
            # Fail closed on the one non-t assignment shape in the closure.
            if not leaf_lhs[handler].startswith("o,T,"):
                raise SystemExit(f"FAIL: unexpected up call LHS: {leaf_lhs[handler]}")
            for ret in rr:
                ctrl = constant_options(ret[0])
                if ctrl is None:
                    raise SystemExit(f"FAIL: unresolved up control at state {state}")
                raw_returns.append(ret[:2])
                if 1 in ctrl:
                    nxt = constant_options(ret[1])
                    if nxt is None:
                        raise SystemExit(f"FAIL: unresolved up next state at {state}")
                    next_states |= nxt
                if 2 in ctrl:
                    terminal = True
        else:
            if not re.search(r"(^|;)t(?:,|=)", leaf_lhs[handler]):
                raise SystemExit(f"FAIL: nonstandard closure assignment for {handler}: {leaf_lhs[handler]}")
            for ret in rr:
                raw_returns.append(ret[0])
                nxt = constant_options(ret[0])
                if nxt is None:
                    raise SystemExit(f"FAIL: unresolved successor {handler} state {state}: {ret[0]}")
                next_states |= nxt
        if any(n > max_state for n in next_states):
            raise SystemExit(f"FAIL: state {state} returns outside derived domain: {sorted(next_states)}")
        rows.append({
            "state": state,
            "handler": handler,
            "state_formal": state_formal[handler],
            "next_states": sorted(next_states),
            "terminal": terminal,
            "return_expr": raw_returns,
        })

    ranges = compress(rows)
    if len(ranges) != 73:
        raise SystemExit(f"FAIL: expected 73 exact state ranges, got {len(ranges)}")

    op = re.search(r"(?<![A-Za-z0-9_])Op=function\(B\)return true,(\d+)", src)
    if not op:
        raise SystemExit("FAIL: B:Op entry state not found")
    entry = int(op.group(1))
    if not 0 <= entry <= max_state:
        raise SystemExit(f"FAIL: entry state {entry} outside domain")

    graph = {r["state"]: set(r["next_states"]) for r in rows}
    possible = {entry}
    todo = [entry]
    while todo:
        s = todo.pop()
        for n in graph[s]:
            if n not in possible:
                possible.add(n)
                todo.append(n)
    unreachable = sorted(set(range(max_state + 1)) - possible)

    print(f"target sha256       : {digest}")
    print(f"micro-handlers      : {len(handlers)}")
    print(f"state domain        : 0..{max_state} ({max_state + 1} states)")
    print(f"exact ranges        : {len(ranges)}")
    print(f"entry state         : {entry} -> {rows[entry]['handler']}")
    print(f"possibly reachable  : {len(possible)}/{max_state + 1}")
    print(f"not reachable even in static overapprox: {unreachable}")
    print("\n=== exact state ranges ===")
    for r in ranges:
        print(f"{r['lo']:3d}..{r['hi']:3d}  {r['handler']}")
    print("\n=== entry neighborhood ===")
    for s in range(max(0, entry - 2), min(max_state, entry + 3) + 1):
        row = rows[s]
        suffix = " + terminal" if row["terminal"] else ""
        print(f"{s:3d} -> {row['handler']:<3} -> {row['next_states']}{suffix}")

    result = {
        "schema": "luraph-deobf.level3-state-graph.v1",
        "target_sha256": digest,
        "source_only": True,
        "interpretation": "successor edges are statically possible; runtime-dependent conditions are unioned",
        "entry_state": entry,
        "state_domain": {"min": 0, "max": max_state, "count": max_state + 1},
        "micro_handler_count": len(handlers),
        "exact_range_count": len(ranges),
        "ranges": ranges,
        "states": rows,
        "possibly_reachable_from_entry_count": len(possible),
        "not_reachable_even_in_static_overapprox": unreachable,
    }
    if args.json:
        args.json.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(f"\nwrote {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
