#!/usr/bin/env python3
"""Extract conservative mode233 handler write footprints from the protected source.

Offline only. This tool does not execute Luau and does not infer reachability.

It scopes extraction to the source branch whose condition is cR==233, then
splits the flattened if/elseif t==N opcode dispatcher. For selected opcodes it
records direct BR assignment destinations, lane aliases, possible BR range
mutators, calls through BR values, and lane self-rewrites.

The result is a source-handler footprint, not a control-flow trace.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

TARGET_SHA256 = "02dc0c6a922796ad4773cbd051745225e4d6bf84d61c9b8c666be71b57f58443"

DEFAULT_OPCODES = {
    1, 11, 21, 26, 30, 31, 32, 34, 38, 48, 56, 60, 61, 64, 66, 68,
    70, 72, 73, 83, 84, 85, 91, 96, 97, 98, 99, 101, 103, 106, 110,
    115, 116, 120, 124,
}

OP21_EXACT_BODY = (
    "N,a,p=s[l],w[l],H[l];g=N+a;n=BR[g];i=n[J];"
    "M=a+i-1;n[J]=M;k(n,1,i,a,n);k(BR,N+1,g-1,1,n);"
    "BR[N]=Y(BR[N](Z(n,1,n[J])));"
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def compact(s: str) -> str:
    return re.sub(r"\s+", "", s)


def locate_mode233_branch(src: str) -> tuple[str, int, int]:
    markers = list(re.finditer(r"(?:if|elseif)\s+cR\s*==\s*233\s+then", src))
    if len(markers) != 1:
        raise ValueError(f"expected one cR==233 branch, got {len(markers)}")
    start = markers[0].end()

    op21 = src.find("elseif t==21 then", start)
    if op21 < 0:
        raise ValueError("mode233 branch has no opcode21 anchor")

    tail_re = re.compile(
        r"elseif\s+t\s*==\s*21\s+then\s*"
        r"N,a,p=s\[l\],w\[l\],H\[l\];g=N\+a;n=BR\[g\];i=n\[J\];"
        r"M=a\+i-1;n\[J\]=M;k\(n,1,i,a,n\);k\(BR,N\+1,g-1,1,n\);"
        r"BR\[N\]=Y\(BR\[N\]\(Z\(n,1,n\[J\]\)\)\);"
        r"else\s+BR\[s\[l\]\]=BR\[H\[l\]\]<w\[l\];end;"
    )
    tm = tail_re.search(src, op21)
    if not tm:
        raise ValueError("exact mode233 opcode21/default tail not found")
    end = tm.end()
    return src[start:end], start, end


def split_t_dispatch(branch: str) -> dict[int, str]:
    markers = list(re.finditer(r"(?:if|elseif)\s+t\s*==\s*(\d+)\s+then", branch))
    if not markers:
        raise ValueError("no t==N opcode clauses in mode233 branch")

    opcodes = [int(m.group(1)) for m in markers]
    if len(opcodes) != len(set(opcodes)):
        dup = sorted({x for x in opcodes if opcodes.count(x) > 1})
        raise ValueError(f"duplicate mode233 opcode markers: {dup}")

    out = {}
    for i, m in enumerate(markers):
        op = int(m.group(1))
        body_end = markers[i + 1].start() if i + 1 < len(markers) else len(branch)
        body = branch[m.end():body_end]
        if op == 21:
            default = re.search(
                r"else\s+BR\[s\[l\]\]=BR\[H\[l\]\]<w\[l\];end;\s*$",
                body,
            )
            if not default:
                raise ValueError("opcode21 clause missing exact final default")
            body = body[:default.start()]
        out[op] = body

    if 21 not in out:
        raise ValueError("opcode21 missing after split")
    if compact(out[21]) != compact(OP21_EXACT_BODY):
        raise ValueError("opcode21 body differs from exact guarded semantics")
    return out


def alias_map(body: str) -> dict[str, str]:
    aliases = {}
    pat = re.compile(
        r"([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)+)\s*=\s*"
        r"((?:[SswH]\[l\])(?:\s*,\s*(?:[SswH]\[l\]))+)"
    )
    for m in pat.finditer(body):
        lhs = [x.strip() for x in m.group(1).split(",")]
        rhs = [re.match(r"([SswH])\[l\]", x.strip()).group(1)
               for x in m.group(2).split(",")]
        if len(lhs) == len(rhs):
            aliases.update(zip(lhs, rhs))

    for m in re.finditer(r"\b([A-Za-z_]\w*)\s*=\s*([SswH])\[l\]", body):
        aliases[m.group(1)] = m.group(2)
    return aliases


def resolve_dest(expr: str, aliases: dict[str, str]) -> dict:
    expr = expr.strip()
    if expr in ("s[l]", "w[l]", "H[l]", "S[l]"):
        return {"kind": "lane", "field": expr[0], "expr": expr}
    if expr in aliases:
        return {
            "kind": "lane_alias",
            "field": aliases[expr],
            "alias": expr,
            "expr": expr,
        }
    if re.fullmatch(r"\d+", expr):
        return {"kind": "constant", "register": int(expr), "expr": expr}
    return {"kind": "expression", "expr": expr}


def iter_br_assignment_lhs(body: str):
    """Yield (offset, inner_expr) for direct top-level BR[expr] assignments."""
    pos = 0
    while True:
        start = body.find("BR[", pos)
        if start < 0:
            return
        i = start + 3
        depth = 1
        while i < len(body) and depth:
            if body[i] == "[":
                depth += 1
            elif body[i] == "]":
                depth -= 1
            i += 1
        if depth:
            return

        expr = body[start + 3:i - 1]
        j = i
        while j < len(body) and body[j].isspace():
            j += 1
        if j < len(body) and body[j] == "=":
            if not (j + 1 < len(body) and body[j + 1] == "="):
                yield start, expr
        pos = i


def direct_br_writes(body: str, aliases: dict[str, str]) -> list[dict]:
    rows = [
        {
            "offset": offset,
            "destination": resolve_dest(expr, aliases),
        }
        for offset, expr in iter_br_assignment_lhs(body)
    ]

    seen = set()
    out = []
    for row in rows:
        key = (row["offset"], json.dumps(row["destination"], sort_keys=True))
        if key not in seen:
            seen.add(key)
            out.append(row)
    return out


def helper_calls_with_br(body: str) -> list[dict]:
    rows = []
    for m in re.finditer(r"\b([A-Za-z_]\w*)\s*\(([^;()]*)\)", body):
        fn, args = m.group(1), m.group(2)
        if re.search(r"(?:^|,)\s*BR\s*(?:,|$)", args):
            rows.append({
                "function": fn,
                "args": args.strip(),
                "offset": m.start(),
            })
    return rows


def br_value_calls(body: str) -> list[dict]:
    rows = []
    for m in re.finditer(r"BR\[([^\]]+)\]\s*\(", body):
        rows.append({
            "kind": "direct_BR_value_call",
            "expr": m.group(1),
            "offset": m.start(),
        })

    br_aliases = set()
    for m in re.finditer(r"\b([A-Za-z_]\w*)\s*=\s*BR\[[^\]]+\]", body):
        br_aliases.add(m.group(1))
    for name in sorted(br_aliases):
        for m in re.finditer(r"\b" + re.escape(name) + r"\s*\(", body):
            rows.append({
                "kind": "BR_alias_call",
                "alias": name,
                "offset": m.start(),
            })
    return rows


def all_named_calls(body: str) -> list[dict]:
    rows = []
    keywords = {"if", "elseif", "for", "while", "function", "return"}
    for m in re.finditer(r"\b([A-Za-z_]\w*)\s*\(", body):
        name = m.group(1)
        if name not in keywords:
            rows.append({"name": name, "offset": m.start()})
    return rows


def footprint(op: int, body: str) -> dict:
    aliases = alias_map(body)
    direct = direct_br_writes(body, aliases)
    helper = helper_calls_with_br(body)
    value_calls = br_value_calls(body)
    all_calls = all_named_calls(body)
    lane_rewrites = sorted(set(
        m.group(1)
        for m in re.finditer(r"\b([SswH])\[l\]\s*=", body)
    ))

    resolved_lanes = sorted({
        row["destination"]["field"]
        for row in direct
        if row["destination"]["kind"] in ("lane", "lane_alias")
    })
    constants = sorted({
        row["destination"]["register"]
        for row in direct
        if row["destination"]["kind"] == "constant"
    })
    unknown_dests = [
        row["destination"]["expr"]
        for row in direct
        if row["destination"]["kind"] == "expression"
    ]

    if direct and not unknown_dests and not helper and not all_calls:
        cls = "DIRECT_BR_WRITE_FOOTPRINT"
    elif not direct and not all_calls:
        cls = "NO_TOP_LEVEL_BR_WRITE_OBSERVED"
    else:
        cls = "MIXED_OR_SIDE_EFFECT_GAP"

    return {
        "opcode": op,
        "classification": cls,
        "aliases": aliases,
        "direct_br_writes": direct,
        "direct_dest_lane_fields": resolved_lanes,
        "direct_dest_constants": constants,
        "unknown_direct_dest_expressions": unknown_dests,
        "helper_calls_with_BR": helper,
        "calls_through_BR_values": value_calls,
        "all_named_calls": all_calls,
        "lane_self_rewrites": lane_rewrites,
        "body_sha256": sha256(body.encode("utf-8")),
        "body_length": len(body),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("script", type=Path)
    ap.add_argument("--opcodes", nargs="*", type=int)
    ap.add_argument("--json-out", type=Path)
    args = ap.parse_args()

    raw = args.script.read_bytes()
    got = sha256(raw)
    if got != TARGET_SHA256:
        raise SystemExit(f"FAIL: target SHA mismatch: {got}")

    try:
        src = raw.decode("utf-8")
        branch, start, end = locate_mode233_branch(src)
        clauses = split_t_dispatch(branch)

        wanted = sorted(set(args.opcodes or DEFAULT_OPCODES))
        missing = [op for op in wanted if op not in clauses]
        if missing:
            raise ValueError(f"requested opcodes absent from mode233 dispatch: {missing}")

        fps = {str(op): footprint(op, clauses[op]) for op in wanted}
        result = {
            "schema": "luraph-deobf.mode233-handler-write-footprints.v1",
            "target_sha256": TARGET_SHA256,
            "mode233_branch": {
                "source_start": start,
                "source_end": end,
                "sha256": sha256(branch.encode("utf-8")),
                "opcode_clause_count": len(clauses),
            },
            "requested_opcodes": wanted,
            "footprints": fps,
            "scope": "source handler write footprints only; no execution/reachability proof",
            "no_target_execution": True,
        }

        if args.json_out:
            args.json_out.parent.mkdir(parents=True, exist_ok=True)
            args.json_out.write_text(
                json.dumps(result, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )

        counts = {}
        for fp in fps.values():
            counts[fp["classification"]] = counts.get(fp["classification"], 0) + 1
        print(f"mode233 opcode clauses: {len(clauses)}")
        print(f"requested footprints: {len(fps)}")
        for key in sorted(counts):
            print(f"{key}: {counts[key]}")
        print("proof: HANDLER_FOOTPRINTS_ONLY")
        print("No target execution performed")
        return 0
    except (ValueError, UnicodeDecodeError) as exc:
        raise SystemExit(f"FAIL: {exc}") from exc


if __name__ == "__main__":
    raise SystemExit(main())
