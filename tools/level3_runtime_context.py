#!/usr/bin/env python3
"""Validate a level-3 runtime trace against the source-derived state graph.

Optionally compare the [L3VP8] runtime buffer facts with a candidate buffer
(such as the 79,999-byte J9 handoff z[7] buffer). This does not claim pointer
identity from length alone: it reports exactly which runtime facts match.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
from pathlib import Path


def parse_kv_int(line: str, key: str) -> int:
    m = re.search(rf"(?:^|[\s\t]){re.escape(key)}[\s\t]+(-?\d+)", line)
    if not m:
        raise ValueError(f"{key} missing from marker: {line}")
    return int(m.group(1))


def parse_capture(path: Path) -> tuple[dict, list[int], list[dict]]:
    vp = []
    states: list[int] = []
    terms = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith("[L3VP8]"):
            vp.append({
                "proto": parse_kv_int(line, "proto"),
                "cursor": parse_kv_int(line, "cursor"),
                "byte": parse_kv_int(line, "byte"),
                "buflen": parse_kv_int(line, "buflen"),
                "raw": line,
            })
        elif line.startswith("[L3CHUNK]") or line.startswith("[L3TAIL]"):
            run = parse_kv_int(line, "run")
            if run != 1:
                continue
            m = re.search(r"(?:^|[\s\t])states[\s\t]+([0-9,]+)", line)
            if not m:
                raise ValueError(f"states payload missing: {line}")
            states.extend(int(x) for x in m.group(1).split(",") if x)
        elif line.startswith("[L3TERM]"):
            terms.append({
                "run": parse_kv_int(line, "run"),
                "n": parse_kv_int(line, "n"),
            })
    if len(vp) != 1:
        raise ValueError(f"expected exactly one [L3VP8], got {len(vp)}")
    if not states:
        raise ValueError("no run-1 level3 states found")
    return vp[0], states, terms


def load_graph(path: Path) -> dict[int, dict]:
    rows = {}
    with path.open("r", encoding="utf-8", newline="") as fh:
        for row in csv.DictReader(fh, delimiter="\t"):
            state = int(row["state"])
            nxt = {int(x) for x in row["next_states"].split(",") if x}
            rows[state] = {
                "handler": row["handler"],
                "next_states": nxt,
                "terminal": row["terminal"].lower() == "true",
            }
    if not rows:
        raise ValueError("empty state graph")
    return rows


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("capture", type=Path)
    ap.add_argument(
        "--graph", type=Path,
        default=Path(__file__).resolve().parents[1] / "receipts" / "luraph_level3_state_graph.tsv",
    )
    ap.add_argument("--candidate-buffer", type=Path)
    ap.add_argument("--json", type=Path)
    args = ap.parse_args()

    vp, states, terms = parse_capture(args.capture)
    graph = load_graph(args.graph)

    violations = []
    for a, b in zip(states, states[1:]):
        if a not in graph:
            violations.append(f"state {a} missing from graph")
            continue
        if b not in graph[a]["next_states"]:
            violations.append(
                f"runtime edge {a}->{b} not in static successors "
                f"{sorted(graph[a]['next_states'])}"
            )

    run1_terms = [x for x in terms if x["run"] == 1]
    terminal_ok = bool(run1_terms) and states[-1] in graph and graph[states[-1]]["terminal"]
    if run1_terms and run1_terms[-1]["n"] != len(states):
        violations.append(
            f"run1 terminal n={run1_terms[-1]['n']} != observed state count {len(states)}"
        )

    candidate = None
    if args.candidate_buffer:
        data = args.candidate_buffer.read_bytes()
        cursor_in_range = 0 <= vp["cursor"] < len(data)
        byte_at_cursor = data[vp["cursor"]] if cursor_in_range else None
        candidate = {
            "path": str(args.candidate_buffer),
            "sha256": hashlib.sha256(data).hexdigest(),
            "size": len(data),
            "runtime_buflen": vp["buflen"],
            "size_matches_runtime": len(data) == vp["buflen"],
            "cursor": vp["cursor"],
            "cursor_in_range": cursor_in_range,
            "runtime_byte": vp["byte"],
            "candidate_byte_at_cursor": byte_at_cursor,
            "byte_matches_runtime": cursor_in_range and byte_at_cursor == vp["byte"],
            "identity_status": (
                "consistent-with-runtime-marker"
                if len(data) == vp["buflen"] and cursor_in_range and byte_at_cursor == vp["byte"]
                else "does-not-match-runtime-marker"
            ),
            "note": (
                "Length+cursor-byte agreement is strong consistency evidence, "
                "but it is not a cryptographic runtime pointer identity proof."
            ),
        }

    result = {
        "schema": "luraph-deobf.level3-runtime-context.v1",
        "vp8": {k: v for k, v in vp.items() if k != "raw"},
        "states": states,
        "state_count": len(states),
        "handlers": [graph[s]["handler"] if s in graph else None for s in states],
        "all_runtime_edges_in_static_graph": not violations,
        "terminal_state": states[-1],
        "terminal_matches_graph": terminal_ok,
        "run1_terminal_markers": run1_terms,
        "later_terminal_marker_count": sum(1 for x in terms if x["run"] != 1),
        "later_run_note": (
            "The current probe traces states only when run==1. Therefore n=0 on later "
            "[L3TERM] markers does NOT mean those invocations executed zero states."
        ),
        "violations": violations,
        "candidate_buffer": candidate,
    }

    print(json.dumps(result, indent=2))
    if args.json:
        args.json.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")

    if violations or not terminal_ok:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
