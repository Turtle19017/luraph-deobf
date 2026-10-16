#!/usr/bin/env python3
"""Validate the post-B:A finalized lane snapshot for block #1.

Consumes capture output from tools/make_A_final_lane_probe.py and compares the
finalized main lanes against the independently parsed serialized lane seeds.

The comparison deliberately separates:
  * object metadata (dispatch/mode/entry/stack)
  * main lanes op/S/w/H
  * auxiliary companion lanes av/aI/aV/aK

The serialized companion arrays are allocated empty, so any non-nil finalized
aux value in the sampled slots is evidence that post-fill finalization populated
them.

This tool does not execute or emulate B[68].
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

EXPECTED_META = {
    "dispatch": "68",
    "pc": "4453",
    "mode": "215",
    "stack": "130",
}

EXPECTED_BOOTSTRAP = {
    4453: {"op": "52", "S": "12", "w": "1", "H": "0"},
    4454: {"op": "39", "S": "15", "w": "77", "H": "0"},
    4455: {"op": "24", "S": "88", "w": "78", "H": "0"},
    4456: {"op": "24", "S": "43", "w": "79", "H": "0"},
    4457: {"op": "24", "S": "72", "w": "58", "H": "0"},
    4458: {"op": "39", "S": "87", "w": "48", "H": "0"},
    4459: {"op": "24", "S": "19", "w": "50", "H": "0"},
    4460: {"op": "24", "S": "25", "w": "80", "H": "0"},
    4461: {"op": "24", "S": "61", "w": "10", "H": "0"},
    4462: {"op": "39", "S": "114", "w": "81", "H": "0"},
    4463: {"op": "24", "S": "23", "w": "82", "H": "0"},
    4464: {"op": "24", "S": "20", "w": "83", "H": "0"},
    4465: {"op": "24", "S": "47", "w": "84", "H": "0"},
    4466: {"op": "39", "S": "96", "w": "85", "H": "0"},
    4467: {"op": "24", "S": "22", "w": "86", "H": "0"},
    4468: {"op": "24", "S": "97", "w": "87", "H": "0"},
    4469: {"op": "24", "S": "8", "w": "11", "H": "0"},
    4470: {"op": "32", "S": "0", "w": "37", "H": "19"},
    4471: {"op": "15", "S": "0", "w": "10", "H": "0"},
}

EXPECTED_PC11_MAIN = {"op": "23", "S": "46", "w": "12326", "H": "74"}
AUX_KEYS = ("av", "aI", "aV", "aK")
MAIN_KEYS = ("op", "S", "w", "H")


def parse_kv(line: str) -> dict[str, str]:
    # Markers are print() fields separated by tabs in Luau output.
    parts = re.split(r"[\t ]+", line.strip())
    out: dict[str, str] = {}
    i = 1
    while i + 1 < len(parts):
        out[parts[i]] = parts[i + 1]
        i += 2
    return out


def one(lines: list[str], marker: str) -> str:
    hits = [line for line in lines if line.startswith(marker)]
    if len(hits) != 1:
        raise SystemExit(f"FAIL: expected exactly one {marker}, got {len(hits)}")
    return hits[0]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("capture", type=Path)
    ap.add_argument("--json", type=Path)
    args = ap.parse_args()

    lines = args.capture.read_text(encoding="utf-8", errors="replace").splitlines()

    meta = parse_kv(one(lines, "[AFINALMETA]"))
    lens = parse_kv(one(lines, "[AFINALLEN]"))
    helper = parse_kv(one(lines, "[AFINALHELPER]"))
    entry = parse_kv(one(lines, "[AFINALENTRY]"))
    pc11 = parse_kv(one(lines, "[AFINAL11]"))

    meta_mismatches = {
        key: {"expected": expected, "actual": meta.get(key)}
        for key, expected in EXPECTED_META.items()
        if meta.get(key) != expected
    }

    slot_lines = [line for line in lines if line.startswith("[AFINALSLOT]")]
    slots: dict[int, dict[str, str]] = {}
    for line in slot_lines:
        row = parse_kv(line)
        if "pc" not in row:
            raise SystemExit(f"FAIL: AFINALSLOT missing pc: {line}")
        pc = int(row["pc"])
        if pc in slots:
            raise SystemExit(f"FAIL: duplicate AFINALSLOT pc={pc}")
        slots[pc] = row

    expected_pcs = set(EXPECTED_BOOTSTRAP)
    missing = sorted(expected_pcs - set(slots))
    if missing:
        raise SystemExit(f"FAIL: missing finalized bootstrap slots: {missing}")

    main_diffs = []
    aux_population = []
    rows = []
    for pc in sorted(EXPECTED_BOOTSTRAP):
        actual = slots[pc]
        expected = EXPECTED_BOOTSTRAP[pc]
        diffs = {
            key: {"serialized": expected[key], "finalized": actual.get(key)}
            for key in MAIN_KEYS
            if actual.get(key) != expected[key]
        }
        aux = {key: actual.get(key) for key in AUX_KEYS}
        populated = {key: val for key, val in aux.items() if val not in (None, "nil")}
        if diffs:
            main_diffs.append({"pc": pc, "diffs": diffs})
        if populated:
            aux_population.append({"pc": pc, "values": populated})
        rows.append({
            "pc": pc,
            "serialized_main": expected,
            "finalized_main": {key: actual.get(key) for key in MAIN_KEYS},
            "main_changed": bool(diffs),
            "finalized_aux": aux,
        })

    pc11_diffs = {
        key: {"serialized": EXPECTED_PC11_MAIN[key], "finalized": pc11.get(key)}
        for key in MAIN_KEYS
        if pc11.get(key) != EXPECTED_PC11_MAIN[key]
    }
    pc11_aux = {key: pc11.get(key) for key in AUX_KEYS}
    pc11_aux_populated = {
        key: val for key, val in pc11_aux.items() if val not in (None, "nil")
    }

    result = {
        "schema": "luraph-deobf.a321-finalized-lanes.v1",
        "metadata": meta,
        "metadata_mismatches": meta_mismatches,
        "lane_lengths": lens,
        "B3_helper": helper,
        "entry_marker": entry,
        "bootstrap_slot_count": len(rows),
        "bootstrap_main_lane_differences": main_diffs,
        "bootstrap_main_lanes_unchanged": not main_diffs,
        "bootstrap_aux_population": aux_population,
        "bootstrap_any_aux_populated": bool(aux_population),
        "pc11": {
            "serialized_main": EXPECTED_PC11_MAIN,
            "finalized_main": {key: pc11.get(key) for key in MAIN_KEYS},
            "main_differences": pc11_diffs,
            "main_unchanged": not pc11_diffs,
            "finalized_aux": pc11_aux,
            "aux_populated": pc11_aux_populated,
        },
        "slots": rows,
        "interpretation": (
            "If main lanes are unchanged but auxiliary lanes are populated, "
            "post-fill finalization preserves serialized op/S/w/H seeds while "
            "materializing companion per-slot data. If main lanes differ, "
            "model B[3] before runtime disassembly."
        ),
    }

    print(json.dumps(result, indent=2))
    if args.json:
        args.json.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
