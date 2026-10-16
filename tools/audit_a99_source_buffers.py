#!/usr/bin/env python3
"""Test the hypothesis that all 11 observed A99 blocks read from outer J9 z[7].

Runtime observed [A321] first=1 for all eleven blocks. For each runtime A99
(seed,size,srcoff), this tool applies the verified LCG transform to the provided
candidate source buffer and compares the candidate first plaintext byte against
that observation.

For the known outer z[7] slice, block #1 matches and blocks #2..#11 do not.
That disproves reuse of this single source buffer for all eleven invocations.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

Z7_SHA256 = "158c17bfdd79cb23c036639223a730d9c8d2c4940cb07cbfb31aa97551b64891"

OBSERVED = [
    # index, seed_in, size, runtime srcoff
    (1, 164, 20936, 35915),
    (2, 325, 186, 67199),
    (3, 229, 462, 63804),
    (4, 129, 7397, 67610),
    (5, 305, 2479, 64645),
    (6, 339, 231, 76744),
    (7, 347, 640, 25107),
    (8, 281, 578, 33488),
    (9, 187, 738, 34478),
    (10, 283, 250, 27267),
    (11, 211, 3693, 20461),
]
EXPECTED_A321_FIRST = 1


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def first_plain(buf: bytes, seed_in: int, srcoff: int) -> int:
    if not 0 <= srcoff < len(buf):
        raise ValueError(f"srcoff {srcoff} outside candidate buffer len={len(buf)}")
    key0 = (seed_in + 240) & 0xFF
    key1 = (155 + key0 * 93) & 0xFF
    return buf[srcoff] ^ key1 ^ 240


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("candidate_buffer", type=Path)
    ap.add_argument("--json", type=Path)
    args = ap.parse_args()

    buf = args.candidate_buffer.read_bytes()
    digest = sha256(buf)
    if digest != Z7_SHA256:
        raise SystemExit(
            f"FAIL: candidate is not the verified outer z[7] buffer: sha256={digest}"
        )

    rows = []
    for index, seed_in, size, srcoff in OBSERVED:
        cand = first_plain(buf, seed_in, srcoff)
        rows.append({
            "index": index,
            "seed_in": seed_in,
            "size": size,
            "runtime_srcoff": srcoff,
            "runtime_A321_first": EXPECTED_A321_FIRST,
            "candidate_plain_first": cand,
            "matches_runtime_first": cand == EXPECTED_A321_FIRST,
        })

    matching = [r["index"] for r in rows if r["matches_runtime_first"]]
    result = {
        "schema": "luraph-deobf.a99-source-buffer-audit.v1",
        "candidate_buffer_sha256": digest,
        "candidate_buffer_size": len(buf),
        "runtime_observation": "A321 first=1 after every one of the 11 A99 decodes",
        "blocks": rows,
        "matching_block_indices": matching,
        "single_outer_z7_for_all_11": False,
        "conclusion": (
            "Only block 1 is consistent with reading its runtime srcoff from the verified "
            "outer J9 z[7] buffer. The other ten require distinct source-buffer provenance "
            "or another runtime context; do not apply a universal +1274 stage1 base."
        ),
    }

    if matching != [1]:
        raise SystemExit(
            f"FAIL: expected only block 1 to match the known trace, got matches={matching}"
        )

    if args.json:
        args.json.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
