#!/usr/bin/env python3
"""Recover the verified outer J9 z[7] buffer directly from stage1.bin.

The earlier J9 handoff established that z[7] is a byte-for-byte copy of:

    stage1[1274 : 1274 + 79999]

This tool does not replay the J9 VM. It reconstructs the copied buffer directly
and fails closed on the known stage1 and z[7] SHA-256 digests.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

STAGE1_SHA256 = "108da67ce0920931a4896896927fa127816bb9980d9fec2518bcad8ed472b2ec"
Z7_OFFSET = 1274
Z7_SIZE = 79999
Z7_SHA256 = "158c17bfdd79cb23c036639223a730d9c8d2c4940cb07cbfb31aa97551b64891"
Z7_HEAD64 = bytes.fromhex(
    "2d06fa48cbb5c5eb03b44b9226fb422d0aa02405849f478cc65fb1e939191dac"
    "32de24eda21e61e9e520fb3a509da401dc38d079858d6911da44d98a485feaa8"
)
RUNTIME_CURSOR = 63037
RUNTIME_BYTE = 45


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("stage1", type=Path)
    ap.add_argument("-o", "--out", type=Path, default=Path("luraph_j9_z_7.bin"))
    ap.add_argument("--receipt", type=Path)
    args = ap.parse_args()

    stage1 = args.stage1.read_bytes()
    got_stage1 = sha256(stage1)
    if got_stage1 != STAGE1_SHA256:
        raise SystemExit(f"FAIL: stage1 SHA mismatch: {got_stage1}")

    end = Z7_OFFSET + Z7_SIZE
    if end > len(stage1):
        raise SystemExit(
            f"FAIL: z7 slice [{Z7_OFFSET},{end}) exceeds stage1 len={len(stage1)}"
        )

    z7 = stage1[Z7_OFFSET:end]
    got_z7 = sha256(z7)
    if got_z7 != Z7_SHA256:
        raise SystemExit(f"FAIL: z7 SHA mismatch: {got_z7}")
    if z7[:64] != Z7_HEAD64:
        raise SystemExit("FAIL: z7 head64 mismatch")
    if z7[RUNTIME_CURSOR] != RUNTIME_BYTE:
        raise SystemExit(
            f"FAIL: z7[{RUNTIME_CURSOR}]={z7[RUNTIME_CURSOR]} != runtime byte {RUNTIME_BYTE}"
        )

    args.out.write_bytes(z7)
    receipt = {
        "schema": "luraph-deobf.j9-z7-slice.v1",
        "stage1_sha256": got_stage1,
        "stage1_offset": Z7_OFFSET,
        "size": len(z7),
        "sha256": got_z7,
        "head64_hex": z7[:64].hex(),
        "runtime_crosscheck": {
            "cursor": RUNTIME_CURSOR,
            "byte": RUNTIME_BYTE,
            "candidate_byte": z7[RUNTIME_CURSOR],
            "matches": True,
            "stage1_absolute_offset": Z7_OFFSET + RUNTIME_CURSOR,
        },
        "identity_scope": (
            "Byte-content identity with the previously verified J9 z[7] copy is established. "
            "This does not claim object/pointer identity for the runtime buffer."
        ),
    }
    if args.receipt:
        args.receipt.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(receipt, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
