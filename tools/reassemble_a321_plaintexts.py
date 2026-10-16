#!/usr/bin/env python3
"""Reassemble runtime-dumped A321 plaintext buffers from hex chunk markers.

Expected marker format:
  [A321BEGIN] n <index> seed <seed> len <size> first <byte>
  [A321HEX]   n <index> off <offset> hex <hex-bytes>
  [A321END]   n <index>

The tool is intentionally independent of source-buffer provenance. It verifies
the known eleven (seed,size) pairs, contiguous chunk coverage, first byte == 1
for every block, and the reference SHA-256 for block #1.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

EXPECTED = [
    (1, 164, 20936),
    (2, 325, 186),
    (3, 229, 462),
    (4, 129, 7397),
    (5, 305, 2479),
    (6, 339, 231),
    (7, 347, 640),
    (8, 281, 578),
    (9, 187, 738),
    (10, 283, 250),
    (11, 211, 3693),
]
BLOCK1_SHA256 = "ecdc76fa288993cd2093564fe9a8b3f50f361dbe8f3282aa977c019e9954857e"


def ints(line: str) -> dict[str, int]:
    parts = re.split(r"[\s\t]+", line.strip())
    out: dict[str, int] = {}
    for i in range(1, len(parts) - 1):
        if parts[i] in {"n", "seed", "len", "first", "off"}:
            out[parts[i]] = int(parts[i + 1])
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("capture", type=Path)
    ap.add_argument("-o", "--out-dir", type=Path, default=Path("a321_plaintexts"))
    ap.add_argument("--receipt", type=Path)
    args = ap.parse_args()

    begins: dict[int, dict[str, int]] = {}
    chunks: dict[int, dict[int, bytes]] = {}
    ends: set[int] = set()

    for line in args.capture.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith("[A321BEGIN]"):
            kv = ints(line)
            n = kv["n"]
            if n in begins:
                raise SystemExit(f"FAIL: duplicate BEGIN for block {n}")
            begins[n] = kv
            chunks[n] = {}
        elif line.startswith("[A321HEX]"):
            kv = ints(line)
            n = kv["n"]
            m = re.search(r"(?:^|[\s\t])hex[\s\t]+([0-9a-fA-F]+)", line)
            if not m:
                raise SystemExit(f"FAIL: HEX marker missing hex payload: {line}")
            off = kv["off"]
            blob = bytes.fromhex(m.group(1))
            if n not in chunks:
                raise SystemExit(f"FAIL: HEX before BEGIN for block {n}")
            if off in chunks[n]:
                raise SystemExit(f"FAIL: duplicate chunk offset block {n}: {off}")
            chunks[n][off] = blob
        elif line.startswith("[A321END]"):
            kv = ints(line)
            ends.add(kv["n"])

    expected_map = {i: (seed, size) for i, seed, size in EXPECTED}
    if set(begins) != set(expected_map):
        raise SystemExit(
            f"FAIL: BEGIN blocks {sorted(begins)} != expected {sorted(expected_map)}"
        )
    if ends != set(expected_map):
        raise SystemExit(
            f"FAIL: END blocks {sorted(ends)} != expected {sorted(expected_map)}"
        )

    args.out_dir.mkdir(parents=True, exist_ok=True)
    rows = []

    for index, seed, size in EXPECTED:
        meta = begins[index]
        if meta.get("seed") != seed or meta.get("len") != size:
            raise SystemExit(
                f"FAIL: block {index} metadata seed/len "
                f"{meta.get('seed')}/{meta.get('len')} != {seed}/{size}"
            )
        if meta.get("first") != 1:
            raise SystemExit(f"FAIL: block {index} runtime first != 1")

        out = bytearray()
        cursor = 0
        for off in sorted(chunks[index]):
            if off != cursor:
                raise SystemExit(
                    f"FAIL: block {index} non-contiguous chunks: expected off {cursor}, got {off}"
                )
            blob = chunks[index][off]
            out += blob
            cursor += len(blob)

        if len(out) != size:
            raise SystemExit(
                f"FAIL: block {index} reconstructed len {len(out)} != {size}"
            )
        if not out or out[0] != 1:
            raise SystemExit(f"FAIL: block {index} reconstructed first byte != 1")

        digest = hashlib.sha256(out).hexdigest()
        if index == 1 and digest != BLOCK1_SHA256:
            raise SystemExit(f"FAIL: block1 SHA mismatch: {digest}")

        path = args.out_dir / f"block{index:02d}_seed{seed}.bin"
        path.write_bytes(out)
        rows.append({
            "index": index,
            "seed_in": seed,
            "size": size,
            "sha256": digest,
            "head16_hex": bytes(out[:16]).hex(),
            "output": str(path),
            "block1_reference_verified": index == 1,
        })

    receipt = {
        "schema": "luraph-deobf.a321-runtime-plaintext-dump.v1",
        "block_count": len(rows),
        "total_bytes": sum(r["size"] for r in rows),
        "all_first_bytes": 1,
        "block1_sha256": BLOCK1_SHA256,
        "blocks": rows,
    }
    print(json.dumps(receipt, indent=2))
    if args.receipt:
        args.receipt.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
