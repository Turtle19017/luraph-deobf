#!/usr/bin/env python3
"""Locate A99 source spans in stage1 from runtime-decoded plaintext prefixes.

Input JSON contains one row per A99 invocation with:
  index, seed_in, size, runtime_srcoff, plain_head_hex

The tool re-encrypts each plaintext prefix with the verified LCG-XOR transform
and searches stage1.bin for exact byte occurrences. It reports all hits and the
implied buffer base (absolute_hit - runtime_srcoff). No entropy heuristic or
universal base assumption is used.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

STAGE1_SHA256 = "108da67ce0920931a4896896927fa127816bb9980d9fec2518bcad8ed472b2ec"


def cipher_prefix(seed_in: int, plain: bytes) -> bytes:
    key = (seed_in + 240) & 0xFF
    out = bytearray(len(plain))
    for i, p in enumerate(plain):
        key = (155 + key * 93) & 0xFF
        out[i] = p ^ key ^ 240
    return bytes(out)


def find_all(haystack: bytes, needle: bytes) -> list[int]:
    hits = []
    pos = 0
    while True:
        pos = haystack.find(needle, pos)
        if pos < 0:
            return hits
        hits.append(pos)
        pos += 1


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("stage1", type=Path)
    ap.add_argument("heads_json", type=Path)
    ap.add_argument("--json", type=Path)
    ap.add_argument("--min-prefix", type=int, default=8)
    args = ap.parse_args()

    stage1 = args.stage1.read_bytes()
    digest = hashlib.sha256(stage1).hexdigest()
    if digest != STAGE1_SHA256:
        raise SystemExit(f"FAIL: stage1 SHA mismatch: {digest}")

    obj = json.loads(args.heads_json.read_text(encoding="utf-8"))
    rows = obj["blocks"] if isinstance(obj, dict) else obj
    result_rows = []

    for row in rows:
        index = int(row["index"])
        seed = int(row["seed_in"])
        srcoff = int(row["runtime_srcoff"])
        plain = bytes.fromhex(row["plain_head_hex"])
        if len(plain) < args.min_prefix:
            raise SystemExit(
                f"FAIL: block {index} prefix only {len(plain)} bytes; "
                f"need >= {args.min_prefix}"
            )
        cipher = cipher_prefix(seed, plain)
        hits = find_all(stage1, cipher)
        result_rows.append({
            "index": index,
            "seed_in": seed,
            "runtime_srcoff": srcoff,
            "plain_head_hex": plain.hex(),
            "derived_cipher_head_hex": cipher.hex(),
            "stage1_hits": hits,
            "hit_count": len(hits),
            "implied_bases": [h - srcoff for h in hits],
            "unique_stage1_match": len(hits) == 1,
        })

    result = {
        "schema": "luraph-deobf.a99-cipher-span-locator.v1",
        "stage1_sha256": digest,
        "prefix_rule": "cipher[i] = plain[i] XOR key[i+1] XOR 240; key0=(seed+240)%256; key[n+1]=(155+93*key[n])%256",
        "blocks": result_rows,
    }
    print(json.dumps(result, indent=2))
    if args.json:
        args.json.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
