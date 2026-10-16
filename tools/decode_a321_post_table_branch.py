#!/usr/bin/env python3
"""Classify the common post-table B:A branch across all 11 A321 plaintexts.

The first-table parser already establishes table_end for every object and shows
that the next serialized integer is 215 (encoded as 81 57) in all eleven.

This tool follows the exact source path immediately after that integer:

  table_end:
    82(M)  reads b0
    272(zy) reads b1
    275(Yy) decodes 215 and advances cursor by 2
    147(p)  reads meta16 byte at +2
      <128  -> 167(_)
      >=128 -> 267(...)
    167(_) advances cursor by 1
    46(G)   reads meta5 byte at +3
      <128  -> 229(Sy)
      >=128 -> 490(...)
    229(Sy) advances cursor by 1
    10(o)   reads selector byte at +4
      <128  -> 425(...)
      >=128 -> 328(Ey) -> 237(Ty)

It reports branch signatures and raw bytes; it does not force all objects to
match block #1. Inputs are verified against the runtime plaintext receipt.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from decode_a321_first_tables import decode_one, derive_count, resolve_file, TABLE_START


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def recompute_table_end(data: bytes) -> tuple[int, int]:
    _, count = derive_count(data)
    pos = TABLE_START
    for _ in range(count):
        _, pos, _ = decode_one(data, pos)
    return count, pos


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("plaintext_dir", type=Path)
    ap.add_argument(
        "--runtime-receipt",
        type=Path,
        default=Path(__file__).resolve().parents[1]
        / "receipts" / "luraph_A321_plaintexts.runtime.json",
    )
    ap.add_argument("--json", type=Path)
    args = ap.parse_args()

    runtime = json.loads(args.runtime_receipt.read_text(encoding="utf-8"))
    blocks = runtime.get("blocks")
    if not isinstance(blocks, list) or len(blocks) != 11:
        raise SystemExit("FAIL: runtime receipt must contain exactly 11 blocks")

    rows = []
    for meta in blocks:
        index = int(meta["index"])
        path = resolve_file(args.plaintext_dir, meta)
        data = path.read_bytes()

        if len(data) != int(meta["size"]):
            raise SystemExit(f"FAIL: block {index} size mismatch")
        digest = sha256(data)
        if digest != meta["sha256"]:
            raise SystemExit(f"FAIL: block {index} SHA mismatch: {digest}")
        if data[:16].hex() != meta["head16_hex"]:
            raise SystemExit(f"FAIL: block {index} head16 mismatch")

        count, table_end = recompute_table_end(data)

        tag, tag_end, tag_width = decode_one(data, table_end)
        if tag != 215 or tag_width != 2:
            raise SystemExit(
                f"FAIL: block {index} post-table integer {tag}/width{tag_width} != 215/2"
            )
        if data[table_end:tag_end] != bytes.fromhex("8157"):
            raise SystemExit(
                f"FAIL: block {index} post-table encoding "
                f"{data[table_end:tag_end].hex()} != 8157"
            )

        if tag_end + 3 > len(data):
            raise SystemExit(f"FAIL: block {index} truncated after post-table tag")

        meta16 = data[tag_end]
        branch147 = 167 if meta16 < 128 else 267

        meta5 = data[tag_end + 1]
        # state46 is only reached through the block-1-compatible 147->167 branch.
        branch46 = (229 if meta5 < 128 else 490) if branch147 == 167 else None

        selector = data[tag_end + 2]
        # state10 is only reached through 46->229.
        branch10 = (
            328 if selector >= 128 else 425
            if branch147 == 167 and branch46 == 229
            else None
        )
        # Avoid Python conditional-precedence ambiguity in the emitted meaning.
        if not (branch147 == 167 and branch46 == 229):
            branch10 = None

        reaches237 = branch147 == 167 and branch46 == 229 and selector >= 128

        rows.append({
            "index": index,
            "seed_in": int(meta["seed_in"]),
            "table_count": count,
            "table_end": table_end,
            "tag215": {
                "offset": table_end,
                "end_offset": tag_end,
                "encoding_hex": data[table_end:tag_end].hex(),
                "value": tag,
                "width": tag_width,
            },
            "meta16": {
                "offset": tag_end,
                "byte": meta16,
                "state147_next": branch147,
            },
            "meta5": {
                "offset": tag_end + 1,
                "byte": meta5,
                "state46_next": branch46,
            },
            "selector": {
                "offset": tag_end + 2,
                "byte": selector,
                "state10_next": branch10,
            },
            "block1_compatible_suffix_path": reaches237,
            "suffix_path_if_compatible": [82,272,275,147,167,46,229,10,328,237]
                if reaches237 else None,
            "cursor_at_state237": tag_end + 3 if reaches237 else None,
            "raw5_hex": data[table_end:tag_end + 3].hex(),
        })

    compatible = [r["index"] for r in rows if r["block1_compatible_suffix_path"]]
    signatures = {}
    for r in rows:
        sig = (
            r["meta16"]["state147_next"],
            r["meta5"]["state46_next"],
            r["selector"]["state10_next"],
        )
        signatures.setdefault(str(sig), []).append(r["index"])

    result = {
        "schema": "luraph-deobf.a321-post-table-branch.v1",
        "block_count": len(rows),
        "invariant_tag": {"value": 215, "width": 2, "encoding_hex": "8157"},
        "block1_compatible_suffix_blocks": compatible,
        "branch_signature_groups": signatures,
        "blocks": rows,
    }

    print(json.dumps(result, indent=2))
    if args.json:
        args.json.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
