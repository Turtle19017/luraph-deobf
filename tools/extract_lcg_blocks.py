#!/usr/bin/env python3
"""Offline extractor for the eleven observed B:A LCG-XOR blocks.

Input:
  * the A-layer source buffer used by Sy(228), and
  * either a runtime trace containing [A99] markers with seed/size/src, or a
    JSON manifest with those fields.

Once the 11 source offsets are captured, this script performs no target/runtime
execution. It emits one plaintext block per A99 invocation, a concatenation in
trace order, and a receipt with hashes and structural checks.
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import math
import re
from pathlib import Path

EXPECTED = [
    (164, 20936),
    (325, 186),
    (229, 462),
    (129, 7397),
    (305, 2479),
    (339, 231),
    (347, 640),
    (281, 578),
    (187, 738),
    (283, 250),
    (211, 3693),
]
INC = 155
MULT = 93
XOR_CONST = 240
SEED_BIAS = 240


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    counts = collections.Counter(data)
    return -sum((v / n) * math.log2(v / n) for v in counts.values())


def named_int(line: str, name: str) -> int | None:
    m = re.search(rf"(?:^|[\s:=,]){re.escape(name)}(?:[\s:=]+)(-?\d+)", line)
    return int(m.group(1)) if m else None


def parse_trace(path: Path) -> list[dict[str, int]]:
    rows: list[dict[str, int]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if "[A99]" not in line:
            continue
        seed_in = named_int(line, "seed_in")
        seed0 = named_int(line, "seed0")
        size = named_int(line, "size")
        src = named_int(line, "src")
        if None in (seed_in, seed0, size, src):
            raise ValueError(f"incomplete A99 marker: {line}")
        rows.append({"seed_in": seed_in, "seed0": seed0, "size": size, "src": src})
    if not rows:
        raise ValueError("no [A99] markers found")
    return rows


def parse_manifest(path: Path) -> list[dict[str, int]]:
    obj = json.loads(path.read_text(encoding="utf-8"))
    rows = obj["blocks"] if isinstance(obj, dict) else obj
    out = []
    for i, row in enumerate(rows, 1):
        try:
            seed_in = int(row["seed_in"])
            size = int(row["size"])
            src = int(row["src"])
        except (KeyError, TypeError, ValueError) as e:
            raise ValueError(f"manifest block {i} missing integer seed_in/size/src") from e
        seed0 = int(row.get("seed0", (seed_in + SEED_BIAS) % 256))
        out.append({"seed_in": seed_in, "seed0": seed0, "size": size, "src": src})
    return out


def decode(cipher: bytes, row: dict[str, int]) -> bytes:
    seed_in, seed0, size, src = (row[k] for k in ("seed_in", "seed0", "size", "src"))
    expected_seed0 = (seed_in + SEED_BIAS) % 256
    if seed0 != expected_seed0:
        raise ValueError(f"seed0 mismatch for seed_in={seed_in}: {seed0} != {expected_seed0}")
    if size < 0 or src < 0 or src + size > len(cipher):
        raise ValueError(f"block seed={seed_in} range [{src},{src+size}) outside buffer len={len(cipher)}")

    key = seed0
    out = bytearray(size)
    for i, b in enumerate(cipher[src:src + size]):
        key = (INC + key * MULT) & 0xFF
        out[i] = b ^ key ^ XOR_CONST
    return bytes(out)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("buffer", type=Path, help="A-layer source/cipher buffer used by Sy(228)")
    source = ap.add_mutually_exclusive_group(required=True)
    source.add_argument("--trace", type=Path, help="runtime log with [A99] seed_in/seed0/size/src markers")
    source.add_argument("--manifest", type=Path, help="JSON block manifest containing seed_in/size/src")
    ap.add_argument("--out-dir", type=Path, default=Path("lcg_blocks"))
    ap.add_argument("--concat", type=Path, default=Path("luraph_A_lcg_all.bin"))
    ap.add_argument("--receipt", type=Path, default=Path("luraph_A_lcg_all.receipt.json"))
    ap.add_argument("--expect-known-sample", action="store_true")
    args = ap.parse_args()

    rows = parse_trace(args.trace) if args.trace else parse_manifest(args.manifest)
    if args.expect_known_sample:
        got = [(r["seed_in"], r["size"]) for r in rows]
        if got != EXPECTED:
            raise ValueError(f"block census mismatch: {got!r}")

    cipher = args.buffer.read_bytes()
    args.out_dir.mkdir(parents=True, exist_ok=True)
    decoded: list[bytes] = []
    receipt_rows = []

    for i, row in enumerate(rows, 1):
        plain = decode(cipher, row)
        decoded.append(plain)
        name = f"block_{i:02d}_seed_{row['seed_in']}.bin"
        out_path = args.out_dir / name
        out_path.write_bytes(plain)
        receipt_rows.append({
            "index": i,
            **row,
            "output": str(out_path),
            "sha256": sha256(plain),
            "entropy_bits_per_byte": entropy(plain),
            "head32_hex": plain[:32].hex(),
        })

    all_plain = b"".join(decoded)
    args.concat.write_bytes(all_plain)
    receipt = {
        "cipher_buffer": str(args.buffer),
        "cipher_size": len(cipher),
        "cipher_sha256": sha256(cipher),
        "lcg": {"seed_bias": SEED_BIAS, "inc": INC, "mult": MULT, "xor": XOR_CONST},
        "block_count": len(rows),
        "total_decoded_bytes": len(all_plain),
        "blocks": receipt_rows,
        "concat": str(args.concat),
        "concat_sha256": sha256(all_plain),
        "concat_entropy_bits_per_byte": entropy(all_plain),
    }
    args.receipt.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(receipt, indent=2))


if __name__ == "__main__":
    main()
