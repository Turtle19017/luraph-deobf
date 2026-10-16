#!/usr/bin/env python3
"""Lift the verified block-1 level-3 prefix after a runtime [L3VP8] marker.

This is deliberately narrow. Runtime supplies only the identity facts the source
cannot prove by itself (proto index, cursor, entry byte, buffer length). Once
those agree with the verified block-1 bytes, the early state transitions and the
first nested 93/155/93 LCG-XOR peel are deterministic from source.
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import math
import re
from pathlib import Path

BLOCK1_SHA256 = "ecdc76fa288993cd2093564fe9a8b3f50f361dbe8f3282aa977c019e9954857e"


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    return -sum((v / n) * math.log2(v / n) for v in collections.Counter(data).values())


def parse_marker(path: Path) -> dict[str, int]:
    hits = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.startswith("[L3VP8]"):
            continue
        vals = {}
        for key in ("proto", "cursor", "byte", "buflen"):
            m = re.search(rf"(?:^|[\s\t]){key}[\s\t]+(-?\d+)", line)
            if not m:
                raise ValueError(f"incomplete [L3VP8] marker ({key} missing): {line}")
            vals[key] = int(m.group(1))
        hits.append(vals)
    if len(hits) != 1:
        raise ValueError(f"expected exactly one [L3VP8] marker, got {len(hits)}")
    return hits[0]


def parse_trace_states(path: Path) -> list[int]:
    states: list[int] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not (line.startswith("[L3CHUNK]") or line.startswith("[L3TAIL]")):
            continue
        m = re.search(r"(?:^|[\\s\\t])states[\\s\\t]+([0-9,]+)", line)
        if not m:
            raise ValueError(f"trace marker missing states payload: {line}")
        states.extend(int(x) for x in m.group(1).split(",") if x)
    if not states:
        raise ValueError("capture has no [L3CHUNK]/[L3TAIL] states")
    return states


def nested_decode(block: bytes, proto: int, start: int, size: int) -> bytes:
    if start < 0 or size < 0 or start + size > len(block):
        raise ValueError("nested LCG range outside block1")
    key = (93 + proto) & 0xFF
    out = bytearray(size)
    for i, c in enumerate(block[start:start + size]):
        key = (155 + 93 * key) & 0xFF
        out[i] = c ^ key ^ 93
    return bytes(out)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("block1", type=Path)
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--capture", type=Path, help="capture containing one [L3VP8] marker")
    src.add_argument("--proto", type=int, help="runtime proto value (requires --cursor)")
    ap.add_argument("--cursor", type=int)
    ap.add_argument("--entry-byte", type=int, default=None)
    ap.add_argument("--buflen", type=int, default=None)
    ap.add_argument("--json", type=Path, default=None)
    args = ap.parse_args()

    block = args.block1.read_bytes()
    digest = hashlib.sha256(block).hexdigest()
    if digest != BLOCK1_SHA256:
        raise SystemExit(f"FAIL: block1 SHA mismatch: {digest}")

    observed_states: list[int] | None = None
    if args.capture:
        marker = parse_marker(args.capture)
        observed_states = parse_trace_states(args.capture)
        proto = marker["proto"]
        cursor = marker["cursor"]
        entry_byte = marker["byte"]
        buflen = marker["buflen"]
    else:
        if args.cursor is None:
            raise SystemExit("FAIL: --proto requires --cursor")
        proto = args.proto
        cursor = args.cursor
        entry_byte = args.entry_byte
        buflen = args.buflen

    if buflen is not None and buflen != len(block):
        raise SystemExit(
            f"FAIL: [L3VP8] buffer length {buflen} != verified block1 length {len(block)}; "
            "do not assume this runtime buffer is block1"
        )
    if not 0 <= cursor < len(block):
        raise SystemExit(f"FAIL: cursor {cursor} outside block1")
    if entry_byte is not None and entry_byte != block[cursor]:
        raise SystemExit(
            f"FAIL: marker byte {entry_byte} != block1[{cursor}]={block[cursor]}"
        )

    x0 = block[cursor]
    path = [8]
    s = 210 if x0 > 86 else 204
    path.append(s)
    if s != 204:
        result = {"verified_block1": True, "proto": proto, "cursor": cursor,
                  "entry_byte": x0, "prefix_states": path,
                  "status": "entry took vp->210; narrow prefix model stops"}
    else:
        s = 12 if x0 > 26 else 80
        path.append(s)
        if s != 80:
            result = {"verified_block1": True, "proto": proto, "cursor": cursor,
                      "entry_byte": x0, "prefix_states": path,
                      "status": "L9 state204 took ->12; narrow prefix model stops"}
        else:
            s = 58 if x0 <= 3 else 27
            path.append(s)
            if s != 58:
                result = {"verified_block1": True, "proto": proto, "cursor": cursor,
                          "entry_byte": x0, "prefix_states": path,
                          "status": "Jp state80 took ->27; narrow prefix model stops"}
            else:
                s = 159 if x0 <= 0 else 6
                path.append(s)
                if s != 6:
                    result = {"verified_block1": True, "proto": proto, "cursor": cursor,
                              "entry_byte": x0, "prefix_states": path,
                              "status": "qp state58 took ->159; narrow prefix model stops"}
                else:
                    s = 206 if x0 == 3 else 0
                    path.append(s)
                    if s != 0:
                        result = {"verified_block1": True, "proto": proto, "cursor": cursor,
                                  "entry_byte": x0, "prefix_states": path,
                                  "status": "wp state6 took ->206; narrow prefix model stops"}
                    else:
                        if cursor + 1 >= len(block):
                            raise SystemExit("FAIL: block1 truncated after entry byte")
                        x1 = block[cursor + 1]
                        s = 190 if x1 >= 128 else 135
                        path.append(s)
                        if s != 135:
                            result = {"verified_block1": True, "proto": proto,
                                      "cursor": cursor, "entry_byte": x0,
                                      "length_byte": x1, "prefix_states": path,
                                      "status": "Ap state0 entered multi-byte branch ->190; model stops"}
                        else:
                            # Fp state135 advances the source cursor once, then kp state22
                            # allocates a scratch buffer of exactly x1 bytes.
                            path += [22]
                            size = x1
                            nested_start = cursor + 2
                            plain = nested_decode(block, proto, nested_start, size)

                            # Hp139 / qp55 alternate exactly size times, then Hp139 ->109.
                            post = [139]
                            for _ in range(size):
                                post += [55, 139]
                            post.append(109)
                            path += post

                            first = plain[0] if plain else None
                            second = plain[1] if len(plain) > 1 else None
                            if first is not None:
                                after = 11 if first >= 128 else 92
                                path.append(after)
                                if after == 92:
                                    path += [49, 103]
                                    state103 = 24 if first >= 1 else 66
                                    path.append(state103)
                                    if state103 == 24 and second is not None:
                                        path.append(188 if second >= 128 else 223)

                            result = {
                                "verified_block1": True,
                                "proto": proto,
                                "cursor": cursor,
                                "entry_byte": x0,
                                "length_byte": x1,
                                "nested": {
                                    "source_offset": nested_start,
                                    "size": size,
                                    "lcg": {"seed0": (93 + proto) & 0xFF,
                                            "inc": 155, "mult": 93, "xor": 93},
                                    "sha256": hashlib.sha256(plain).hexdigest(),
                                    "entropy_bits_per_byte": entropy(plain),
                                    "head_hex": plain[:64].hex(),
                                    "first_byte": first,
                                    "second_byte": second,
                                },
                                "prefix_states": path,
                                "status": "nested prefix reconstructed from source + runtime identity marker",
                            }

    if observed_states is not None:
        predicted = result["prefix_states"]
        n = min(len(predicted), len(observed_states))
        if predicted[:n] != observed_states[:n]:
            for i in range(n):
                if predicted[i] != observed_states[i]:
                    raise SystemExit(
                        f"FAIL: level3 runtime diverges at trace index {i}: "
                        f"predicted {predicted[i]}, observed {observed_states[i]}"
                    )
            raise SystemExit("FAIL: level3 runtime/prediction prefix mismatch")
        result["runtime_trace"] = {
            "observed_state_count": len(observed_states),
            "compared_prefix_count": n,
            "predicted_prefix_fully_observed": len(observed_states) >= len(predicted),
            "prefix_match": True,
        }

    print(json.dumps(result, indent=2))
    if args.json:
        args.json.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(f"wrote {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
