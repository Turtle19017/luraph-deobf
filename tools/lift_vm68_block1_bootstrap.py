#!/usr/bin/env python3
"""Lift the deterministic block-1 VM68 bootstrap and first body decryption pass.

This tool starts from the verified block-1 A321 plaintext, reconstructs the four
main VM lanes, and follows the source-derived bootstrap through:

  mode 215 entry
  -> self-rewrite/jump trampolines
  -> mode 24 register-remap trampoline
  -> mode 54 setup
  -> opcode 84 bulk XOR decryption of body slots 85..4441
  -> the first instruction that requires runtime register provenance

After the first bulk decrypt, mode54 pc35 rewrites to opcode 72. In mode54,
opcode 72 is a direct jump-base instruction:

    pc_base = s[pc]

Thus pc35 sets the base to 11; the common increment selects pc12. pc12 then
rewrites to opcode80 and jumps indirectly through R37=84, entering the decrypted
body at pc85.

The tool currently models the deterministic bootstrap and first bulk-decrypt
checkpoint; later reachable-mode lifting is recorded separately.

No target execution is performed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from decode_a321_first_tables import decode_one, derive_count
from decode_a321_post_table_branch import secondary_integer_path
from decode_a321_third_tables import scalar_b_state_path

BLOCK1_SHA256 = "ecdc76fa288993cd2093564fe9a8b3f50f361dbe8f3282aa977c019e9954857e"
MASK = 0xFFFFFFFF


def u32(x: int) -> int:
    return x & MASK


def band(a: int, b: int) -> int:
    return (a & b) & MASK


def bor(a: int, b: int) -> int:
    return (a | b) & MASK


def bxor(a: int, b: int) -> int:
    return (a ^ b) & MASK


def bnot(a: int) -> int:
    return (~a) & MASK


def lshift(a: int, n: int) -> int:
    return (a << (n & 31)) & MASK


def rshift(a: int, n: int) -> int:
    return (a & MASK) >> (n & 31)


def mul32(a: int, b: int) -> int:
    # B:Kp is exactly the low 32 bits of unsigned multiplication.
    return (a * b) & MASK


def parse_values(data: bytes, pos: int, count: int) -> tuple[list[int], int]:
    out = []
    for _ in range(count):
        value, pos, _ = decode_one(data, pos)
        out.append(value)
    return out, pos


def parse_lanes(data: bytes) -> tuple[int, list[int], list[int], list[int], list[int]]:
    _, count = derive_count(data)
    if count != 4474:
        raise ValueError(f"block1 count {count} != 4474")

    pos = 16
    table1, pos = parse_values(data, pos, count)

    tag, tag_end, width = decode_one(data, pos)
    if (tag, width, data[pos:tag_end].hex()) != (215, 2, "8157"):
        raise ValueError("tag215 mismatch")
    pos = tag_end

    meta16 = data[pos]
    meta5 = data[pos + 1]
    if meta16 >= 128 or meta5 >= 128:
        raise ValueError("unexpected meta16/meta5 branch")
    pos += 2

    _, pos, _, path = secondary_integer_path(data, pos)
    if path[-1] != 237:
        raise ValueError(f"secondary path does not reach 237: {path}")

    table2, pos = parse_values(data, pos, count)

    scalar_a, pos, scalar_a_width = decode_one(data, pos)
    if scalar_a_width != 1:
        raise ValueError("unexpected scalar_a width")

    _, pos, _, scalar_b_path = scalar_b_state_path(data, pos)
    if scalar_b_path[-1] != 412:
        raise ValueError(f"scalar_b path does not reach 412: {scalar_b_path}")

    table3, pos = parse_values(data, pos, count)

    if pos + 4 > len(data):
        raise ValueError("truncated phase4 count")
    phase4_count = int.from_bytes(data[pos:pos + 4], "little")
    pos += 4
    for _ in range(phase4_count):
        if pos + 4 > len(data):
            raise ValueError("truncated phase4 tag")
        tag32 = int.from_bytes(data[pos:pos + 4], "little")
        pos += 4
        if tag32 & 1:
            if pos + 8 > len(data):
                raise ValueError("truncated phase4 range")
            pos += 8

    # phase5 metadata A/B/C
    _, pos, _ = decode_one(data, pos)
    _, pos, _ = decode_one(data, pos)
    _, pos, _ = decode_one(data, pos)

    table4, pos = parse_values(data, pos, count)

    # tail is not needed for VM lanes, but requiring it closes the boundary.
    _, pos, _ = decode_one(data, pos)
    _, pos, _ = decode_one(data, pos)
    if pos >= len(data):
        raise ValueError("missing fill byte")
    pos += 1
    if pos != len(data):
        raise ValueError(f"lane parse does not end at EOF: {pos} != {len(data)}")

    # 1-based lane arrays, matching runtime Lua tables.
    return (
        count,
        [None] + table1,
        [None] + table2,
        [None] + table3,
        [None] + table4,
    )


def rewrite215_op23(pc: int, S: int, w: int, H: int) -> tuple[int, int, int, int]:
    N, a, p = w, H, S
    g = 7 if N < 16384 else (14 if N < 2097152 else 21)
    n = band(N, lshift(1, g) - 1)
    i = rshift(N, g)

    S2 = u32(
        u32(p)
        + (46 + mul32(0xFFFFFFFE, band(u32(p), 46)))
        + (
            mul32(704803237, MASK)
            + mul32(3590164059, u32(pc))
            + mul32(3590164059, bnot(u32(pc)))
        )
    )
    w2 = u32(
        bxor(u32(n), 38)
        + mul32(474534088, MASK)
        + mul32(3820433208, 38)
        + mul32(3820433208, bnot(38))
    )
    H2 = u32(
        bxor(u32(a), 111)
        + mul32(211919387, MASK)
        + mul32(4083047909, u32(g))
        + mul32(4083047909, bnot(u32(g)))
    )
    op2 = u32(
        bxor(u32(i), 97)
        + mul32(0x80000000, u32(i))
        + mul32(0x80000000, u32(pc))
        + mul32(0x80000000, bxor(u32(i), u32(pc)))
    )
    return S2, w2, op2, H2


def rewrite24_op44(S: int, w: int, s: int, H: int) -> tuple[int, int, int, int]:
    del w  # opcode is known to be 44
    N, a, p = s, H, S
    g = 7 if a < 16384 else (14 if a < 2097152 else 21)
    n = band(a, lshift(1, g) - 1)
    i = rshift(a, g)

    H2 = u32(
        bxor(u32(n), 105)
        + mul32(555606651, MASK)
        + mul32(3739360645, u32(i))
        + mul32(3739360645, bnot(u32(i)))
    )
    s2 = u32(
        bxor(u32(N), 90)
        + mul32(1440942772, MASK)
        + mul32(2854024524, u32(N))
        + mul32(2854024524, bnot(u32(N)))
    )
    S2 = u32(
        mul32(3621682331, u32(p))
        + mul32(3621682331, 36)
        + mul32(1346569930, bor(u32(p), 36))
        + mul32(3621682332, bxor(u32(p), 36))
    )
    w2 = u32(
        bxor(u32(i), 20)
        + mul32(946075594, MASK)
        + mul32(3348891702, u32(i))
        + mul32(3348891702, bnot(u32(i)))
    )
    return S2, w2, s2, H2


def rewrite54_op20(S: int, w: int, s: int, H: int) -> tuple[int, int, int, int]:
    del H  # opcode is known to be 20
    N, a, p = w, S, s
    g = 7 if a < 16384 else (14 if a < 2097152 else 21)
    n = band(a, lshift(1, g) - 1)
    i = rshift(a, g)

    w2 = u32(
        bxor(u32(N), 36)
        + mul32(219665369, MASK)
        + mul32(4075301927, u32(g))
        + mul32(4075301927, bnot(u32(g)))
    )
    S2 = u32(
        mul32(2147483649, MASK)
        + mul32(2147483648, u32(n))
        + mul32(2147483648, 14)
        + mul32(2147483647, bnot(bxor(u32(n), 14)))
    )
    s2 = u32(
        bxor(u32(p), 60)
        + mul32(192030977, MASK)
        + mul32(4102936319, u32(N))
        + mul32(4102936319, bnot(u32(N)))
    )
    H2 = u32(
        bxor(u32(i), 68)
        + mul32(655034459, MASK)
        + mul32(3639932837, u32(n))
        + mul32(3639932837, bnot(u32(n)))
    )
    return S2, w2, s2, H2


def lane_tuple(S, w, s, H, pc: int) -> dict:
    return {"pc": pc, "S": S[pc], "w": w[pc], "s": s[pc], "H": H[pc]}


def hash_lane(values: list[int], start: int, end: int) -> str:
    blob = b"".join(int(values[i]).to_bytes(4, "little", signed=False)
                    for i in range(start, end + 1))
    return hashlib.sha256(blob).hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("block1", type=Path)
    ap.add_argument("--json", type=Path)
    args = ap.parse_args()

    data = args.block1.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != BLOCK1_SHA256:
        raise SystemExit(f"FAIL: block1 SHA mismatch: {digest}")

    try:
        count, S, w, s, H = parse_lanes(data)
    except (ValueError, IndexError) as e:
        raise SystemExit(f"FAIL: parse lanes: {e}") from e

    trace = []

    def event(stage: str, text: str, pc: int | None = None):
        row = {"stage": stage, "text": text}
        if pc is not None:
            row["pc"] = pc
            row["tuple"] = lane_tuple(S, w, s, H, pc)
        trace.append(row)

    # Finalized snapshot v2 proves these positive-index main lanes match runtime.
    if (S[4470], w[4470], s[4470], H[4470]) != (0, 37, 32, 19):
        raise SystemExit("FAIL: corrected pc4470 tuple mismatch")

    R37 = 19
    event("mode215", "pc4470 opcode32 sets R37=19", 4470)

    # pc11 lazily rewrites itself from opcode23 to opcode1.
    S[11], w[11], s[11], H[11] = rewrite215_op23(11, S[11], w[11], H[11])
    if (S[11], w[11], s[11], H[11]) != (0, 0, 1, 37):
        raise SystemExit(f"FAIL: pc11 rewrite mismatch: {lane_tuple(S,w,s,H,11)}")
    event("mode215", "pc11 rewrites 23 -> opcode1; indirect jump uses R37", 11)
    event("mode215", "R37=19 makes next executed slot pc20")

    # Decode pc20..26. Only the R37/jump effects are needed here.
    expected_20_26 = {
        20: (18, 21, 24, 0),
        21: (44, 44, 54, 45),
        22: (0, 88, 32, 102),
        23: (36, 28, 24, 0),
        24: (42, 1, 24, 0),
        25: (0, 37, 32, 4441),
        26: (0, 10, 15, 0),
    }
    for pc in range(20, 27):
        S[pc], w[pc], s[pc], H[pc] = rewrite215_op23(pc, S[pc], w[pc], H[pc])
        if (S[pc], w[pc], s[pc], H[pc]) != expected_20_26[pc]:
            raise SystemExit(f"FAIL: pc{pc} rewrite mismatch")
    R37 = 4441
    event("mode215", "pc25 sets R37=4441; pc26 returns through pc11")
    event("mode215", "rewritten pc11 jumps to pc4442")

    # Bootstrap copies at 4442..; pc4451 supplies next jump target.
    if (s[4451], w[4451], H[4451]) != (32, 37, 59):
        raise SystemExit("FAIL: pc4451 tuple mismatch")
    R37 = 59
    event("mode215", "pc4451 opcode32 sets R37=59; pc4452 -> pc11 -> pc60", 4451)

    # Decode the self-rewrite band at 64..67.
    expected_64_67 = {
        64: (32, 94, 24, 0),
        65: (62, 95, 24, 0),
        66: (0, 37, 32, 67),
        67: (0, 10, 15, 0),
    }
    for pc in range(64, 68):
        S[pc], w[pc], s[pc], H[pc] = rewrite215_op23(pc, S[pc], w[pc], H[pc])
        if (S[pc], w[pc], s[pc], H[pc]) != expected_64_67[pc]:
            raise SystemExit(f"FAIL: pc{pc} rewrite mismatch")
    R37 = 67
    event("mode215", "pc66 sets R37=67; pc67 -> pc11 -> pc68")

    # pc75 switches interpreter mode.
    S[75], w[75], s[75], H[75] = rewrite215_op23(75, S[75], w[75], H[75])
    if (S[75], w[75], s[75], H[75]) != (41, 24, 48, 0):
        raise SystemExit("FAIL: pc75 rewrite mismatch")
    event("mode215", "pc75 rewrites to opcode48 and switches mode 215 -> 24 at pc42", 75)

    # Mode24 trampoline: 42..48, 4..10, 13..19, 36..41.
    for lo, hi in ((42, 48), (4, 10), (13, 19), (36, 41)):
        for pc in range(lo, hi + 1):
            if w[pc] == 44:
                S[pc], w[pc], s[pc], H[pc] = rewrite24_op44(
                    S[pc], w[pc], s[pc], H[pc]
                )

    if (w[47], S[47], H[47]) != (16, 37, 3):
        raise SystemExit("FAIL: mode24 pc47 mismatch")
    event("mode24", "pc47 opcode16 sets R37=3; pc48 -> pc76; pc76 indirects to pc4")

    if (w[9], S[9], H[9]) != (16, 37, 12):
        raise SystemExit("FAIL: mode24 pc9 mismatch")
    event("mode24", "pc9 sets R37=12; pc10 -> pc76; pc76 indirects to pc13")

    if (w[18], S[18], H[18]) != (16, 37, 35):
        raise SystemExit("FAIL: mode24 pc18 mismatch")
    event("mode24", "pc18 sets R37=35; pc19 -> pc76; pc76 indirects to pc36")

    if (w[41], S[41], s[41], H[41]) != (0, 26, 54, 0):
        raise SystemExit(f"FAIL: mode24 pc41 mismatch: {lane_tuple(S,w,s,H,41)}")
    event("mode24", "pc41 opcode0 switches mode 24 -> 54 at pc27", 41)

    # Mode54 setup reaches the bulk decryptor at pc33.
    if H[33] != 84:
        raise SystemExit(f"FAIL: expected mode54 opcode84 at pc33, got {H[33]}")
    body_start = s[33] + 1
    body_length = w[33]
    body_end = body_start + body_length - 1
    if (body_start, body_length, body_end) != (85, 4357, 4441):
        raise SystemExit(
            f"FAIL: unexpected body decrypt range "
            f"{body_start} + {body_length} -> {body_end}"
        )

    before_hashes = {
        "S": hash_lane(S, body_start, body_end),
        "w": hash_lane(w, body_start, body_end),
        "s": hash_lane(s, body_start, body_end),
        "H": hash_lane(H, body_start, body_end),
    }

    seed = S[33]
    for i in range(1, body_length + 1):
        mask = band(bxor(seed, i), 127)
        pc = body_start + i - 1
        S[pc] = bxor(S[pc], mask)
        w[pc] = bxor(w[pc], mask)
        s[pc] = bxor(s[pc], mask)
        H[pc] = bxor(H[pc], mask)
    H[33] = 87

    after_hashes = {
        "S": hash_lane(S, body_start, body_end),
        "w": hash_lane(w, body_start, body_end),
        "s": hash_lane(s, body_start, body_end),
        "H": hash_lane(H, body_start, body_end),
    }
    event(
        "mode54",
        "pc33 opcode84 XOR-decrypts all four main lanes for slots 85..4441",
        33,
    )

    # The next two bootstrap slots self-rewrite.
    S[34], w[34], s[34], H[34] = rewrite54_op20(S[34], w[34], s[34], H[34])
    if (S[34], w[34], s[34], H[34]) != (0, 37, 84, 45):
        raise SystemExit("FAIL: mode54 pc34 rewrite mismatch")
    R37 = 84
    event("mode54", "pc34 opcode45 stores constant 84 into R37", 34)

    S[35], w[35], s[35], H[35] = rewrite54_op20(S[35], w[35], s[35], H[35])
    if (S[35], w[35], s[35], H[35]) != (0, 0, 11, 72):
        raise SystemExit("FAIL: mode54 pc35 rewrite mismatch")
    event(
        "mode54",
        "pc35 becomes opcode72: R0 = R72(R11); stop before guessing R72/R11",
        35,
    )

    preview = [lane_tuple(S, w, s, H, pc) for pc in range(85, 101)]

    result = {
        "schema": "luraph-deobf.vm68-block1-bootstrap-lift.v1",
        "block1_sha256": digest,
        "slot_count": count,
        "entry": {"dispatch_id": 68, "mode": 215, "pc": 4453, "stack_size": 130},
        "finalized_snapshot_fact": (
            "sampled positive-index bootstrap main lanes match serialized lanes "
            "19/19 after correcting validator pc4470 expected value"
        ),
        "trace": trace,
        "body_decrypt": {
            "opcode_pc": 33,
            "mode": 54,
            "seed_lane_S": seed,
            "start": body_start,
            "length": body_length,
            "end": body_end,
            "rule": "mask=((S[33] XOR i) & 0x7f); XOR mask into S/w/s/H slot start+i-1",
            "before_u32le_sha256": before_hashes,
            "after_u32le_sha256": after_hashes,
            "first16_decrypted_tuples": preview,
        },
        "continuation": {
            "mode": 54,
            "pc": 35,
            "rewritten_tuple": lane_tuple(S, w, s, H, 35),
            "semantic": "mode54 opcode72: pc base = s[35] = 11",
            "next": (
                "common increment -> pc12; pc12 rewrites to opcode80 and "
                "indirects through R37=84 -> next executed pc85"
            ),
        },
    }

    print(json.dumps(result, indent=2))
    if args.json:
        args.json.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
