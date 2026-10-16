# 014 — Third count-sized integer table

## Confirmed transition after the second table

The second-table parser succeeds on all eleven runtime-verified A321 plaintext
objects. Each second table contains exactly the same `count` as the first table.

After that table, source mapping gives the common path:

```text
495(QW) loop exit
→ 404(vW)
→ 50(U)
```

State 50 begins another serialized scalar. In the current eleven-object corpus,
the first byte is always below 128, so every object takes:

```text
50 -> 325 -> 503 -> 4 -> 412
```

The observed values are:

```text
block 1   21
block 2   31
block 3   32
block 4   19
block 5   32
block 6   25
block 7   32
block 8   30
block 9   19
block 10  27
block 11  23
```

These values are stored into the current object. They are **not** used as the
next loop bound.

## State 412 creates the next count-sized phase

At state `412(nW)`, the source allocates:

```text
table.create(count)
table.create(count)
```

using the still-live original object count.

It also constructs a loop descriptor with:

```text
step  = 1
bound = count
```

and enters state 36.

The loop is:

```text
36(T)      loop controller
401(vW)    read first serialized-integer limb
250/52/... decode 1/2/3/4-byte integer
343(Py)    store decoded value[index]
36(T)      repeat
```

All integer-width paths converge at state 343 before returning to state 36.

Therefore the known layout extends to:

```text
header
first_int_table[count]
tag215
meta16
meta5
secondary_integer
second_int_table[count]
post_second_scalar
third_int_table[count]
...
```

## Block #1 checkpoint

Verified block #1 gives:

```text
count                    4474
second table end         10201
post-second scalar       21 / 0x15
third table start        10202
third table end          15208
third table encoded size 5006
width histogram          1-byte:3944, 2-byte:529, 4-byte:1
```

The next four bytes are:

```text
0f 00 00 00
```

State 55 reads those bytes with `buffer.readu32`, producing value `15`.

## Phase-4 boundary

When the third-table loop finishes:

```text
36 -> 51 -> 55
```

State 55 reads one little-endian u32 from the current cursor, advances four
bytes, allocates a new table, and constructs another loop descriptor.

`tools/decode_a321_third_tables.py` therefore reports this u32 as
`phase4_count_u32` but deliberately stops before parsing its records.

## Reproduce

```bash
python tools/decode_a321_third_tables.py \
  _probe/a321_plaintexts \
  --json _probe/a321_third_tables.json
```

The tool verifies every plaintext by the runtime size/SHA/head receipt, replays
the already-proven first and second-table boundaries, requires the observed
one-byte post-second scalar path, parses exactly `count` integers into the
third table, then reads the phase-4 u32.

No Luau/target execution is required.
