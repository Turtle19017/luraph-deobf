# 017 — Canonical A321 object IR and indirect slot map

## Why an IR is now useful

The A321 plaintext format is no longer best described as a sequence of opaque
dispatcher states. Source tracing shows a stable serialized object layout whose
logical fields are written through an indirection table stored in the object
itself.

The important distinction is:

```text
serialized order            runtime placement
-------------------------   --------------------------
logical table / metadata -> q[q[n]] or q[n]
```

The `q[n]` values act as field-key descriptors. This is one reason the raw
object layout looks randomized even when the serializer grammar is stable.

## Source-derived canonical slot map

The current canonical names are intentionally semantic-neutral. They describe
serializer order, not original program names.

```text
table1
  value table -> q[q[12]]
  companion   -> q[q[15]]

table2
  value table -> q[q[13]]
  companion   -> q[q[11]]

phase4 range/RLE table
  result      -> q[q[5]]

table3
  value table -> q[q[10]]
  companion   -> q[q[16]]

metadata A
  value       -> q[q[9]]

metadata B
  value       -> q[q[1]]

metadata C
  value       -> q[8]

table4
  value table -> q[q[8]] after q[8] = metadata C
  companion   -> q[q[14]]
```

The critical subtlety is the last pair: phase-5 metadata C first overwrites
`q[8]` with a decoded integer, and that value immediately becomes the indirect
key used for table4.

## Source checkpoints

The assignments are visible at the allocation/store convergence states.

### First table — state 251

The handler allocates two `table.create(count)` arrays and stores them at:

```text
q[q[12]]
q[q[15]]
```

The decoded integer loop stores into the first of those arrays.

### Second table — state 237

The handler allocates two arrays and stores them at:

```text
q[q[13]]
q[q[11]]
```

The state495/.../469 loop fills the first array.

### Phase-4 range table — state 55

State55 creates a result table and stores it at:

```text
q[q[5]]
```

The u32 tagged record stream then writes literal or interval-expanded values
into that result.

### Third table — state 412

After scalar A and scalar B, state412 stores the latter metadata value and
allocates:

```text
q[q[10]]
q[q[16]]
```

The state36/.../343 loop fills the first array.

### Phase-5 metadata A/B/C and fourth table

State388 starts metadata A. State485 stores it through the key already held in
`q[9]`:

```text
q[q[9]] = metadata_A
```

State485 then seeds metadata B. The low-width path carries `q[1]` forward as
the destination key and state340 stores:

```text
q[q[1]] = metadata_B
```

State340 immediately begins metadata C and explicitly carries constant `8` as
its destination index. At state129:

```text
q[8] = metadata_C
```

State129 then allocates the fourth table pair:

```text
q[q[8]]
q[q[14]]
```

and state169/.../475 fills the first array.

## Final byte-consuming operation

After table4, the parser decodes:

```text
fill_offset_delta
fill_length
fill_byte
```

State214 invokes:

```text
buffer.fill(
    target_buffer,
    base_offset + fill_offset_delta,
    fill_byte,
    fill_length
)
```

For verified block #1 this operation consumes the final byte of the plaintext
object exactly.

## Post-fill runtime finalization

After `buffer.fill`, state214 no longer performs serialized-field decoding. It
branches on an object flag:

```text
flag [6] false -> 451
flag [6] true  -> 35
```

State451 either reuses an already installed object slot `[5]` and continues at
state48, or goes through state39.

The `J > 38` branch of state39 constructs the third-level `c[B.ep]`
interpreter closure, stores it in:

```text
P[2][5]
```

and returns to state48.

The state35 finalization path reaches state513; state513's `B:WW` handler
returns control code 2, causing `B:A` to return the assembled object `q`.

The exact runtime branch sequence after fill may vary by object state. The
binary-layout claim is deliberately separated from this in-memory finalization.

## Consolidated parser

`tools/decode_a321_full_layout.py` replaces the need to run every phase parser
separately.

It performs one fail-closed pass over each runtime-verified plaintext and emits:

```text
count
table1
tag215 / meta16 / meta5 / secondary_integer
table2
scalar_a / scalar_b
table3
phase4 range/RLE records
metadata_a / metadata_b / metadata_c
table4
fill tail
end_offset / remaining bytes
canonical slot map
```

Run:

```bash
python tools/decode_a321_full_layout.py \
  _probe/a321_plaintexts \
  --json _probe/a321_full_layout.json
```

If all eleven objects report:

```text
consumes_object_exactly = true
bytes_remaining = 0
```

then the complete byte framing of the known eleven-object A321 corpus is
recovered. The next problem is semantic lifting of the four parallel tables,
not finding another serialized phase.
