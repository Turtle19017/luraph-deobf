# 015 — Phase-4 u32-counted record stream

## Correct entry boundary

Phase 4 begins only after the corrected third-table boundary:

```text
second_int_table[count]
scalar A
scalar B
third_int_table[count]
u32 phase4_record_count
phase4 records...
```

The previous one-scalar model shifted this boundary by one byte. It is
superseded by `docs/014-A321-third-int-table.md`.

## Source structure

State `55(t)` creates a new result table, reads a little-endian u32 record
count, and constructs an outer loop descriptor.

```text
55(t)
  record_count = buffer.readu32(...)
  -> 407(sW)
```

State `407(sW)` runs exactly `record_count` outer iterations and enters state
`72(Y)` for each record.

State `72(Y)` reads a u32 tag and branches on its low bit.

### Even tag

For an even tag:

```text
value = tag / 2
72 -> 477 -> 95 -> 407
```

State `477(MW)` stores the integer part of `tag/2` into the phase-4 result
table at the current sequential record slot.

### Odd tag

For an odd tag:

```text
range_start = floor(tag / 2)
range_end   = next u32
value       = next u32
```

The source path is:

```text
72
-> 411        read range_end and value
-> 221        inner interval-loop controller
-> 297        store value at the current logical interval index
-> 221        repeat
-> 456
-> 95
-> 407
```

The inner loop is source-defined by the interval bounds. Offline tooling must
not materialize the interval merely to validate the serialized structure.

## Fail-closed offline parser

`tools/decode_a321_phase4_records.py`:

- verifies each plaintext against the runtime size/SHA/head receipt,
- recomputes the corrected two-scalar + third-table boundary,
- reads the phase-4 u32 record count,
- rejects a count that cannot fit in the remaining bytes even at the minimum
  four bytes per record,
- parses even and odd records exactly,
- records odd logical spans without expanding them,
- and previews the next serialized integer without assigning phase-5 meaning.

Run:

```bash
python tools/decode_a321_phase4_records.py \
  _probe/a321_plaintexts \
  --json _probe/a321_phase4_records.json
```

## Block #1 checkpoint

With the corrected third-table end:

```text
third table end       15209
phase4 count bytes    00 00 00 00
phase4 record count   0
phase4 start/end      15213
next bytes            81 02 ...
next integer preview  130 (width 2)
```

So block #1 has an empty phase-4 record stream. The previous apparent
`record_count=15` came from the superseded one-byte-shifted boundary.

The semantic purpose of the phase-4 result table is not promoted yet; only the
source-level record grammar and assignments are claimed.
