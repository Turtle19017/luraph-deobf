# 011 — Multi-object A321 plaintext parsing

## Runtime corpus

The complete runtime-decrypted A321 plaintext corpus is now fixed by receipt:

```text
receipts/luraph_A321_plaintexts.runtime.json
```

It contains 11 objects totaling 37,590 bytes. Every object begins with byte
`0x01`; block #1 reproduces its independently verified SHA-256 exactly.

The 11 object sizes and SHA-256 digests are treated as immutable parser inputs,
not heuristics.

## Shared header grammar

All eleven 16-byte prefixes enter the same source-verified B:A prefix path.

Bytes 8..10 take the three-byte integer branch:

```text
raw =
    128*(b8-128)
  + (b9-128)
  + 16384*b10

count = raw - 38764
```

This yields:

```text
block 1   4474
block 2     34
block 3     99
block 4   1516
block 5    532
block 6     43
block 7    138
block 8    127
block 9    157
block 10    50
block 11   780
```

For block #1, the source/data path already proves that the first serialized
integer table begins at byte offset 16. The child prefixes follow the same
branch structure through that point.

## Generalized parser

`tools/decode_a321_first_tables.py` verifies every plaintext against the runtime
receipt and then parses exactly the derived count from offset 16 using the
source-derived serialized integer decoder.

It does **not** assume:

- a common table end offset,
- a common width histogram,
- a common source buffer,
- a stage1 base,
- or a particular amount of data remaining after the table.

For every object it reports:

```text
table_count
table_start / table_end
encoded byte size
1/2/3/4-byte width histogram
min / max / zero count
raw table SHA-256
decoded-value SHA-256
the next serialized integer, if one can be read
```

## Reproduce

With the runtime plaintext directory:

```bash
python tools/decode_a321_first_tables.py \
  _probe/a321_plaintexts \
  --json _probe/a321_first_tables.json
```

A failure means one of the child objects diverges from the currently inferred
common prefix grammar. Do not adjust the offset/count to force a parse.
