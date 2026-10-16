# 012 — Shared post-table tag and second serialized integer

## Corpus-wide invariants

The first-table parser succeeds on all eleven verified A321 plaintext objects:

```text
object count        11
total object bytes  37,590
total table entries 7,950
```

The integer immediately following every first table is identical:

```text
value    215
width    2
encoding 81 57
```

This is a corpus-wide serialized-format invariant for the known sample.

## Exact source path after the first table

The common path begins:

```text
82(M)
→ 272(zy)
→ 275(Yy)        decode 81 57 -> 215
→ 147(p)
→ 167(_) or 267(...)
→ 46(G) or alternate path
→ 229(Sy) or 490(...)
→ 10(o)
```

For all eleven observed objects, the bytes read by state 147 and state 46 are
below 128, so every object takes:

```text
147 -> 167
46  -> 229
```

## Correction: state 10 starts another serialized integer

An earlier version of this report inverted the branch at state 10. The source
is:

```lua
not(128 > first_byte) and 425 or 328
```

Therefore the correct rule is:

```text
first byte < 128   -> 328
first byte >= 128  -> 425
```

State 10 is not reading a Boolean selector. It is reading the **first byte of
another serialized integer** using the same 1/2/3/4-byte grammar already
verified for the first table.

The exact state paths are:

```text
width 1:
10 -> 328 -> 237

width 2:
10 -> 425 -> 88 -> 237

width 3:
10 -> 425 -> 473 -> 482 -> 237

width 4:
10 -> 425 -> 473 -> 101 -> 237
```

For block #1, the bytes after the common tag begin:

```text
81 57 14 19 a2 65 ...
```

The first two bytes are the invariant 215. Then:

```text
14   meta16  -> 147 -> 167
19   meta5   -> 46  -> 229
a2 65        -> second integer
```

and:

```text
(0xa2 - 128) * 128 + 0x65 = 4453
```

so block #1 follows:

```text
82 -> 272 -> 275 -> 147 -> 167 -> 46 -> 229
   -> 10 -> 425 -> 88 -> 237
```

## Offline parser

`tools/decode_a321_post_table_branch.py` now verifies every plaintext against
the runtime SHA/size/head receipt, recomputes its first-table end, requires the
`215 / 81 57` invariant, and then decodes the second serialized integer
instead of treating its first byte as an independent selector.

Run:

```bash
python tools/decode_a321_post_table_branch.py \
  _probe/a321_plaintexts \
  --json _probe/a321_post_table_fields.json
```

The important outputs are:

```text
secondary_integer.value
secondary_integer.width
secondary_integer.encoding_hex
secondary_integer.state_path
cursor_at_state237
secondary_integer_width_groups
path_groups
reaches_state237_blocks
```

The parser does not assume all eleven second integers have the same width or
value. It derives the exact path from the serialized bytes.
