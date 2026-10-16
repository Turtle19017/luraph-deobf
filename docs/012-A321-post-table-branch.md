# 012 — Shared post-table tag and branch classifier

## New multi-object invariant

The first-table parser succeeds on all eleven verified A321 plaintext objects.

Across the corpus:

```text
object count        11
total object bytes  37,590
total table entries 7,950
```

The table sizes vary widely, but the integer immediately following every first
table is identical:

```text
value    215
width    2
encoding 81 57
```

This is now treated as a corpus-wide serialized-format invariant for the known
sample.

## Exact source path after the first table

The block-1 source path after the table is:

```text
155(H)
→ 82(M)
→ 272(zy)
→ 275(Yy)
→ 147(p)
→ 167(_) or 267(...)
→ 46(G) or alternate path
→ 229(Sy) or 490(...)
→ 10(o)
→ 328(Ey) or 425(...)
→ 237(Ty) on the block-1-compatible branch
```

The first three transitions decode the common post-table integer.

At state 82, the first byte is read. With `0x81 >= 128`, execution goes to
state 272. State 272 reads the second byte. With `0x57 < 128`, state 275
decodes:

```text
(0x81 - 128) * 128 + 0x57 = 215
```

and advances the plaintext cursor by two bytes.

## The next three raw bytes

After `81 57`, the source consumes three raw bytes that control subsequent
branches.

For an object whose first table ends at `E`:

```text
E+0..E+1  81 57    serialized integer 215

E+2       read by state 147
          <128  -> 167
          >=128 -> 267

E+3       read by state 46 if state 167 was taken
          <128  -> 229
          >=128 -> 490

E+4       read by state 10 if state 229 was taken
          <128  -> 425
          >=128 -> 328 -> 237
```

For verified block #1 this five-byte sequence is:

```text
81 57 14 19 a2
```

which follows:

```text
82 -> 272 -> 275 -> 147 -> 167 -> 46 -> 229 -> 10 -> 328 -> 237
```

State 237 then allocates the next pair of tables using the still-live first-table
count.

## Offline classifier

`tools/decode_a321_post_table_branch.py` verifies every plaintext against the
runtime SHA/size/head receipt, recomputes its first-table end, requires the
`215 / 81 57` invariant, and then reports the three branch bytes without
forcing them to match block #1.

Run:

```bash
python tools/decode_a321_post_table_branch.py \
  _probe/a321_plaintexts \
  --json _probe/a321_post_table_branch.json
```

The useful result is the grouping of objects by:

```text
state147_next
state46_next
state10_next
```

If all eleven reach state 237, the serialized grammar remains common through
the next allocation phase. If they split, that split is the next format
boundary to model.
