# 013 — Second count-sized integer table

## Source-derived structure

After the first integer table and the common `215` tag, the parser consumes:

```text
meta16
meta5
secondary serialized integer
```

All widths of that secondary integer converge at state `237`:

```text
width 1: 10 -> 328 -> 237
width 2: 10 -> 425 -> 88 -> 237
width 3: 10 -> 425 -> 473 -> 482 -> 237
width 4: 10 -> 425 -> 473 -> 101 -> 237
```

State `237(Ty)` allocates two tables using the still-live first-table count and
constructs a loop descriptor whose bound is exactly that count.

The loop is:

```text
237(Ty)
  -> 495(QW)      loop counter / bound check
  -> 162(g)       read first limb of one serialized integer
  -> ...          1/2/3/4-byte integer branches
  -> 469(YW)      store decoded value by loop index
  -> 495(QW)
```

When the loop has consumed `count` values, state `495` exits to state `404`.

Therefore the binary layout now known for the sample is:

```text
header
first_int_table[count]
tag215
meta16
meta5
secondary_integer
second_int_table[count]
...
```

## Block #1 checkpoint

For block #1:

```text
count              4474
first table end    4500
tag215             81 57
meta16/meta5       14 19
secondary integer  a2 65 -> 4453
second table start 4506
second table end   10201
encoded bytes      5695
width histogram    1-byte:3261, 2-byte:1209, 4-byte:4
```

This checkpoint is derived from the verified block-1 plaintext and source path.

## Multi-object parser

`tools/decode_a321_second_tables.py` applies the same source-derived phase to
all eleven runtime-verified plaintext objects.

It verifies each input by size/SHA/head16, recomputes the first table, requires
the `215 / 81 57` tag and the observed low `meta16/meta5` path, decodes the
secondary integer, then parses exactly `count` integers into the second table.

Run:

```bash
python tools/decode_a321_second_tables.py \
  _probe/a321_plaintexts \
  --json _probe/a321_second_tables.json
```

No target execution is required. A failure means an object diverges from the
currently source-derived common grammar; do not adjust count or offsets to make
it pass.
