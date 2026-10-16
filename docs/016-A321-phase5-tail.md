# 016 — Phase-5 metadata, fourth integer table, and fill tail

## Scope

This phase begins after the u32-counted phase-4 record stream. For block #1,
phase 4 is empty and ends at plaintext offset 15213.

Static source tracing now closes the remaining serialized bytes of block #1 all
the way to EOF.

## Three serialized metadata integers

State 388 starts a serialized integer. All 1/2/3/4-byte decoder paths converge
at state 485, which stores the decoded value into the object metadata table.

State 485 immediately begins a second serialized integer. Its width paths
converge at state 340, which stores the value into another metadata slot.

State 340 immediately begins a third serialized integer. Its width paths
converge at state 129. State 129 stores the value, allocates two
`table.create(count)` arrays, and creates a loop descriptor bounded by the
original object `count`.

Thus the phase begins:

```text
phase4_end
serialized_integer_A
serialized_integer_B
serialized_integer_C
```

For block #1:

```text
81 02 -> A = 130
44    -> B = 68
1d    -> C = 29
```

## Fourth count-sized integer table

The loop created at state 129 is:

```text
169(cy)     loop controller, exactly count iterations
43(m)       read first limb of one serialized integer
...         shared 1/2/3/4-byte integer decoder
475(jW)     store decoded value[index]
169(cy)     repeat
```

So the next field is another integer array of the same cardinality:

```text
fourth_int_table[count]
```

Block #1 checkpoint:

```text
count             4474
start             15217
end               20931
encoded bytes      5714
1-byte entries     3240
2-byte entries     1231
4-byte entries        3
minimum               0
maximum       404839701
zero entries          60
raw SHA-256
f14a8de2dd31217d2dac7536edc68a58808ba59a195c19dc3c1e0e1840e127e7
```

## Final fill tail

When the fourth-table loop exits, state 361 restores the surrounding parser
registers and state 393 begins another serialized integer. Its decoder
converges at state 357.

State 357 begins one more serialized integer. Its decoder converges at state
214.

State 214 then reads one raw byte and calls the method installed at `B[11]`.
The source binds:

```text
B[11] = buffer.fill
```

so the serialized tail is:

```text
fill_offset_delta   serialized integer
fill_length         serialized integer
fill_byte           raw u8
```

followed by:

```text
buffer.fill(
    target_buffer,
    base_offset + fill_offset_delta,
    fill_byte,
    fill_length
)
```

For block #1 the exact tail is:

```text
00       fill_offset_delta = 0
a3 bd 01 fill_length       = 20925
6d       fill_byte         = 109
```

The parser cursor then equals the object size exactly:

```text
phase5_end = 20936
object_size = 20936
remaining = 0
```

This is the first source/data proof that the recovered serialized layout
consumes an entire A321 plaintext object from byte 0 through EOF.

## Multi-object parser

`tools/decode_a321_phase5_tail.py` replays all previously established
boundaries, parses the phase-4 record stream, then decodes this complete
phase-5 structure for each of the eleven runtime-verified plaintext objects.

It does **not** require every child object to end at the same structural
boundary. It reports `bytes_remaining_after_phase5` and
`consumes_object_exactly` per object so the eleven-object corpus can establish
or reject that stronger invariant without forcing it.

Run:

```bash
python tools/decode_a321_phase5_tail.py \
  _probe/a321_plaintexts \
  --json _probe/a321_phase5_tail.json
```
