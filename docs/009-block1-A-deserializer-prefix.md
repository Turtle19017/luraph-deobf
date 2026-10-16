# 009 — Verified `B:A` block-1 deserializer prefix

## Scope

This report follows the already-verified block-1 plaintext (SHA-256
`ecdc76fa288993cd2093564fe9a8b3f50f361dbe8f3282aa977c019e9954857e`) through the
actual `B:A` source dispatch. It is source/data-derived and does not require a target run.

It supersedes the earlier interpretation that the numeric value `43238` existed only on a
false `438 → 365` path.

## Corrected path around `43238`

The real block-1 path reaches the same numeric value through different states:

```text
... 268(iy) → 353(Hy) → 416(kW) → 317(ay) → 84(J) → 365(_y) ...
```

At state `416`, handler `kW` combines bytes `d1 e6 02` and computes:

```text
128*(0xd1-128) + (0xe6-128) + 16384*0x02 = 43238
```

That number is real, but it is **not** passed to `buffer.readu8` as an offset.
State `317` (`ay`) immediately computes:

```text
43238 - 38764 = 4474
```

while the actual byte read remains at block cursor `11`. State `365` then reads the next
byte at cursor `12`.

Therefore the old contradiction was caused by attaching the numeric value to the wrong
register/role, not by the number itself being absent from the real path.

## Prefix to the first large integer table

Using the block-1 bytes, the deterministic prefix is:

```text
321(Zy) → 145(p) → 212(ny) → 437(mW) → 283(My)
→ 277(jy) → 44(G) → 355(Hy) → 114(W) → 176(dy)
→ 336(ry) → 288(Jy) → 378(KW) → 197(wy) → 344(Py)
→ 225(by) → 87(J) → 85(J) → 113(W) → 306(By)
→ 268(iy) → 353(Hy) → 416(kW) → 317(ay) → 84(J)
→ 365(_y) → 59(q) → 81(M) → 74(Y) → 279(jy)
→ 422(bW) → 257(qy) → 15(n) → 251(Uy)
```

The first 16 plaintext bytes are consumed as deserializer header/control data. State `251`
creates a table of size `4474` plus a loop descriptor. State `375` (`dW`) is the loop
counter; state `154` (`H`) reads the first integer byte; state `269` (`zy`) stores each
decoded integer into the table.

## Exact integer decoder

The source has four serialized integer branches:

```text
1 byte: b0
2 byte: (b0-128)*128 + b1
3 byte: (b0-128)*128 + (b1-128) + 16384*b2
4 byte: build-specific permutation implemented by state 24 (`b`)
```

For this particular 4474-entry table, only the first two branches are exercised.

`tools/decode_block1_table4474.py` reproduces the table fail-closed from the verified block.
The exact receipt is:

```text
start offset        16
end offset          4500
encoded bytes       4484
entry count         4474
1-byte entries      4464
2-byte entries      10
3/4-byte entries    0
minimum             0
maximum             13477
zero entries        46
values < 128        4464
raw-span SHA-256    710e664df1c6a340316b6fe86696351f55a1fa6bfeb686b6e7770bc79ffe3f44
u32le-values SHA256 4c79f884d866a14860621efb1b41869b3bace4e45906dedaeb7e9840cab05699
```

The first values are:

```text
65, 13454, 1550, 14, 66, 67, 50, 76, 1, 111, 46, 2574, 15,
31, 24, 28, 26, 1, 111, 60, 2, 46, 10, 4, 46, 46, 0, 0, 0, 0, 0, 0
```

This is strong structural evidence: 4464/4474 values are below 128 and the loop lands
exactly at byte offset 4500.

## What happens after the table

The source/data path continues deterministically at least through:

```text
155(H) → 82(M) → 272(zy) → 275(Yy) → 147(p)
→ 167(_) → 46(G) → 229(Sy) → 10(o) → 328(Ey) → 237(Ty)
```

At offsets `4500..` the bytes begin:

```text
81 57 14 19 a2 65 ...
```

The path decodes `81 57` to integer `215`, then reads the two low metadata
bytes `14 19`. State `10(o)` then starts another serialized integer at
`a2 65`.

A previous interpretation incorrectly sent `a2` directly to state 328. The
source condition is:

```lua
not(128 > first_byte) and 425 or 328
```

so `a2 >= 128` goes to state `425`, which reads the second limb `65`.
Because `65 < 128`, state `88` decodes:

```text
(0xa2 - 128) * 128 + 0x65 = 4453
```

and then reaches state `237`.

State `237` allocates another table of size `4474`. The
`237 -> 495 -> 162 -> ... -> 469 -> 495` loop then decodes exactly 4474 more
serialized integers. For block #1 this second table starts at offset `4506`
and ends at offset `10201`.

## Reproduce

```bash
python tools/decode_block1_table4474.py \
  luraph_A_entry164_layer1.bin \
  --receipt luraph_A_block1_table4474.receipt.json
```

No Roblox/Luau runtime is required for this checkpoint.
