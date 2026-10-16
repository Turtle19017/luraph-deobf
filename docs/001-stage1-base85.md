# Report 001 — Stage-1 payload and custom Base85

## Target summary

The analyzed target is a Roblox/Luau script protected by Luraph Obfuscator v15.0. Its dominant embedded payload is the long string `Y9`.

The verified outer pipeline is:

```text
Y9
  → strip 4-byte magic `LPH%`
  → gsub(j9, M9)
  → custom 5-character / 4-byte radix-85 decoder
  → stage1.bin
```

## Anti-transform

The loader performs the equivalent of:

```lua
local a = string.gsub(string.sub(Y9, 5), j9, M9)
local J = buffer.fromstring(a)
```

For this sample:

```text
j9 = [ -"x-~]
```

After applying `M9`, the alphabet is exactly the contiguous 85-character range ASCII 35..119.

Observed values:

| Property | Value |
|---|---:|
| `Y9` length | 479,491 |
| Length after magic removal | 479,487 |
| Replacement count | 32 |
| Length after `gsub` | 479,615 |
| 5-character groups | 95,923 |
| Decoded bytes | 383,692 |

## Nonstandard radix-85 permutation

Let the five input characters be `c0..c4` and:

```text
d_i = ord(c_i) - 35
```

The exponent order for `d0..d4` is:

```text
EXP = (1, 2, 4, 0, 3)
```

Therefore:

```text
V = d0*85^1 + d1*85^2 + d2*85^4 + d3*85^0 + d4*85^3
```

Equivalent expanded form:

```text
V = 85*d0 + 7225*d1 + 52200625*d2 + d3 + 614125*d4
```

`V` is emitted as `uint32` little-endian.

This explains why Adobe Ascii85 and ordinary Base85 decoders do not reconstruct the target bytes.

## Independent confirmation

The permutation was cross-checked from three independent directions:

1. End-to-end SHA-256 of the reconstructed binary.
2. The inverse handler (`gW`, state/opcode 36), which decomposes the packed value into five digits.
3. The forward handler (`FW`, state/opcode 28), which recombines the five digits using the weights above.

## Receipt

Expected SHA-256 of `stage1.bin`:

```text
108da67ce0920931a4896896927fa127816bb9980d9fec2518bcad8ed472b2ec
```

The machine-readable extraction metadata is stored in:

```text
receipts/luraph_stage1.receipt.json
```
