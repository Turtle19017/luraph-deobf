# Report 003 — First A-layer LCG-XOR block checkpoint

> **Superseded interpretation:** this report originally treated the first
> 20,936-byte decode as a complete inner layer and continued along a static
> successor chain that included `121 → 9 → 438 → 365`. Runtime tracing and
> direct source mapping later showed that interpretation was wrong. The verified
> content retained here is the byte-for-byte reconstruction of block #1 only.
> See `docs/005-multiblock-lcg.md` for the corrected 11-block model.

## Verified block #1

The first observed A-layer LCG-XOR block uses:

```text
seed_in = 164
seed0   = (164 + 240) % 256 = 148
size    = 20,936
src     = 35,915
```

The transform is:

```text
key[n+1] = (155 + key[n] * 93) % 256
plain[n] = cipher[n] XOR key[n+1] XOR 240
```

The reconstructed plaintext has SHA-256:

```text
ecdc76fa288993cd2093564fe9a8b3f50f361dbe8f3282aa977c019e9954857e
```

First 64 bytes:

```text
01 1a 16 00 18 17 1b 1e d1 e6 02 1c 11 13 12 20
41 e9 0e 8c 0e 0e 42 43 32 4c 01 6f 2e 94 0e 0f
1f 18 1c 1a 01 6f 3c 02 2e 0a 04 2e 2e 00 00 00
00 00 2c e9 0e 8c 0e 09 0a 0d 0b 11 3e 07 00
```

Runtime tracing later established that this is **block 1 of 11**, with
37,590 decoded bytes total across all A99 invocations.

## Post-block observation

After this block, runtime instrumentation reports:

```text
[A321] first=1 next=145
```

The same `A321 → 145` observation occurs after every one of the eleven blocks.

## Correction to the old successor model

The old model continued:

```text
... → 121 → 9 → 438 → 365
```

That chain is invalid for this build.

Direct source mapping shows:

```text
B:Z at state 121 → 42
B:T at state 42  → 48
```

Therefore the previously reported computed offset `43238` and the resulting
`43238 > 20936` contradiction are not runtime facts. They were produced by
following an unreachable static successor chain.

The historical receipt
`receipts/luraph_A_entry164_layer1.receipt.json` is retained for audit history
but its successor-path fields are superseded. The corrected block-only tool is
`tools/luraph15_A_layer1.py`.
