# Report 003 — Reachable `B:A` replay and inner LCG-XOR layer

## Strategy

Instead of translating every branch of `B:A` up front, the analysis follows only the state sequence reachable from the real starting state and records each register shuttle literally.

This reduced the amount of code that needed to be modeled while preserving auditable 1:1 semantics for the executed path.

## Reached entry

The replay reaches prototype/entry index:

```text
entry = 164
```

with a source pointer around:

```text
z[4][164] = 35911
```

The encrypted substream begins four bytes later at offset 35915.

## Inner decode

A 20,936-byte substream is decoded by an LCG-XOR loop. After correcting an early register-shuttle mistake, the verified recurrence is:

```text
seed0 = (164 + 240) mod 256 = 148
key[n+1] = (155 + 93*key[n]) mod 256
plain[n] = cipher[n] XOR key[n+1] XOR 240
```

Decoded size:

```text
20,936 bytes
```

SHA-256:

```text
ecdc76fa288993cd2093564fe9a8b3f50f361dbe8f3282aa977c019e9954857e
```

The first 64 decoded bytes are:

```text
01 1a 16 00 18 17 1b 1e d1 e6 02 1c 11 13 12 20
41 e9 0e 8c 0e 0e 42 43 32 4c 01 6f 2e 94 0e 0f
1f 18 1c 1a 01 6f 3c 02 2e 0a 04 2e 2e 00 00 00
00 00 2c e9 0e 8c 0e 09 0a 0d 0b 11 3e 07 00
```

Its byte entropy drops substantially relative to `stage1.bin`, which is a strong signal that this is a structurally meaningful decoded layer rather than another blind transform.

## Reachable path checkpoint

The replayed state path includes:

```text
245 → 405 → 439 → 300 → 99
    → 323 ↔ 228 × 20,936
    → 321 → 145 → 212 → 437 → 283
    → 277 → 44 → 355 → 114 → 176
    → 336 → 288 → 149 → 157 → 434
    → 348 → 317 → 121 → 9 → 438 → 365
```

## Current divergence

Near `438 → 365`, three bytes in the decoded layer are interpreted as:

```text
f[8]  = 209
f[9]  = 230
f[10] = 2
```

and the modeled handler computes:

```text
(209-128)*128 + (230-128) + 2*16384 = 43238
```

The next state then appears to prepare a byte read at offset `43238` from a buffer whose modeled length is only `20936`.

That invariant is intentionally not patched or guessed around. A runtime probe is used to determine whether the static register shuttle is still wrong or whether an environment/anti-analysis path is involved.
