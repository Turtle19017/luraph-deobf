# 010 — A99 source-buffer provenance

## Result

The eleven observed A99 decodes do not all read from one outer J9 `z[7]`
buffer.

The key source-level fact is at `B:A` entry state 245 (`Gy`).

For an invocation:

```text
B:A(P, seed)
```

the handler reads:

```text
P[4][seed]   -> serialized record position
P[7]         -> cipher/source buffer
```

The returned `P[7]` value is carried through the A-layer register set and is the
buffer read by `Sy(228)`:

```text
buffer.readu8(source_buffer, srcoff + byte_index)
```

Therefore `srcoff` is relative to the **current invocation's `P[7]`**, not
necessarily to the outer J9 `z[7]`.

## Outer invocation

The outer J9 handoff calls:

```text
B:A(z, c)
```

and its `z[7]` is the verified byte copy:

```text
stage1[1274 : 1274+79999]
size    79999
SHA-256 158c17bfdd79cb23c036639223a730d9c8d2c4940cb07cbfb31aa97551b64891
```

Runtime level-3 entry later observed:

```text
buflen = 79999
cursor = 63037
byte   = 45
```

and the verified outer `z[7]` has:

```text
z7[63037] = 45
```

This establishes byte-content consistency with the previously verified outer
J9 buffer. It does not by itself assert object/pointer identity.

## Recursive B:A call-sites

There are only three static call-sites:

```text
outer
  rW  -> B:A(z, c)

recursive level-3 handler Sp, state 33
  X = B:A(c, P)

recursive level-3 handler Hp, state 140
  ... B:A(k, I) ...
```

The recursive calls pass new objects as the first argument. Each new object has
its own `[4]` record-index table and `[7]` source buffer.

This explains why a runtime `srcoff` from a child invocation cannot be mapped
back to outer stage1 using the block-1 `+1274` base without further evidence.

## Single-z7 hypothesis test

Runtime observed `[A321] first=1` after all eleven A99 decodes.

Applying all eleven runtime `srcoff` values to the verified outer `z[7]` and
the verified LCG transform gives:

```text
block 1  ->   1   MATCH
block 2  ->  79
block 3  -> 188
block 4  -> 230
block 5  -> 242
block 6  ->  40
block 7  ->  70
block 8  -> 179
block 9  -> 129
block 10 -> 201
block 11 -> 124
```

So only block #1 is consistent with the outer J9 `z[7]` at the observed
runtime offset.

The machine-readable result is:

```text
receipts/luraph_A99_outer_z7_audit.json
```

## Consequence

The remaining task is not to search for another universal stage1 base.

It is to recover, for each recursive `B:A(P, seed)` invocation:

```text
seed -> P object -> P[7] buffer provenance
```

There are two valid routes:

1. continue the parent deserializer offline until the child objects and their
   `[7]` buffers are reconstructed, or
2. obtain one lightweight runtime provenance marker per `B:A` invocation and
   then return offline.

Until one of those routes establishes the child `P[7]` buffers, blocks 2..11
remain runtime-observed decodes with unresolved source-buffer provenance.
