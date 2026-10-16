# Report 002 — Outer `J9` loader replay

## Overview

The outer loader is a VM/state machine split across 12 top-level dispatchers. Replaying the reachable path shows that almost all execution steps belong to the radix-85 decoding loop.

## Base85 decode loop

The core states are:

```text
_W(39)  advance input cursor by 5
ZW(0)   read current 5-character packed unit and query memo table
  ├─ cache hit  → FW(25)
  └─ cache miss → gW(36)
gW(36) split packed value into five ASCII digits
FW(28) recombine digits to uint32 and memoize
FW(25) write uint32 to output buffer
```

Observed state histogram for the completed run:

```text
y=0   ×95,923
y=25  ×95,923
y=39  ×95,924
y=28  ×95,836
y=36  ×95,836
```

The difference:

```text
95,923 - 95,836 = 87
```

is the number of memo/cache hits during the decode loop.

## Epilogue and handoff

After the output buffer is built, the loader enters a short epilogue and eventually calls:

```lua
Z = B:A(z, c)
B[Z[Z[1]]](B, nil, B.y, Z)
```

This is the important handoff from the outer loader into the next VM/deserialization layer.

Useful runtime roles established during replay:

- `B.V`: current buffer.
- `B[77]`: sequential program/read cursor used by the loader.
- `B.y`: prototype/environment table initialized empty.
- `B:A`: large state machine used to deserialize/build the next executable structure.

## Interpretation correction

The first bytes of `stage1.bin`, e.g.:

```text
ca 33 81 24 bf 83 03 ...
```

must not be treated as a conventional file header. The loader's Base85 state operates on the encoded text buffer before `stage1.bin` exists; the later `B:A` phase gives the meaningful parsing context for the decoded bytes.
