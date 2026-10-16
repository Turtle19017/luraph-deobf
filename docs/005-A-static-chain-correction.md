# Report 005 — Correction: `B:A` leaves the previous static model at state 121

## Summary

The previously published static model was wrong after state `121`.

The old model claimed:

```text
121 → 9 → 438 → 365
```

That chain is revoked for this sample/build.

Direct source mapping shows that state `121` is handled by `B:Z` and returns **42 unconditionally**, and state `42` is handled by `B:T` and returns **48** on the observed source branch that installs the `c.ep` closure.

The resulting transition is:

```text
121 → 42 → 48
```

The earlier `43238 > 20936` bounds contradiction was therefore an artifact of entering a handler that the corrected static path does not reach.

## Source-grounded transitions

### State 121 — `B:Z`

For the relevant branch:

```lua
local Y,Z=1+v,k[1];return 42,k[2],Z,P,Y,I,z;
```

This transition has no runtime predicate in the selected branch:

```text
121 → 42
```

### State 42 — `B:T`

The relevant branch creates the `c.ep` closure, installs it into `P[2][5]`, then returns state 48:

```lua
local c={[B.ep]=function(I,r) ... end};
P[2][5]=c;local B=P[1];return 48,P[2],B,c,v,z;
```

So:

```text
42 → 48
```

This is the handoff into the third interpreter layer.

## Static candidate chain after A321

The current source-derived candidate chain is:

```text
321 → 145 → 212 → 437 → 283 → 314 → 121 → 42 → 48
```

with the following handlers:

| state | handler | condition | selected next |
|---:|---|---|---:|
| 321 | `Zy` | first byte < 128 | 145 |
| 145 | `B:p` | — | 212 |
| 212 | `B:ny` | `r != 2` | 437 |
| 437 | `B:mW` | `Y != 0` | 283 |
| 283 | `B:Jy` | — | 314 |
| 314 | `B:ay` | `Y >= 128` | 121 |
| 121 | `B:Z` | selected branch is unconditional | 42 |
| 42 | `B:T` | relevant `J > 38` branch | 48 |

The conditions at 212, 437, and 314 are source-derived but their runtime values have not yet been observed. Therefore the whole chain up to 121 remains a **candidate static path**, not a runtime trace.

The correction at state 121 itself is stronger: the prior `121 → 9` mapping is incompatible with this build's source.

## Three interpreter layers

The current architecture is:

| layer | entry | approximate opcode space | initializer |
|---|---|---|---|
| 1 | `J9` | 0..39 via 12 dispatchers | `B:aW()` |
| 2 | `B:A` | ~0..513 / 233 branches | `B:w(I)` |
| 3 | `c.ep` closure created in `B:T` | ~234 opcodes / ~80 micro-handlers | `B:Op()` |

The third layer includes the handler family:

```text
Ap wp vp sp op np kp fp bp Sp Lp Tp mp Gp Up tp qp xp ip zp Yp jp Mp Jp
Ip Qp Rp lp Cp Bp Wp Dp ap Zp Ep hp rp Xp Pp pp Fp Hp Np gp _p c9 V9
d9 K9 y9 e9 O9 A9 w9 v9 s9 o9 n9 k9 f9 b9 S9 L9 T9 m9 G9 U9 t9
q9 x9 i9 z9
```

The known group selectors `f == 89/93/99/223/224/228` belong to this layer.

## Probe-generator bug

The earlier public probe generator used an `A438` anchor from a different sample/build:

```lua
local c,X,y=k+(Y+2097152*(c-c%128))+J+Z,4+I,P[1];return 79,P[2],y,X,j,r,z;
```

The current build instead contains:

```lua
local j,X,y=(J-128)*128+(r-128+k*16384),c+3,v[1];return 365,v[2],y,Y,X,I,j;
```

The register names, limb formula, and return transition all differ. The old probe anchor has been removed from the repository.

## Status

The next runtime evidence needed is the trace immediately after `A321`. If the observed state sequence is:

```text
145, 212, 437, 283, 314, 121, 42, 48
```

then the candidate static path is confirmed and analysis can continue directly inside `c.ep`.
