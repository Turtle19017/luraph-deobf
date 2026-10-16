# 007 — Exact level-3 state map and static successor graph

## Result

The third interpreter can now be mapped without guessing binary-search "group"
counts and without executing the target.

A block-aware parser walks the nested `if/elseif/else/end` tree inside the
`c[B.ep]` closure built by `B:T`. It then maps the closure argument `t` into the
formal parameter used by each micro-handler and follows that handler's own
state branch.

For target SHA-256:

```text
02dc0c6a922796ad4773cbd051745225e4d6bf84d61c9b8c666be71b57f58443
```

the source-derived result is:

```text
state domain       0..238   (239 states)
micro-handlers     73
exact ranges       73
entry              t=8 -> B:vp
terminal state     83
```

The complete table is committed as:

```text
receipts/luraph_level3_state_graph.tsv
```

and the compact machine-readable summary is:

```text
receipts/luraph_level3_state_graph.summary.json
```

## Exact ranges

Unlike the earlier 21/38 "bound group" counts, these ranges are semantic: every
integer state in a range dispatches to that handler.

The start of the map is:

```text
  0..  2  Ap
  3..  6  wp
  7..  9  vp
 10.. 13  sp
 14.. 16  op
 17.. 20  np
 21.. 24  kp
 25.. 28  fp
```

and the end is:

```text
209..211  m9
212..215  G9
216..219  U9
220..223  t9
224..226  q9
227..230  x9
231..234  i9
235..238  z9
```

This also fixes the domain boundary: the final open-ended source branch is
`z9`, but no micro-handler produces a next state above 238. State 238 itself
returns to state 22.

## Successor extraction

For the ordinary 72 closure leaves, the handler call assigns its first return
value directly to `t`, so the first return expression is the next state.
Every reachable first return expression in this sample resolves to either:

- one integer state, or
- a Luau `condition and A or B` expression where both `A` and `B` are integer
  states.

Runtime-dependent conditions are conservatively unioned. For example:

```text
state 7  -> vp -> {111}
state 8  -> vp -> {204, 210}
state 9  -> vp -> {150, 222}
```

Runtime tracing later observed the first invocation taking `8 -> 204`, with
`[L3VP8] byte=45` from a 79,999-byte runtime buffer. That observation is
consistent with the source condition for state 8, but it is separate runtime
evidence rather than part of this source-only graph.

## The one special closure leaf: `up`

States 81..84 call `B:up`, but its first return is a control code `o`, not the
next interpreter state:

```text
o,T,... = B:up(...)
if o==1 then
    t,... = T,...
elseif o==2 then
    return V
end
```

The parser asserts that exact wrapper before using the second return as the next
state. The resulting semantics are:

```text
81 -> 70
82 -> {164, 221}
83 -> terminal
84 -> 224
```

Treating the first `up` return as `t` would incorrectly create edges to states 1
and 2.

## Static reachability

A review of the first successor extractor found one important scope bug: a
handler formal can initially carry the dispatcher state and then be shadowed by
a local of the same name. Conditions after that shadow are runtime data, not
tests of the original state.

Three states were affected:

```text
5   wp : {228}  -> {78, 228}
143 gp : {104}  -> {104, 169}
184 o9 : {149}  -> {149, 156}
```

Those three added edges lead exactly to the three states previously reported as
unreachable. With shadowing handled conservatively, the static
over-approximation from entry state `8` now contains **239 of 239 states**.

This still does **not** mean all 239 states are observed at runtime. It means
source control flow alone cannot eliminate any state once runtime-dependent
conditions are conservatively unioned.

## Reproduce

```bash
python tools/level3_state_graph.py script.txt \
  --json level3_state_graph.json
```

The tool is fail-closed for the known sample SHA unless
`--allow-foreign-sha` is supplied. It also fails if:

- the 73-handler census changes,
- a dispatch leaf stops assigning the current state in the expected way,
- a successor expression cannot be reduced to integer state choices,
- the `B:up` wrapper changes,
- a state-carrying formal is shadowed/reassigned and later treated as if it still
  held the original dispatcher state, or
- a successor leaves the derived state domain.

## What this unlocks

The level-3 dispatcher no longer needs a runtime trace merely to answer
"which handler owns state N?" The next useful step is semantic lifting of the
states actually exercised while parsing the verified block-1 plaintext, using
this table as the control-flow backbone.
