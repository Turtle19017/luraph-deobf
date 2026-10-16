# 008 — Bounded runtime trace for the first level-3 invocation

## Why this trace is needed

The source-derived level-3 map is now exact for:

- state → micro-handler ownership,
- the closed state domain 0..238,
- conservative successor candidates after accounting for formal shadowing.

What it still does **not** tell us is which runtime-dependent edge is taken while
the verified block-1 plaintext is actually parsed.

That runtime path is the shortest way to decide which subset of the 239 states
needs semantic lifting first.

## Probe

`tools/make_level3_trace_probe.py` instruments only the first `c[B.ep]`
closure invocation.

It is fail-closed on target SHA-256:

```text
02dc0c6a922796ad4773cbd051745225e4d6bf84d61c9b8c666be71b57f58443
```

and requires three unique source anchors:

1. the `c[B.ep]` closure prologue,
2. the `vp` state-8 branch,
3. the `up` terminal wrapper.

Generated instrumented targets are excluded from Git.

## Output

The trace is batched so it does not print one line per interpreter iteration.

```text
[L3CHUNK] run 1 n 1  states 8,
[L3CHUNK] run 1 n 32 states ...
...
[L3TAIL]  run 1 n N  states ...
[L3TERM]  run 1 n N
```

Every 32-state batch is followed by padding to force stdout through Luau's
block buffering before a timeout/kill.

A focused entry marker is also emitted from `vp` state 8:

```text
[L3VP8] proto <n> cursor <n> byte <n> buflen <n> buf <identity>
```

This is intended to answer whether the entry read really corresponds to
block1[0] == 0x01, and identifies the runtime buffer/cursor used by that branch.

## Build

```bash
python tools/make_level3_trace_probe.py \
  script.txt \
  -o script_level3_trace.luau \
  --budget 2048
```

Run the generated target with the existing Roblox shim and
`tools/run_luau_capture.py`/harness workflow from report 006.

## Trust boundary

The probe does not claim that every statically possible successor is reachable.
The state graph remains a source-derived over-approximation.

A runtime sequence from this probe promotes only the edges actually printed for
that first closure invocation. Semantic lifting should follow those observed
states first; unobserved graph edges remain static possibilities only.
