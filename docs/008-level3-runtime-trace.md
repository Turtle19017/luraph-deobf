# 008 — Bounded runtime trace for the first level-3 invocation

## Why this trace is needed

The source-derived level-3 map is now exact for:

- state → micro-handler ownership,
- the closed state domain 0..238,
- conservative successor candidates after accounting for formal shadowing.

What it still does **not** tell us is which runtime-dependent edge is taken in a
real `c[B.ep]` invocation, or which serialized buffer/cursor that invocation
actually reads.

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

This identifies the runtime buffer/cursor used by that branch. The first
observed run disproved the earlier block-1 assumption:

```text
proto  = 159
cursor = 63037
byte   = 45
buflen = 79999
```

The 79,999-byte length is consistent with the previously recovered J9 `z[7]`
buffer, but length alone is not pointer identity proof.

## Build

```bash
python tools/make_level3_trace_probe.py \
  script.txt \
  -o script_level3_trace.luau \
  --budget 2048
```

Assemble the harness without executing it through the short-lived builder,
then use the durable capture runner:

```bash
python tools/build_and_run_probe.py \
  /path/to/luau \
  script_level3_trace.luau \
  tools/roblox_shim.luau \
  -o run_level3.luau \
  --build-only

python tools/run_luau_capture.py \
  /path/to/luau \
  run_level3.luau \
  -o capture_level3.txt \
  --timeout 300
```

Using `--build-only` avoids the older builder's `subprocess.run(..., timeout=...)`
path discarding partial output when the target survives indefinitely.


After capture, validate the runtime sequence against the source-derived graph:

```bash
python tools/level3_runtime_context.py \
  capture_level3.txt \
  --json level3_runtime_context.json
```

If the recovered J9 `z[7]` buffer is available, cross-check it as the runtime
buffer candidate:

```bash
python tools/level3_runtime_context.py \
  capture_level3.txt \
  --candidate-buffer luraph_j9_z_7.bin \
  --json level3_runtime_context.json
```

The verifier checks every observed runtime edge against
`receipts/luraph_level3_state_graph.tsv`, checks that the observed final state
is terminal, and compares the candidate buffer length plus byte at the runtime
cursor. It deliberately reports candidate-buffer agreement as consistency
evidence rather than pointer identity proof.

## First observed run

The first bounded trace produced:

```text
8 -> 204 -> 12 -> 94 -> 207 -> 16 -> 72 -> 68
  -> 117 -> 142 -> 117 -> 147 -> 153 -> 83
```

Every edge is present in the conservative source graph, and state `83` is the
special `up` terminal state. The earlier predicted `204 -> 80` was not a state
graph error; it came from incorrectly applying block-1 bytes to a different
runtime buffer.

The original probe printed `[L3TERM] run=2..226 n=0`. This does **not** mean
those invocations executed zero states: the probe increments `__l3n` only while
`__l3trace` is true, and `__l3trace` is enabled only for run 1. Later `n=0`
values are therefore an instrumentation artifact. The probe has been changed to
emit `[L3TERM]` only for the traced invocation.

## Trust boundary

The probe does not claim that every statically possible successor is reachable.
The state graph remains a source-derived over-approximation.

A runtime sequence from this probe promotes only the edges actually printed for
that first closure invocation. Semantic lifting should follow those observed
states first; unobserved graph edges remain static possibilities only.
