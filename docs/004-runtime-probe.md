# Report 004 — Corrected A-layer runtime probes

## Status

The original probe design targeted a supposed `438 → 365` divergence. That
path is not part of the valid successor chain for this build and the old A438
anchor also matched a different handler layout.

The corrected probe strategy has two separate jobs.

## Probe 1 — block census

`tools/make_A_probe.py` instruments only the verified A-layer block decoder
checkpoints:

```text
[A99]  seed_in / seed0 / size / src
[A321] decoded-buffer length / first byte / next state
```

The A99 marker now includes the A register `q`, passed into `B:Q` as
parameter `J`, under the label `src`.

That source offset is the remaining datum needed to reconstruct each block
offline.

Runtime tracing has already established eleven A99 invocations with these
`seed_in,size` pairs:

```text
164,20936
325,186
229,462
129,7397
305,2479
339,231
347,640
281,578
187,738
283,250
211,3693
```

Total decoded size: **37,590 bytes**.

## Probe 2 — successor trace after A321

`tools/make_A_trace_probe.py` activates tracing only after state 321 chooses
its continuation.

At the top of the `B:A` dispatch loop it logs:

```text
(C) <state>
```

while suppressing the hot decode-loop states:

```text
99, 323, 228, 321
```

This prevents the byte-by-byte LCG loop from consuming the trace budget.

The source-supported candidate chain currently under confirmation is:

```text
145 → 212 → 437 → 283 → 314 → 121 → 42 → 48
```

The conditional transitions at 212, 437 and 314 must still be confirmed by the
runtime successor trace. The `121 → 42 → 48` suffix is direct in source.

## Environment survival gate

A reduced Roblox shim previously terminated at a dynamically resolved
`.cancel` access. Supplying `task.cancel` and the additional Roblox-like
environment objects/services allowed the target to continue.

This is currently treated as an environment-survival condition, not evidence
that the A-layer successor chain itself changes.

## Offline handoff

Once all eleven A99 lines contain `src`, use:

```bash
python tools/extract_lcg_blocks.py luraph_j9_z_7.bin \
  --trace probe.log \
  --expect-known-sample
```

The extractor performs the LCG-XOR reconstruction only; it does not execute the
protected target.
