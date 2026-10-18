# 027 — R178B CFG register footprints

## Scope

R178B is the bridge between the R177/R178A provenance work and future liveness
summaries. It does **not** prune state and it does **not** change the evaluator.
The exporter invokes `Program.lift_raw()` on an already-captured offline
snapshot, then inspects the returned IR plus `Program.edges`.

The worklist `order` returned by `_walk()` is explicitly **not** treated as
execution order. It is only the set/order in which graph nodes were retained.
Control flow comes from the IR leaf outcomes and the propagated CFG edges.

## Output

`tools/export_r178b_cfg_footprints.py` emits:

- the entry state key and final walk metrics;
- every retained CFG node and its proved successors;
- one micro-path for each internal branch leaf of a node;
- ordered register-read/register-write events inside each micro-path;
- call, indirect-store, set-list, and close-upvalue barriers;
- transport-edge provenance for NOP chains skipped by transport threading;
- edge mismatch / missing-target diagnostics.

A node such as:

```text
r3 = r1 + r2
if r4 then
    r5 = 1
    -> A
else
    r6 = 2
    -> B
end
```

is exported as two micro-paths. Both read `R1`, `R2`, and `R4`; only the true
leaf writes `R5`, and only the false leaf writes `R6`. The two branches are not
unioned into one fake linear trace.

## Calls and frame aliases

Ordinary call arguments contribute exact register reads. A call remains a
`call-barrier`; R178B does not assume it is pure. If a `FrameArg`/register-file
argument is present, the micro-path records a may-read-all-registers barrier.
If `CallStmt.frame_eval` contains exact writes, those writes are emitted while
the read barrier remains; otherwise the frame call also remains a
may-write-all-registers barrier.

This is deliberately conservative. Calls also carry `may_write_registers` for
`lf.captured_regs`, matching the evaluator's existing rule that any call kills
facts for captured registers. A `FrameArg` records both its concrete holder
register read and the may-read-all frame alias. A later stage may discharge a
barrier with handler- or callee-specific evidence, but R178B itself never
invents purity.

## Transport threading

`thread_transport()` can omit transparent fallthrough nodes from `order`. These
are safe to keep outside the footprint list because the existing transport
invariant requires no statements, condition, error, or transport effects.
R178B records the skipped keys separately on each transport edge rather than
pretending they disappeared without provenance.

## Completeness

`graph_complete=true` only when the final `_walk()` metrics say:

```text
restart = false
reason  = complete
```

A walk-limit result, pending restart, symbolic jump, unstable pack, or missing
CFG target remains incomplete.

R178B intentionally emits:

```text
r178a_ledger_ready = false
proof_status = CFG_FOOTPRINTS_ONLY
```

because a CFG with loops/branches is not yet a proof-complete ordered event
ledger. The next stage must summarize or enumerate the relevant paths before
feeding negative liveness claims (`SHADOWED` / `DEAD`) into R178A.

## Usage

```bash
python tools/export_r178b_cfg_footprints.py \
  SOURCE.lua SNAPSHOT.json PROTO_KEY \
  --source-commit 3d6a1a2 \
  --json-out _probe/r178b_cfg_PROTO_KEY.json
```

Optional `--chunk` arguments mirror the devirtualizer's offline chunk inputs.
The generated `_probe` file remains local/untracked.
