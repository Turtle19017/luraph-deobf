# 028 — R178C path-conditioned write fates

## Scope

R178C consumes an R178B CFG-footprint JSON file and performs conservative
register-value fate analysis without importing or executing the devirtualizer.
It does not enumerate unbounded execution paths and it does not prune evaluator
state.

Each result describes one path-conditioned write instance. The stage deliberately
does not merge duplicated common-prefix writes back into a single source write;
R178B does not yet emit stable source-statement origin identifiers for that
operation.

## Fate lattice

For one register value, R178C stops at the first relevant event on every
continuation:

- `READ`: the current value is definitely consumed before clobber.
- `CLOBBER`: another exact write replaces the value before a read.
- `DEAD`: the path terminates by return/crash without a read or clobber.
- `BARRIER`: a dynamic alias, call/frame effect, indirect effect, or unknown IR
  statement prevents a negative claim.
- `INCOMPLETE`: the continuation is absent or ends without a proved terminal.
- `LOOP`: a continuation SCC can cycle without first reaching a decisive event.
- `INCONSISTENT_CFG`: R178B reported a leaf/CFG successor mismatch at the source.

The exported classifications are:

- `MUST_LIVE` iff the only possible fate is `READ`.
- `MUST_SHADOWED` iff the only possible fate is `CLOBBER`.
- `MUST_DEAD` iff the only possible fate is `DEAD`.
- `PATH_DEPENDENT` when all fates are decisive but disagree across branches.
- `UNKNOWN` when any unresolved fate remains.

Only `MUST_SHADOWED` and `MUST_DEAD` set `safe_negative_claim=true`.

## CFG fixed point instead of path explosion

For each tracked register, R178C builds a continuation graph from R178B
micro-paths. A micro-path that reaches a read, clobber, or barrier contributes
that local fate and stops. A micro-path with no relevant event and a `next`
outcome contributes an edge to its successor.

Tarjan SCC detection marks cyclic continuation components with `LOOP`. The fate
set for each node is then computed as a backwards fixed point by unioning local
fates with successor fate sets. This avoids unbounded loop unrolling while
remaining fail-closed.

A loop does not automatically make every incoming write unknown. If every path
reaches a decisive clobber before re-entering the cycle, the earlier write can
still be `MUST_SHADOWED`. A cycle that can preserve the current value around the
loop contributes `LOOP` and therefore blocks a negative claim.

## Call and alias barriers

R178C understands the conservative R178B call events:

- `may_read_all_registers` blocks negative proof because the current value may be
  consumed.
- `may_write_all_registers` blocks proof because the current value may be
  clobbered through a frame alias.
- `may_write_registers` blocks proof for captured registers specifically.
- exact post-call `frame_eval` writes remain ordinary exact writes because R178B
  records the call barrier before them.

Indirect assignments, `SetList`, close-upvalue effects, and unknown IR statements
are also barriers until a later stage discharges their alias/effect footprint.

## Current pruning boundary

R178C intentionally emits:

```text
global_prune_ready = false
proof_status = PATH_CONDITIONED_WRITE_FATES
```

A `safe_negative_claim` is valid for that path-conditioned write instance, but
it is not yet permission to delete the corresponding source/IR write globally.
The next proof obligation is to attach stable origin IDs in R178B and prove that
all duplicated instances of one source write agree on a negative fate.

## Usage

```bash
python tools/analyze_r178c_cfg_write_fates.py \
  _probe/r178b_cfg_PROTO.json \
  --register 177 \
  --json-out _probe/r178c_fates_PROTO.json
```

Omit `--register` to analyze every exact register written in the R178B document.
The `_probe` outputs remain local/untracked.


## Origin propagation

When R178B supplies `origin_id` and `statement_origin`, R178C copies them
unchanged onto each path-conditioned write-fate row. This allows R178D to group
the duplicated micro-path instances of one retained node-IR write without
guessing from PC, register, or traversal order.
