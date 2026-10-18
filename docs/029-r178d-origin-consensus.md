# 029 — R178D stable-origin consensus

## Scope

R178D is still a proof/receipt stage. It does not remove IR statements and it
does not modify evaluator state. It consumes R178C path-conditioned write fates
and groups the duplicated micro-path instances that R178B proves came from the
same retained node-IR write origin.

R178B origin IDs are derived from the full state-key repr hash plus the internal
branch-tree position, statement index, register and write role. A statement that
appears before an internal branch therefore keeps one origin across every
flattened branch leaf. Writes located in different branch subtrees receive
different origins.

These IDs intentionally identify a retained **node-IR write**, not an asserted
identity between different VM state nodes or protected-source statements.

## Consensus

For every `(origin_id, register)` group:

- `PROVEN_UNCONSUMED` means every represented instance is a safe R178C negative
  result (`MUST_SHADOWED` or `MUST_DEAD`). Mixing shadowed and dead is allowed:
  either way the value written by that origin is never read before replacement
  or path termination.
- `PROVEN_LIVE` means every represented instance is `MUST_LIVE`.
- `PATH_DEPENDENT` means represented instances have decisive but incompatible
  fates, for example one live branch and one dead branch.
- `UNKNOWN` means at least one instance is unresolved or the origin metadata is
  unavailable.

The output contains `prunable_origins`, but also explicitly sets
`pruning_applied=false`. A future stage can use this receipt to experiment with
IR pruning behind a feature gate; R178D itself performs no rewrite.

## End-to-end regression

The integration regression builds one synthetic node with a common-prefix write
and two leaves:

```text
R1 = 7
if cond then
    R1 = 8       # common value is shadowed
    return
else
    return       # common value dies unread
end
```

R178B emits the same origin ID for the duplicated `R1 = 7` event, R178C assigns
`MUST_SHADOWED` and `MUST_DEAD` to the two path-conditioned instances, and R178D
merges them to `PROVEN_UNCONSUMED`.

## Usage

```bash
python tools/analyze_r178d_origin_consensus.py \
  _probe/r178c_fates_PROTO.json \
  --json-out _probe/r178d_origin_consensus_PROTO.json
```

The `_probe` output remains local/untracked.
