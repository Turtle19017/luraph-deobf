# 026 — R178A ordered state liveness census

## Purpose

R178A is a **census-only** stage.  It does not prune evaluator state and it does
not execute the protected target.  Its job is to attach conservative
write→consumer status to an already-recorded, ordered offline event ledger.

The analyzer intentionally separates this from R177's write-order checker.
R177 can prove a *last writer* only from a complete write ledger.  R178A needs
both read and write completeness before it is allowed to call an unconsumed
write `SHADOWED` or `DEAD`.

## Classifications

- `LIVE`: a definite read (or host-effect read) consumes the exact location
  before a definite overwrite.  This does not require completeness because the
  consumer itself is positive evidence.
- `SHADOWED`: a definite later write overwrites the location before any read,
  but only when control order and both read/write completeness are asserted for
  that location.
- `DEAD`: an explicit path boundary is reached without a consumer or overwrite,
  under the same completeness requirements.
- `UNKNOWN`: the fail-closed result for incomplete ledgers, dynamic aliases,
  missing boundaries, or other unresolved cases.

All classifications are **per ordered path**.  The output explicitly sets
`global_dead_store_claims=false`; a per-path `DEAD` is not a whole-program dead
store proof unless another stage proves complete path enumeration.

## Packed provenance

If a write event carries `packed_provenance`, R178A copies that JSON object
unchanged into the corresponding write-instance rows.  Constant-decoding or
packed-source provenance therefore survives liveness attribution instead of
being collapsed to the decoded literal alone.

## Preferred ledger schema

```json
{
  "schema": "luraph-deobf.r178a-state-event-ledger.v1",
  "source_commit": "729391a",
  "control_order_complete": true,
  "complete_for_locations": ["BR:117", "BR:155", "BR:177"],
  "events": [
    {"seq": 1, "path": "f28/w270", "kind": "opcode7-return-bank",
     "pc": 2150, "register_start": 61, "register_end": 284},
    {"seq": 2, "path": "f28/w270", "kind": "opcode7-return-bank",
     "pc": 3504, "register_start": 117, "register_end": 206},
    {"seq": 3, "path": "f28/w270", "kind": "opcode7-return-bank",
     "pc": 3363, "register_start": 155, "register_end": 202},
    {"seq": 4, "path": "f28/w270", "kind": "read",
     "pc": 3784, "register": 177},
    {"seq": 5, "path": "f28/w270", "kind": "boundary", "pc": 3784}
  ]
}
```

With a proof-complete ledger shaped like the example, the R177 writes to R177
classify as:

```text
pc2150  R177  SHADOWED
pc3504  R177  SHADOWED
pc3363  R177  LIVE      (consumer pc3784)
```

That result is only valid because the example explicitly asserts complete read
and write coverage plus complete control order.  Removing those assertions
makes the same negative claims `UNKNOWN`.

## Dynamic aliases

A dynamic access must be marked as a may-alias event, for example:

```json
{"seq": 12, "kind": "read", "alias": "MAY", "alias_space": "BR"}
```

Such an event can consume any `BR:*` write, so R178A refuses to infer
`SHADOWED` or `DEAD` across it.  An alias with no declared space is treated as
potentially touching every location.

## Usage

```bash
python tools/analyze_r178a_state_liveness.py \
  _probe/r178a_state_events.json \
  --expect-source-commit 729391a \
  --json-out _probe/r178a_state_liveness.json
```

The `_probe` files remain local/untracked.  The analyzer and unit tests are the
only repository changes in this stage.

## Current evidence boundary

The committed R177 tooling contains a write-census and write-order proof
obligation, but not a proof-complete read ledger.  Therefore R178A must not
synthesize reads from numeric PC order, register overlap, or absence of a write.
A local extractor may feed R178A only after it can state exactly which locations
have complete read and write coverage on each ordered path.
