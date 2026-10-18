# 032 — R180A fresh-frame slot-zero provenance

## Motivation

The accepted R179B-v4 census has 49 underflow nodes: 30 read/store slot zero and
19 negative-slot nodes. The existing artifact shows no slot-zero nil proof for
those 30 nodes, so R0 must not be treated as nil merely because it is below the
frame floor.

The existing experimental zero-slot implementation also had a proof-source
problem: any `table.create` executed during a prologue immediately wrote
`frame_entry_facts[0] = ("c", None)`. That proves a new table has no key zero,
but it does not by itself prove that the table is the VM register frame.

## R180A hardening

R180A keeps `DEVIRT_ZERO_SLOT_FACT` off by default and changes only its proof
plumbing.

A prologue `table.create` now returns a fresh `RegFile` candidate carrying an
object-local slot-zero fact. It does **not** publish a frame-entry fact.

The candidate is promoted only after the same `RegFile` is explicitly stored
into itself, matching the frame-self-alias pattern `frame[k] = frame`. The
promoted fact is tagged with provenance:

```text
fresh-regfile-self-alias
```

A direct prologue write to VM register zero remains an independent proof source:

```text
direct-prologue-reg0-write
```

A write to key zero before self-alias changes the object-local candidate fact,
so later promotion preserves that actual value instead of restoring nil.
Unknown writes kill the promoted fact. Multiple distinct self-alias candidates
mark frame identity ambiguous and cannot create another fresh-frame proof.

FRAMEFAIL diagnostics now include the current slot-zero entry fact and its proof
source so a future authorized targeted run can distinguish fresh-frame proof
from unrelated SCCP facts.

## Boundary

R180A does not enable `DEVIRT_ZERO_SLOT_FACT`, does not reinterpret any of the
30 accepted R0 failures, does not rerun the lift, and does not change the
78/64/594 checkpoint. A site becomes eligible for a nil read only if the
existing SCCP invalidation rules also preserve the exact nil fact to that
specific node.
