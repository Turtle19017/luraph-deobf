# 030 — R179A edge-fact control resolution

## Accepted frontier census

The accepted offline checkpoint remains **78 functions / 64 errors / 594
requests** with matching output hash. The completed attribution census classifies
the 64 errors as:

- 49 stack/frame underflow failures;
- 5 symbolic next PC/mode failures;
- 9 Missing-condition failures;
- 1 nil/bxor failure.

Nine requests are directly linked to the nine Missing-condition failures. No
causal claim is made for the other 585 requests.

All five symbolic PC/mode failures have a RAW_REG read for a register that is
already present in `jump_regs`.

This report is evidence from the completed census. R179A does not rerun the
protected target, does not run `--all`, and does not alter the accepted
78/64/594 receipt.

## Code hole

`Program._walk()` already receives edge-specific SCCP facts `nf` from
`propagate()`. Before R179A, a successor whose `pc` or `mode` was still a
symbolic `Reg` skipped directly to jump-register discovery/error handling.
When that register was already in `lf.jump_regs`, the set of *new* jump
registers was empty and the walk emitted `symbolic next pc/mode`.

The walk did not first ask whether the outgoing edge facts already proved that
symbolic control value to be an exact integer.

## R179A

`resolve_control_facts(state, facts)` is called on every propagated successor
before transport threading and symbolic-control handling.

The helper is intentionally narrow:

- only `mode` and `pc` are considered;
- only an exact `("c", integer)` SCCP fact is accepted;
- booleans, truthiness-only facts and unknown values are rejected;
- no decoder is replayed;
- no new request is issued;
- no jump-register guess is introduced.

The walk metric `control_fact_resolutions` records how many successor control
fields were concretized this way.

## Regression boundary

Synthetic tests cover:

1. a direct symbolic successor `pc = Reg(6)` where the outgoing edge contains
   the proved assignment `R6 = 7`; the walk must reach PC 7 even when R6 is
   already in `jump_regs`;
2. exact integer mode/PC facts are accepted;
3. boolean and truthiness-only facts remain symbolic.

R179A is a **candidate fix** for the five census failures, not proof that those
five are closed. Their actual reduction must be measured only on a later
authorized offline checkpoint run. The dominant 49-underflow lane remains the
next attribution target regardless.
