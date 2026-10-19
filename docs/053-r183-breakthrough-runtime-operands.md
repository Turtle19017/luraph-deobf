# 053 — R183 breakthrough: exact failure-time Sub operands and gated -1-slot experiment

R181/R182 reduced the negative-underflow lane to seven read/Sub sites in the exact `(function_id,state_id)` cohort, but frozen snapshots could not prove the call-time values of `K/W/f/h/r`. R182A already added a stronger diagnostic: when `DEVIRT_FRAME_DEBUG=1`, the interpreter records the evaluated left operand, right operand, and result of the exact binary index node immediately before the frame access fails. For the 41 call-shaped RHS instances, that `right` value is the final result of the whole `bit32.bxor(...)` expression, so no nested local reconstruction is required to prove the final arithmetic.

R183A consumes a fresh debug rerun and joins `[FRAMEFAIL]` records back to the seven accepted R181F sites. The join is not by rendered error text: R181F's `(mode,pc)` must be unique across the seven canonical composite identities, after which each failure is assigned back to its exact `(function_id,state_id)`. Only `kind=below_stack`, `register=-1`, `stack_base=1`, `index_ast.op=Sub` records are considered. An exact record requires numeric failure-time `left`, `right`, and `result`, verifies `left-right==result`, and requires `result==-1`.

The breakthrough gate opens only when all seven sites have at least one matched failure record, every deduplicated matched record at every site is an exact arithmetic `Sub -> -1`, and no site has a nonexact/conflicting record. That proves arithmetic origin for the covered failures. It does not prove that register -1 is nil, does not prove the frame base is wrong, and does not by itself authorize a permanent semantic change.

For fast measurement, core/devirt also contains an OFF-by-default diagnostic flag `DEVIRT_NEG1_SLOT_EXPERIMENT`. It affects only the exact observed cohort condition `register == -1 && stack_base == 1`. With the flag on, reads and ordinary stores continue through the existing register machinery instead of raising the underflow guard. Zero and other negative slots are unchanged. The flag is diagnostic only and is never enabled by default.

`tools/run_r183_breakthrough.py` performs the fast path in one command. It verifies the accepted source SHA and the R182C-selected `7792d883...85160aa6` proto snapshot, runs the existing local root27 attribution driver with `DEVIRT_FRAME_DEBUG=1`, scans both the primary log and files emitted under `_probe/<capture-label>/`, writes the R183A receipt, and—only if the seven-site exact-arithmetic gate opens—automatically performs a second diagnostic rerun with `DEVIRT_NEG1_SLOT_EXPERIMENT=1`. The second run remains an experiment; no accepted semantics are changed.

Run tests first:

```powershell
$env:PYTHONPATH = ".;.\tests"
py -3 -m unittest discover -s tests -p "test_r183_exact_underflow_capture.py" -v
py -3 -m unittest discover -s tests -p "test_r183_neg1_slot_experiment.py" -v
```

Then the one-shot breakthrough run:

```powershell
py -3 .\tools\run_r183_breakthrough.py
```

Defaults assume the existing local files used throughout this lane:

- `_probe/attribute_root27_frontier78.py`
- `_probe/v15_root27_frontier78_local_identity_rhs.r181f.json`
- `_probe/v15_root27_base_sub_consistency.r182c.json`
- `script.txt`

Outputs are fail-closed and refuse overwrite:

- `_probe/v15_root27_r183_exact_operands.log`
- `_probe/v15_root27_exact_sub_operands.r183a.json`
- `_probe/v15_root27_r183_neg1_experiment.log` (only if the gate opens)
- `_probe/v15_root27_breakthrough.r183.status.json`

The runner performs no live constant fetch. It reuses the accepted offline attribution driver/snapshot. The experimental second pass changes behavior only through the process-local environment flag and leaves the repository default semantics unchanged.
