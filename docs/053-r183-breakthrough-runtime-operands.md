# 053 — R183-v2 breakthrough integration

R183-v1 stopped in preflight before any long run. The failure was integration-specific, not evidence against the negative-slot hypothesis:

- the local attribution driver removes `DEVIRT_*` environment variables;
- the seven R181F canonical sites currently carry `mode=null, pc=null`;
- the driver retains accepted engine/stat/output-hash locks and lives in a workspace-level `_probe` while the Git repository may be nested below that workspace;
- one unit test compared two distinct `Const(7)` objects by object identity instead of comparing the constant payload.

R183-v2 fixes those integration defects without weakening the permanent semantic gate.

## Engine bytes remain baseline

The checked-in R183-v1 negative-slot branch in `core/obfuscators/luraph_v15/devirt.py` is reverted. The experiment is now installed only inside the child Python process by `tools/r183_sitecustomize.py`. This keeps the engine file at its pre-R183 bytes, so a legacy driver that checks the engine hash continues to see the accepted engine.

The bootstrap is injected through `PYTHONPATH` and maps two R183-only controls to the legacy variables:

- `R183_FRAME_DEBUG=1` protects `DEVIRT_FRAME_DEBUG=1`;
- `R183_NEG1_SLOT_EXPERIMENT=1` protects `DEVIRT_NEG1_SLOT_EXPERIMENT=1` and installs the in-memory experiment.

The bootstrap protects only those exact keys against driver-side environment deletion. It emits an `[R183BOOT]` JSON marker, and the runner refuses to continue if that marker does not prove the requested mode.

The in-memory experiment intercepts only a `RegFile` access whose normalized key is exactly `-1` while `stack_base == 1`. It temporarily passes that access through the pre-existing ordinary register machinery. Register zero, other negative registers, and other stack bases retain the baseline guard. No repository-default semantics are promoted by this experiment.

## Two distinct gates

R183A-v2 no longer pretends that the null `mode/pc` values in R181F are available.

The **diagnostic accepted-location gate** is anchored to the already accepted 78/64/594 summary and its exact source/output hashes. That baseline contains exactly seven unique read-underflow errors for register `-1`. A fresh debug rerun must produce, at every one of those seven exact `(mode,pc)` locations:

- `kind=below_stack`;
- `register=-1`;
- `stack_base=1`;
- a binary `Sub` index AST;
- numeric evaluated `left`, `right`, and `result`;
- `left - right == result == -1`;
- no conflicting record at a covered location;
- no additional fresh read/-1 failure outside the accepted seven-location set.

Only that full gate can start the diagnostic negative-slot experiment.

The **canonical composite-identity gate** remains stricter. It is true only when the seven R181F rows themselves supply a unique `(mode,pc) -> (function_id,state_id)` mapping. With the current R181F receipt's null `mode/pc`, this gate remains false. Therefore R183-v2 can measure the experimental frontier while still refusing to call the experiment accepted semantics.

In all cases:

```text
semantic_change_authorized = false
permanent_semantic_change_authorized = false
```

A successful diagnostic rerun is measurement, not a semantic promotion.

## Path and frozen-input integration

`tools/run_r183_breakthrough.py` now discovers the workspace rather than assuming the Git repository and `_probe` are siblings inside one directory.

It locates the unique ancestor/sibling `_probe` containing `attribute_root27_frontier78.py`, sets the driver's working directory to `_probe.parent`, and independently keeps the repository root from the runner's own file location. It then discovers:

- the accepted source by exact SHA-256
  `02dc0c6a922796ad4773cbd051745225e4d6bf84d61c9b8c666be71b57f58443`;
- the R181F and R182C receipts under that `_probe`;
- an accepted baseline summary with exactly 78 functions, 64 errors, 0 fallbacks, 594 requests, the accepted source hash, and output hash
  `a26d509d79dfbc8cd41c0d751707f6fff3689d36fc193cc3de15e418d2c24075`;
- the R182C-selected proto snapshot. If the serialized absolute path is stale, the runner searches below the discovered `_probe` and requires the exact
  `7792d8830f7f87d3df25c5db243cd27b03c114eda2bcb121788bf8ea85160aa6`
  hash before proceeding.

No snapshot is merged or rewritten.

## Legacy post-run locks

The capture pass should still satisfy the baseline driver locks because debug capture is observation-only and the engine file is reverted to its pre-R183 bytes.

The experimental pass deliberately changes behavior. A legacy driver may therefore exit nonzero after it has generated useful output because its final stats/output assertion still expects the old checkpoint. R183-v2 records that exit and scans the emitted JSON/log artifacts for experimental stats. A nonzero exit is never converted into acceptance.

## Commands

After pulling the R183-v2 integration commit:

```powershell
$env:PYTHONPATH = ".;.\tests"

py -3 -m unittest discover -s tests -p "test_r183_exact_underflow_capture.py" -v
py -3 -m unittest discover -s tests -p "test_r183_neg1_slot_experiment.py" -v
py -3 -m unittest discover -s tests -p "test_r183_runner_integration.py" -v
```

These are 8 analyzer tests, 5 bootstrap/experiment tests, and 5 runner-integration tests.

Before spending time on the long run, resolve only integration:

```powershell
py -3 .\tools\run_r183_breakthrough.py --preflight-only
```

This prints the discovered repository, workspace, `_probe`, local driver, source, R181F/R182C receipts, accepted baseline summary, and selected 7792 snapshot. It performs no attribution rerun.

When those paths are correct:

```powershell
py -3 .\tools\run_r183_breakthrough.py
```

The runner first performs the exact-operand capture. Only if all seven accepted locations pass the failure-time arithmetic gate does it automatically start the in-memory `-1` experiment.

Primary outputs:

- `_probe/v15_root27_r183v2_exact_operands.log`
- `_probe/v15_root27_exact_sub_operands.r183a.v2.json`
- `_probe/v15_root27_r183v2_neg1_experiment.log` when the diagnostic gate opens
- `_probe/v15_root27_breakthrough.r183.v2.status.json`

R183-v2 does not perform a live constant fetch and does not alter either accepted snapshot.
