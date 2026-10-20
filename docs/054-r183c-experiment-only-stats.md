# 054 — R183C experiment-only exact stats

R183 established two facts without authorizing a semantic change:

1. all seven accepted read/-1/base=1 locations are exact failure-time `Sub -> -1` arithmetic;
2. the in-memory -1 experiment removes that cohort completely (60 records -> 0) but does not increase the observed function traversal beyond 78.

The interrupted experiment did not reach a final driver summary, so its exact `errors` and `requests` totals remain unknown. R183C exists only to obtain those exact post-experiment totals. It does **not** rerun the capture phase.

## Gate

R183C requires the saved `v15_root27_exact_sub_operands.r183a.v2.json` receipt to prove:

- checkpoint 78/64/0/594;
- 7/7 matched sites;
- 7/7 exact Sub -> -1;
- 0 nonexact records;
- 0 extra read/-1 locations;
- diagnostic experiment gate true;
- semantic change authorization false;
- accepted source/output hash anchors unchanged.

The engine file must still have Git blob SHA-1:

```text
8d6d9158bcff3b086dfb9812cf4bbf55c9c54572
```

and the accepted source/proto hashes remain:

```text
source  02dc0c6a922796ad4773cbd051745225e4d6bf84d61c9b8c666be71b57f58443
protos  7792d8830f7f87d3df25c5db243cd27b03c114eda2bcb121788bf8ea85160aa6
```

## Exact stats marker

When the experiment process starts, `r183_sitecustomize.py` installs the same in-memory negative-slot patch plus a stats wrapper around the engine's `collect_requests` and `lift_program` entry points.

Immediately after either engine call returns, before the legacy driver's own summary/hash assertions, the wrapper emits:

```text
[R183STATS] {"kind": ..., "functions": ..., "errors": ..., "fallbacks": ...,
             "walked": ..., "fetched": ..., "requests": ...}
```

The marker is flushed to stderr. This means an otherwise-useful experiment can still yield exact engine totals even if the legacy driver subsequently rejects changed stats/output.

Every marker is preserved in the R183C receipt. The final complete marker is selected as the experiment result. If no marker exists, a generated-summary fallback is accepted only when every complete summary candidate under the new experiment label agrees exactly. Conflicting summaries fail closed.

## Run

Tests:

```powershell
$env:PYTHONPATH = ".;.\tests"

py -3 -m unittest discover -s tests -p "test_r183_runner_integration.py" -v
py -3 -m unittest discover -s tests -p "test_r183c_experiment_stats.py" -v
```

Then perform only the fresh experiment run:

```powershell
py -3 .\tools\run_r183_experiment_stats.py
```

Default fresh label:

```text
v15_root27_r183c_neg1_stats
```

Primary artifacts:

```text
_probe/v15_root27_r183c_neg1_stats.log
_probe/v15_root27_r183c_neg1_stats.process.json
_probe/v15_root27_r183c_neg1_stats.json
```

The accepted capture log is not executed or regenerated.

If the parent/server restarts again after the log has been written, recover without rerunning:

```powershell
py -3 .\tools\run_r183_experiment_stats.py `
  --recover-log .\_probe\v15_root27_r183c_neg1_stats.log
```

Use a different `--json-out` only if the default receipt already exists; the tool refuses overwrite.

## Interpretation

Even if R183C proves an improved error/request count, it remains a diagnostic experiment:

```text
capture_rerun_performed = false
negative_slot_experiment_only = true
canonical_composite_identity_proved = false
semantic_change_authorized = false
accepted_checkpoint_unchanged = true
```

The experiment can tell us whether eliminating the -1 cohort merely transforms the same 78-function frontier or materially reduces the remaining blocker set. It cannot by itself authorize the -1 behavior as permanent devirtualizer semantics.
