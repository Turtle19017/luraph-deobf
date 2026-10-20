# 054 — R183B experiment-only exact stats rerun

R183A-v2 has already closed the diagnostic arithmetic question: 7/7 accepted read/-1 locations were observed, every matched record was an exact numeric Sub whose result was -1, and there were zero conflicting records and zero additional read/-1 locations. The diagnostic gate is true while the canonical composite-identity gate remains false.

The first negative-slot experiment removed all 60 read/-1/base=1 records while traversal remained at 78 functions / 642 walks. A server restart occurred before the legacy driver emitted its final summary, so experiment errors and requests remain unknown. The accepted checkpoint therefore remains 78/64/594.

R183B does not rerun the expensive baseline capture. It consumes the existing standard R183A-v2 receipt and runs only a new negative-slot experiment under a fresh label.

## Exact stats capture

`tools/r183_sitecustomize.py` has an optional `R183_STATS_CAPTURE=1` hook. When enabled, it wraps the Luraph v15 `collect_requests` and `lift_program` functions inside the child process only. Immediately when either function returns, before a legacy post-run assertion can reject changed stats/output, it flushes a JSON line prefixed with `[R183STATS]`.

The record includes `functions`, `errors`, `fallbacks`, `walked`, `fetched`, and `requests`, where `requests` is the exact size of the returned request set.

R183B selects the last `collect_requests` marker in the experiment log and preserves all earlier markers in the receipt. A missing marker or a non-integer `functions/errors/fallbacks/requests` field fails closed.

## Input gates

Before running the experiment, R183B requires the exact R183A-v2 schema; 7/7 matched sites; 7/7 exact Sub -> -1 sites; zero nonexact records; zero extra read/-1 locations; diagnostic gate true; semantic-change authorization false; the accepted source SHA-256; checked-in `devirt.py` Git blob `8d6d9158bcff3b086dfb9812cf4bbf55c9c54572`; and selected proto snapshot SHA-256 `7792d8830f7f87d3df25c5db243cd27b03c114eda2bcb121788bf8ea85160aa6`.

The experiment patch remains in-memory and off by default. R183B never promotes it to accepted semantics and never replaces the accepted 78/64/594 checkpoint automatically.

## Run

First run only the new regression file:

```powershell
$env:PYTHONPATH = ".;.\tests"
py -3 -m unittest discover -s tests -p "test_r183_experiment_stats.py" -v
```

Then run exactly one new experiment label:

```powershell
py -3 .\tools\run_r183_experiment_stats.py `
  --label v15_root27_r183b_neg1_stats
```

Do not rerun R183 capture.

Outputs:

```text
_probe/v15_root27_r183b_neg1_stats.log
_probe/v15_root27_r183b_neg1_stats.process.json
_probe/v15_root27_r183b_neg1_stats.receipt.json
```

A legacy driver may still exit nonzero because its final assertion expects the accepted old checkpoint. That does not invalidate an already-flushed `[R183STATS]` record. The R183B receipt records the driver exit code separately and leaves `accepted_checkpoint_replaced=false`.

The decisive result is `selected_collect_stats`, especially `functions`, `errors`, `fallbacks`, and `requests`. Together with the already-observed 78 functions / 642 walks, this determines whether suppressing the exact -1 cohort merely converts those failures into other failures/requests or actually improves the error/request profile.


## Windows checkout normalization gate

R183B does not compute a Git blob id from raw working-tree bytes. On Windows,
a valid checkout can contain CRLF while the Git object stores normalized LF,
so hashing raw bytes would reject an unchanged tracked file.

The engine gate now asks Git for the object identity directly:

```text
git rev-parse HEAD:core/obfuscators/luraph_v15/devirt.py
```

and requires that exact blob to equal
`8d6d9158bcff3b086dfb9812cf4bbf55c9c54572`.

It separately requires both the staged and working-tree views of that path to
be clean according to Git itself:

```text
git diff --cached --quiet -- <path>
git diff --quiet -- <path>
```

Those comparisons honor Git's text filters, so filter-equivalent CRLF/LF
checkouts pass while a real content change still fails closed. No line-ending
rewrite or gate bypass is performed.
