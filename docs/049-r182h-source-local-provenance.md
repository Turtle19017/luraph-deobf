# 049 — R182H source declaration/write provenance

R182G exhausted the already-saved frozen value evidence for the missing call inputs: across the two exact composite states, `K`, `W`, `f`, `h`, and `r` have no captured value candidate, while `v` has only `EVENT_PLUS_NAME_UNIQUE`. R182H therefore changes axis from frozen value search to exact static source provenance.

R182H reparses the exact source under the accepted source SHA-256 gate and uses the declaration locations recovered by R182E-v2 as local identities. It never groups locals by name alone. For each of `K`, `W`, `f`, `h`, and `r`, it identifies the source declaration kind, initializer fingerprint, exact direct assignments to the same declaration, assignments originating inside nested closures, exact-source use count, declaration owner function, and whether that owner is the same function as the recovered bxor call.

The classifications are:

- `PARAMETER`
- `LOCAL_SINGLE_INIT_NO_REASSIGN`
- `LOCAL_INIT_MUTATED`
- `LOCAL_NO_INIT_NO_ASSIGN`
- `LOCAL_NO_INIT_ASSIGNED`
- `LOCAL_COMPLEX_INIT`
- `LOCAL_FUNCTION`
- `FOR_VARIABLE`
- `FORIN_VARIABLE`
- `UNKNOWN_DECL`

`LOCAL_SINGLE_INIT_NO_REASSIGN` and `LOCAL_FUNCTION` are reported as single-static-origin candidates only. That means the source has one syntactic origin and no direct reassignment to the exact declaration anywhere in the parsed source, including writes found inside nested closures. It does not prove the runtime value, object contents, call-time timing, or any table overlay state. Lexical `BEFORE`/`AFTER` labels are source-position facts only and do not prove execution order.

Run:

```powershell
$env:PYTHONPATH = ".;.\tests"
py -3 -m unittest discover -s tests -p "test_r182h_source_local_provenance.py" -v

py -3 .\tools\analyze_r182h_source_local_provenance.py `
  .\_probe\v15_root27_source_call_args.r182e.v2.json `
  .\script.txt `
  --expect-source-sha256 02dc0c6a922796ad4773cbd051745225e4d6bf84d61c9b8c666be71b57f58443 `
  --json-out .\_probe\v15_root27_source_local_provenance.r182h.json
```

If the exact accepted source lives elsewhere, replace `.\script.txt` with that path and keep the SHA gate unchanged.

No lift, attribution, target execution, live fetch, frozen-value reinterpretation, table-overlay replay, candidate evaluation, or semantic change is performed.
