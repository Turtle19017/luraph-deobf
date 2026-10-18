# 045 — R182D frozen stable-table-patch census

Static source audit shows that walk-time concrete writes to captured numeric tables are mirrored into `dump.tab_patch`, and `stable_patches()` serializes them by canonical captured table path as `/=key:value` segments. This is the only existing frozen serialization path that may preserve a table-369 value differing from the base `.protos.json` without rerunning the lifter.

R182D selects exactly one R182B `.protos.json` candidate by a unique SHA-256 prefix, reconstructs `Dump.paths()` for table 369 from raw captured table references, and scans only the supplied frozen artifacts for stable table-patch segments matching that exact canonical path. It reports candidate patch values only for keys 165, 356, 1008, 1490, and 1524.

The classifications are deliberately limited. `UNIQUE_NUMERIC_PATCH_CANDIDATE` means the scanned frozen artifacts serialize one numeric stable-patch value for that key. `CONFLICTING_NUMERIC_PATCH_CANDIDATES` withholds a value. `NO_SERIALIZED_PATCH` means only that no stable patch for the exact table path/key was found in the scanned evidence. None of these states proves the per-instruction value seen at a particular underflow site.

Run:

```powershell
$env:PYTHONPATH = ".;.\tests"
py -3 -m unittest discover -s tests -p "test_r182d_stable_table_patches.py" -v

py -3 .\tools\analyze_r182d_stable_table_patches.py `
  .\_probe\v15_root27_table369_base.r182b.json `
  .\_probe\v15_root27_frontier78_attribution_bigstack `
  .\_probe\v15_frontier78_attribution_bigstack.log `
  --protos-sha-prefix 7792d883 `
  --table-id 369 `
  --keys 165 356 1008 1490 1524 `
  --json-out .\_probe\v15_root27_table369_stable_patches.r182d.json
```

No lift, attribution, target execution, live fetch, overlay replay, base-value overwrite, or semantic change is performed.
