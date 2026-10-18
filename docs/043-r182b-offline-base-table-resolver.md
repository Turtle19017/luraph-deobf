# 043 — R182B offline base-table resolver

Static audit shows that a captured LTable is not opaque in the original proto dump. `Dump._load_tables` creates each `LTable(tid=N)` directly from `d["tables"][N]`, loading positional `arr` entries first and then `kv` entries. Therefore `LTable#369` can be inspected offline if the original saved `.protos.json` used by the frontier run still exists.

R182B searches explicit files or directories for `*.protos.json` and resolves table 369 at the five keys required by R181G: 165, 356, 1008, 1490, and 1524. It reports the raw source (`arr` or `kv`), a bounded decoded value summary, late-key membership, `mt`/`mtf` presence, `pid`, and a SHA-256 anchor for every candidate file.

The resolver intentionally does not instantiate the devirtualizer and does not replay table overlays. `ProtoLifter.index` can consult per-state overlays after reading the base LTable, so a value recovered by R182B is only the saved base/late dump value. It is not proof that the same value was observed at the failing state.

Example:

```powershell
py -3 .\tools\resolve_r182b_table_from_protos.py . `
  --table-id 369 `
  --keys 165 356 1008 1490 1524 `
  --json-out .\_probe\v15_root27_table369_base.r182b.json
```

For a narrower search, replace `.` with the output directory or exact `.protos.json` file from the accepted frontier run.

No lift, attribution, target execution, live fetch, overlay replay, or semantic change is performed.
