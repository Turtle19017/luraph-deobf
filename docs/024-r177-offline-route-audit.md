# 024 — R177 offline route audit (receipt consistency, not runtime proof)

## Scope and current boundary

Audited source-derived receipts on `main` after the R177 v2 timeout.
No protected target, reconstructed bytecode, Luau CLI, or prior evidence capture
was executed. This audit only cross-checks **existing committed receipts**.
The original protected `script.txt` is not tracked in this repository.

The user-supplied R177 v2 observation was:

- timeout at 300 s;
- exactly one visible `[runner] === probe start ===`;
- capture includes 131,072 padding characters;
- `[R177PRE]`, `[R177POST]`, and `__R177_DONE__` **not observed**.

This proves the startup marker reached the capture transport. It does not
prove or disprove execution of any later selector or `pc3784`.

## Conditional, receipt-supported route

```text
selector137: pc2651 sets R88=141
  |
selector141: child297 -> R121 (1464316551), R10 equality true
  |            post-not false -> retry once
selector141: child297 -> R86  (1791364062), R10 equality false
  |            post-not true -> R88=50
selector50:  pc838 calls child339 R50(); result discarded
  |            [normal return is a PRECONDITION]
  |          pc839 sets R88=29
selector29:  pc3235 calls child325 R59(R47)
  |            [normal return is a PRECONDITION]
  |          child297 resume #3 -> nil (single-assign context)
  |          R10(nil,R86) -> false; pc3240 sets R88=true
  |          bulk-XOR repair before pc3784
  |          opcode21 pc3784 performs argument preparation
  |            [successful preparation is a PRECONDITION]
  +--------> R177 mega-call; packed returns; next selector UNKNOWN
```

The equality-gate conclusions also require that child331 setup/resume,
child297 wrapping, and upstream constructor/setup calls complete as modeled.
No v2 runtime checkpoint establishes these preconditions.

## Exact pc3784 shape supported by receipts

```json
{"pc":3784,"S":21,"w":156,"s":177,"H":50}
```

For this opcode21 instance the function is in `R177`, the static argument
append span is `R178..R332` (155 registers), and the packed tail register is
`R333`. The probe's `[R177PRE]` marker is **after** the two `k(...)`
argument-preparation operations, not at opcode entry. An absent PRE cannot
distinguish a nonvisited opcode from a stall/error inside preparation, even
after buffering has been addressed.

## R177 provenance is NOT resolved

Three earlier static multi-return destinations include register 177:

| PC | Destination range | Includes R177 |
|---|---|---|
| 2150 | R61..R284 | yes |
| 3504 | R117..R206 | yes |
| 3363 | R155..R202 | yes |

Range overlap does not determine the **last executed writer**, nor whether
R177 is callable at pc3784. The receipt explicitly excludes full dynamic
producer ordering. Do not equate R177 with any one of R61/R117/R155 solely
because 177 lies in their output spans.

## Provenance and confidence

- **Receipt-consistent:** both signed-int32 little-endian sentinel decodes,
  child297 capture order and expected yields, decision-threshold truth values,
  selector transition constants, and pc3784 instruction tuple.
- **Conditional:** selector141 retry and successor selectors *if* intermediate
  calls and VM decode steps succeed on the actual runtime path.
- **Unobserved:** actual selector141/50/29 execution in the v2 run, pc3784
  entry, execution of the R177 call, R88 after the call, R177 last writer,
  and return versus other control transfer.
- **Do not infer:** no PRE after 300 s means R177 was never called or hung.

## Reproduce without running target

```bash
python tools/audit_r177_route.py
# Optional, inspect an existing local capture without executing Luau:
python tools/audit_r177_route.py --capture _probe/capture_R177_v2.txt \
  --json-out _probe/r177_offline_route_audit.json
```

The checker fails closed on missing/inconsistent receipts. A pass means
internal source-receipt agreement, not an independent replay of original
bytes. Local capture/generated files must remain untracked.
