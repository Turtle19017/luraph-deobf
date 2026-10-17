# 025 — R177 producer overwrite semantics and write-order proof obligations

## New opcode7 fact

The source-validated mode233 opcode7 multi-return call writes its returned
values starting at the same register that held the callee. Therefore return #1
overwrites the callee register itself.

For the three known producer banks that cover R177:

| PC | Callee/start | Return span | R177 ordinal |
|---:|---:|---:|---:|
| 2150 | R61  | R61..R284  | #117 |
| 3504 | R117 | R117..R206 | #61 |
| 3363 | R155 | R155..R202 | #23 |

The arithmetic is exact: ordinal = `177 - start + 1`.

## Consequence for the existing R177 probe

At pc3784, `eq_R61`, `eq_R117`, and `eq_R155` compare R177 with the
**current** contents of those registers. Those registers may already have been
overwritten by return #1 from their own opcode7 calls. Therefore either equality
or inequality is insufficient to identify which producer last wrote R177.

## Stronger proof obligation

To prove a nested producer chain, the audit must track three registers, not one:

1. all writes to R117 before pc3504;
2. all writes to R155 before pc3363;
3. all writes to R177 before pc3784.

A candidate chain

```text
pc2150 -> pc3504 -> pc3363 -> pc3784
```

is proven only if a **complete offline write ledger** establishes:

```text
last_writer(R117, before pc3504) = pc2150
last_writer(R155, before pc3363) = pc3504
last_writer(R177, before pc3784) = pc3363
```

and the ledger includes direct writes and other multi-register write forms, not
only the three known opcode7 banks.

The nested register intervals are suggestive but are not themselves ordering
evidence.

## Tooling

`tools/audit_r177_write_order.py` validates the committed producer receipt and
fails closed on an optional complete ledger. Without a ledger it intentionally
reports:

```text
proof: UNKNOWN
last writer: UNKNOWN
```

Example with a future offline ledger:

```bash
python tools/audit_r177_write_order.py \
  --ledger _probe/r177_write_ledger.json \
  --json-out _probe/r177_write_order.audit.json
```

No Luau target execution is performed by this checker.
