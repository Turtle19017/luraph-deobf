# 042 — R182A frame-index diagnostic capture hardening

R181F/R181G establish that the seven read failures evaluate a Sub expression whose left operand is a local and whose right operand is either K[W] or a call to bit32.bxor. R181H-v2 then shows that the already-saved frozen evidence does not contain the table contents or call arguments needed to reconstruct those RHS values.

Static source audit explains the gap. In core/luasym.py, _debug_ast_index previously serialized AstExprCall as only func + argc, dropping the argument ASTs. Separately, Interp.eval evaluates both operands of an ordinary AstExprBinary before binop, so the concrete RHS value already exists immediately before the final frame index is attempted, but that evaluated operand/result triple was not retained.

R182A changes diagnostics only:
- AstExprCall fingerprints now include bounded structural fingerprints for each argument AST.
- When DEVIRT_FRAME_DEBUG is enabled, the most recent ordinary binary evaluation records structured left/right/result values.
- If the exact same binary AST is then used as the failing frame index, the below-stack failure receives index_eval with those values.
- With DEVIRT_FRAME_DEBUG disabled, no binary value capture occurs.

No VM semantics, constant propagation, frame interpretation, table lookup, call behavior, zero-slot behavior, or lifting gate is changed. This patch does not reinterpret the accepted 78/64/594 checkpoint and does not require an immediate rerun.
