"""Bounded, conservative register provenance; diagnostics only, never feeds lift facts."""
def census(d, nodes, reverse, failures, entry, facts, captured=(), complete=True):
    reports = []
    for failed_key, register, prefix in failures:
        visiting = set()
        memo = {}
        trace = []
        seen_edges = set()
        visits = [0]

        def unknown(reason):
            return ("UNKNOWN", reason)

        def merge(results):
            if results and all(r[0] == "CONST" for r in results):
                first = results[0][1]
                if all(type(r[1]) is type(first) and r[1] == first for r in results):
                    return ("CONST", first)
            return unknown("incoming paths do not all prove the same constant")

        def expr(value, key, stmts, pos, depth):
            if isinstance(value, d.Const):
                return ("CONST", value.v)
            if isinstance(value, d.Reg):
                return scan(key, value.n, stmts, pos, depth + 1)
            if isinstance(value, d.Bin):
                a = expr(value.a, key, stmts, pos, depth + 1)
                b = expr(value.b, key, stmts, pos, depth + 1)
                if a[0] == b[0] == "CONST":
                    try:
                        return ("CONST", d.S.Interp(None).binop(value.op, a[1], b[1]))
                    except (d.Unsupported, ValueError, TypeError, ZeroDivisionError, OverflowError):
                        pass
            return ("EXPR", d.fmt_any(value))

        def scan(key, reg, stmts, pos, depth):
            visits[0] += 1
            if depth > 128 or visits[0] > 20000:
                return unknown("resource limit")
            for i in range(pos - 1, -1, -1):
                st = stmts[i]
                if isinstance(st, d.Assign):
                    if isinstance(st.target, d.Reg) and st.target.n == reg:
                        trace.append({"state": repr(key), "register": reg,
                                      "definition": d.fmt_stmt(st),
                                      "lattice": "ALIAS" if isinstance(st.value, d.Reg) else
                                      "CONST" if isinstance(st.value, d.Const) else "EXPR"})
                        return expr(st.value, key, stmts, i, depth + 1)
                    if not isinstance(st.target, (d.Reg, d.Upval, d.Pseudo)):
                        return ("CLOBBER", "indirect store may alias register")
                elif isinstance(st, d.CallStmt):
                    if reg in captured:
                        return ("CLOBBER", "call may modify captured register")
                elif not isinstance(st, d.Close):
                    return ("CLOBBER", "unmodelled IR effect: " + type(st).__name__)
            return incoming(key, reg, depth + 1)

        def paths(node, prefix=()):
            seq = prefix + tuple(node.stmts)
            if node.cond is None:
                return [seq] if not getattr(node, "error", None) else None
            # Overapproximate both branches, even if only one reaches this target.
            if node.then is None or node.els is None:
                return None
            a, b = paths(node.then, seq), paths(node.els, seq)
            return a + b if a is not None and b is not None and len(a) + len(b) <= 64 else None

        def incoming(key, reg, depth):
            query = (key, reg)
            if query in memo:
                return memo[query]
            if query in visiting:
                return unknown("cycle without proved invariant")
            if key == entry:
                trace.append({"state": repr(key), "register": reg, "lattice": "ENTRY"})
                return ("ENTRY", None)
            preds = reverse.get(key, set())
            if not preds:
                return unknown("no recorded predecessor")
            visiting.add(query)
            results = []
            for pred in sorted(preds, key=repr):
                seen_edges.add((pred, key))
                node = nodes.get(pred)
                sequences = paths(node) if node is not None else None
                if sequences is None:
                    results.append(unknown("missing/error/unsupported predecessor"))
                else:
                    results.extend(scan(pred, reg, seq, len(seq), depth + 1) for seq in sequences)
            visiting.remove(query)
            result = merge(results)
            memo[query] = result
            return result

        result = scan(failed_key, register, prefix, len(prefix), 0)
        if not complete:
            result = unknown("walk incomplete/restarted; proof withheld")
        reports.append({
            "state_key": repr(failed_key), "mode": failed_key[0], "pc": failed_key[1],
            "register": register, "result": result,
            "incoming_predecessors": len(reverse.get(failed_key, set())),
            "checked_reverse_edges": len(seen_edges), "scan_queries": visits[0],
            "distinct_queries": len(memo), "trace": trace[:200],
            "trace_truncated": len(trace) > 200,
            "sccp_fact_at_failure": repr(facts.get(failed_key, {}).get(register)),
            "walk_complete": complete,
            "branch_policy": "both branches overapproximated; no first-wins",
        })
    return reports
