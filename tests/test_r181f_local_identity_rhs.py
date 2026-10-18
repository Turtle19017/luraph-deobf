import importlib.util, json, pathlib, tempfile, unittest
ROOT = pathlib.Path(__file__).resolve().parents[1]
P = ROOT / "tools" / "analyze_r181f_local_identity_rhs.py"
SPEC = importlib.util.spec_from_file_location("r181f", P)
r = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(r)

def receipt(root):
    sites = [
        {"function_id": f"F{i}", "state_id": f"S{i}", "register": -1, "stack_base": 1,
         "operation": "read", "classification": "NO_LINK"} for i in range(7)
    ] + [
        {"function_id": "FS0", "state_id": "SS0", "register": -1, "stack_base": 1,
         "operation": "store", "classification": "AST_EXACT_LOCAL_LINK"},
        {"function_id": "FS1", "state_id": "SS1", "register": -1, "stack_base": 1,
         "operation": "store", "classification": "AST_EXACT_LOCAL_LINK"},
    ]
    obj = {"schema": "luraph-deobf.r181d-index-local-linkage.v2",
           "checkpoint": {"expected": {"functions": 78, "errors": 64, "fallbacks": 0, "requests": 594}},
           "sites": sites}
    p = root / "r181d.json"
    p.write_text(json.dumps(obj), encoding="utf-8")
    return p

def evidence(root, *, left_name="x", local_name="x", local_value=-1, right_type="AstExprIndexExpr", function_prefix="F"):
    p = root / "e.jsonl"
    lines = []
    for i in range(7):
        right = {"type": right_type, "base": {"type": "AstExprLocal", "name": "K"}, "index": {"type": "AstExprLocal", "name": "W"}} if right_type == "AstExprIndexExpr" else {"type": "AstExprCall", "callee": {"type": "AstExprLocal", "name": "v"}, "args": []}
        lines.append(json.dumps({
            "kind": "below_stack", "register": -1, "function_id": f"{function_prefix}{i}", "state_id": f"S{i}",
            "site": {
                "local_values": [{"decl": {"name": local_name, "value": local_value}}],
                "index_ast": {"op": "Sub", "left": {"type": "AstExprLocal", "name": left_name}, "right": right}
            }
        }))
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return p

class R181FTests(unittest.TestCase):
    def test_seven_read_sub_sites(self):
        with tempfile.TemporaryDirectory() as td:
            q = pathlib.Path(td); c = receipt(q); e = evidence(q)
            out = r.analyze(c, [e], 7, 7, 7, 7, 0)
            self.assertEqual(out["summary"]["sub_instances"], 7)
            self.assertEqual(out["summary"]["left_type_counts"], {"AstExprLocal": 7})

    def test_structured_name_matches_snapshot_minus_one(self):
        with tempfile.TemporaryDirectory() as td:
            q = pathlib.Path(td); c = receipt(q); e = evidence(q)
            out = r.analyze(c, [e], 7, 7, 7, 7, 0)
            self.assertEqual(out["summary"]["left_structured_match_minus_one"], 7)
            self.assertFalse(out["interpretation_gate"]["snapshot_value_is_proven_current_at_ast_evaluation"])

    def test_minus_one_value_without_identity_is_not_a_binding(self):
        with tempfile.TemporaryDirectory() as td:
            q = pathlib.Path(td); c = receipt(q); e = evidence(q, left_name="other", local_name="x", local_value=-1)
            out = r.analyze(c, [e], 7, 7, 7, 7, 0)
            self.assertEqual(out["summary"]["left_no_structured_match"], 7)

    def test_rhs_index_and_call_shapes_are_separated(self):
        with tempfile.TemporaryDirectory() as td:
            q = pathlib.Path(td); c = receipt(q)
            p = q / "e.jsonl"; lines = []
            for i in range(7):
                rt = "AstExprIndexExpr" if i < 5 else "AstExprCall"
                right = {"type": rt, "base": {"type": "AstExprLocal", "name": "K"}, "index": {"type": "AstExprLocal", "name": "W"}} if rt == "AstExprIndexExpr" else {"type": rt, "callee": {"type": "AstExprLocal", "name": "v"}, "args": []}
                lines.append(json.dumps({"kind":"below_stack","register":-1,"function_id":f"F{i}","state_id":f"S{i}",
                    "site":{"local_values":[{"decl":{"name":"x","value":-1}}],
                            "index_ast":{"op":"Sub","left":{"type":"AstExprLocal","name":"x"},"right":right}}}))
            p.write_text("\n".join(lines)+"\n",encoding="utf-8")
            out = r.analyze(c, [p], 7, 7, 7, 5, 2)
            self.assertEqual(out["summary"]["right_type_counts"], {"AstExprIndexExpr": 5, "AstExprCall": 2})

    def test_wrong_function_same_state_does_not_match(self):
        with tempfile.TemporaryDirectory() as td:
            q = pathlib.Path(td); c = receipt(q); e = evidence(q, function_prefix="OTHER")
            with self.assertRaisesRegex(ValueError, "no matched frozen Sub AST"):
                r.analyze(c, [e], 7, 7, 7, 7, 0)

    def test_cohort_gate(self):
        with tempfile.TemporaryDirectory() as td:
            q = pathlib.Path(td); c = receipt(q); e = evidence(q)
            with self.assertRaisesRegex(ValueError, "expected 6 read/NO_LINK"):
                r.analyze(c, [e], 6, 7, 7, 7, 0)

if __name__ == "__main__":
    unittest.main()
