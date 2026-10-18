import importlib.util, json, pathlib, tempfile, unittest
ROOT = pathlib.Path(__file__).resolve().parents[1]
P = ROOT / "tools" / "analyze_r181g_rhs_local_dependencies.py"
SPEC = importlib.util.spec_from_file_location("r181g", P)
r = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(r)

def receipt(root, *, right_kind="index", mismatch=False):
    instances = []
    for i in range(136):
        if i < 95:
            right = {
                "type": "AstExprIndexExpr",
                "expr": {"type": "AstExprLocal", "local": {"name": "K"}},
                "index": {"type": "AstExprLocal", "local": {"name": "W"}},
            }
        else:
            right = {
                "type": "AstExprCall",
                "func": {"type": "AstExprLocal", "local": {"name": "v"}},
                "argc": 1,
            }
        snapshots = [
            {"path": "$.locals[0].decl", "name": "K", "value": "TABLE", "ids": [], "encoding": "decl-name-value"},
            {"path": "$.locals[1].decl", "name": "W", "value": 3, "ids": [], "encoding": "decl-name-value"},
            {"path": "$.locals[2].decl", "name": "v", "value": "FUNC", "ids": [], "encoding": "decl-name-value"},
        ]
        if mismatch:
            snapshots = [{"path": "$.locals[0].decl", "name": "other", "value": 7, "ids": [], "encoding": "decl-name-value"}]
        instances.append({
            "function_id": f"F{i%7}", "state_id": f"S{i%7}",
            "right_type": right["type"], "right_node": right,
            "local_snapshot_entries": snapshots,
        })
    obj = {
        "schema": "luraph-deobf.r181f-local-identity-rhs-census.v1",
        "checkpoint": {"expected": {"functions": 78, "errors": 64, "fallbacks": 0, "requests": 594}},
        "cohort_sites": 7,
        "summary": {
            "sub_instances": 136,
            "left_type_counts": {"AstExprLocal": 136},
            "right_type_counts": {"AstExprIndexExpr": 95, "AstExprCall": 41},
            "left_structured_match_other": 136,
        },
        "instances": instances,
    }
    p = root / "r181f.json"
    p.write_text(json.dumps(obj), encoding="utf-8")
    return p

class R181GTests(unittest.TestCase):
    def test_exact_gate_and_rhs_counts(self):
        with tempfile.TemporaryDirectory() as td:
            q = pathlib.Path(td)
            out = r.analyze(receipt(q))
            self.assertEqual(out["summary"]["instances"], 136)
            self.assertEqual(out["summary"]["rhs_type_counts"], {"AstExprIndexExpr": 95, "AstExprCall": 41})

    def test_indexexpr_local_dependencies_bind(self):
        with tempfile.TemporaryDirectory() as td:
            q = pathlib.Path(td)
            out = r.analyze(receipt(q))
            self.assertEqual(out["index_expr_types"], {"AstExprLocal": 95})
            self.assertEqual(out["index_index_types"], {"AstExprLocal": 95})
            self.assertEqual(out["rhs_local_paths"]["$.expr"], 95)
            self.assertEqual(out["rhs_local_paths"]["$.index"], 95)

    def test_call_func_and_argc_are_inventory_only(self):
        with tempfile.TemporaryDirectory() as td:
            q = pathlib.Path(td)
            out = r.analyze(receipt(q))
            self.assertEqual(out["call_func_types"], {"AstExprLocal": 41})
            self.assertEqual(out["call_argc"], {"1": 41})
            self.assertEqual(out["call_args_field"], {"absent": 41})
            self.assertFalse(out["interpretation_gate"]["call_value_evaluated"])

    def test_structured_snapshot_matches_are_dependencies_not_timing_proof(self):
        with tempfile.TemporaryDirectory() as td:
            q = pathlib.Path(td)
            out = r.analyze(receipt(q))
            self.assertEqual(out["summary"]["rhs_unique_snapshot_matches"], 231)
            self.assertFalse(out["interpretation_gate"]["snapshot_value_is_live_at_rhs_evaluation"])

    def test_identity_mismatch_does_not_bind_by_value(self):
        with tempfile.TemporaryDirectory() as td:
            q = pathlib.Path(td)
            out = r.analyze(receipt(q, mismatch=True))
            self.assertEqual(out["summary"]["rhs_unique_snapshot_matches"], 0)
            self.assertEqual(out["summary"]["rhs_no_snapshot_match"], 231)

    def test_bad_checkpoint_fails(self):
        with tempfile.TemporaryDirectory() as td:
            q = pathlib.Path(td); p = receipt(q)
            obj = json.loads(p.read_text()); obj["checkpoint"]["expected"]["requests"] = 593
            p.write_text(json.dumps(obj))
            with self.assertRaisesRegex(ValueError, "checkpoint"):
                r.analyze(p)

if __name__ == "__main__":
    unittest.main()
