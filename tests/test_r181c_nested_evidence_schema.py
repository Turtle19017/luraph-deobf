import importlib.util
import json
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
P = ROOT / "tools" / "analyze_r181c_nested_evidence_schema.py"
SPEC = importlib.util.spec_from_file_location("r181c", P)
r = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(r)


def r181b(root):
    obj = {
        "schema": "luraph-deobf.r181b-negative-slot-provenance.v1",
        "checkpoint": {"expected": {"functions": 78, "errors": 64, "fallbacks": 0, "requests": 594}},
        "sites": [
            {"function_id": f"F{i}", "state_id": f"S{i}", "register": -1, "stack_base": 1}
            for i in range(9)
        ],
    }
    p = root / "r181b.json"
    p.write_text(json.dumps(obj), encoding="utf-8")
    return p


class R181CTests(unittest.TestCase):
    def test_nested_producer_and_raw_key_are_found(self):
        with tempfile.TemporaryDirectory() as td:
            q = pathlib.Path(td); c = r181b(q)
            e = q / "e.jsonl"
            e.write_text(json.dumps({
                "kind": "below_stack", "register": -1, "function_id": "F0", "state_id": "S0",
                "debug": {"index": {"raw_key": -1, "producer": {"temp": 7}}},
            }) + "\n", encoding="utf-8")
            out = r.analyze(c, [e], 9)
            paths = {x["path"] for x in out["nested_candidate_paths"]}
            self.assertIn("$.debug.index.raw_key", paths)
            self.assertIn("$.debug.index.producer.temp", paths)

    def test_minus_one_nested_path_is_counted_not_interpreted(self):
        with tempfile.TemporaryDirectory() as td:
            q = pathlib.Path(td); c = r181b(q)
            e = q / "e.jsonl"
            e.write_text(json.dumps({
                "kind": "below_stack", "register": -1, "function_id": "F0", "state_id": "S0",
                "ctx": {"expr": {"lhs": -1}},
            }) + "\n", encoding="utf-8")
            out = r.analyze(c, [e], 9)
            self.assertTrue(any(x["path"] == "$.ctx.expr.lhs" for x in out["minus_one_paths"]))
            self.assertFalse(out["interpretation_gate"]["minus_one_value_implies_origin"])

    def test_wrong_function_same_state_is_ignored(self):
        with tempfile.TemporaryDirectory() as td:
            q = pathlib.Path(td); c = r181b(q)
            e = q / "e.jsonl"
            e.write_text(json.dumps({
                "kind": "below_stack", "register": -1, "function_id": "OTHER", "state_id": "S0",
                "debug": {"producer": {"temp": 1}},
            }) + "\n", encoding="utf-8")
            out = r.analyze(c, [e], 9)
            self.assertEqual(out["summary"]["matched_record_instances"], 0)

    def test_list_indices_normalize(self):
        with tempfile.TemporaryDirectory() as td:
            q = pathlib.Path(td); c = r181b(q)
            e = q / "e.jsonl"
            e.write_text(json.dumps({
                "kind": "below_stack", "register": -1, "function_id": "F0", "state_id": "S0",
                "recent_ir": [{"expr": 1}, {"expr": 2}],
            }) + "\n", encoding="utf-8")
            out = r.analyze(c, [e], 9)
            rows = [x for x in out["candidate_paths"] if x["path"] == "$.recent_ir[].expr"]
            self.assertEqual(rows[0]["hits"], 2)

    def test_cohort_gate(self):
        with tempfile.TemporaryDirectory() as td:
            q = pathlib.Path(td); c = r181b(q); e = q / "e"; e.mkdir()
            with self.assertRaisesRegex(ValueError, "expected 8 R181B cohort"):
                r.analyze(c, [e], 8)


if __name__ == "__main__":
    unittest.main()
