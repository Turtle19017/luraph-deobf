import importlib.util
import json
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
P = ROOT / "tools" / "analyze_r181d_index_local_linkage.py"
SPEC = importlib.util.spec_from_file_location("r181d", P)
r = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(r)

def census(root):
    obj = {
        "schema": "luraph-deobf.r181b-negative-slot-provenance.v1",
        "checkpoint": {"expected": {"functions": 78, "errors": 64, "fallbacks": 0, "requests": 594}},
        "sites": [{"function_id": f"F{i}", "state_id": f"S{i}", "register": -1, "stack_base": 1} for i in range(9)],
    }
    p = root / "r181b.json"
    p.write_text(json.dumps(obj), encoding="utf-8")
    return p

class R181DTests(unittest.TestCase):
    def test_exact_structured_local_link(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td); c=census(q); e=q/"e.jsonl"
            e.write_text(json.dumps({
                "kind":"below_stack","register":-1,"function_id":"F0","state_id":"S0",
                "site":{"local_values":{"x":-1},"index_ast":{"op":"Sub","lhs":{"local":"x"},"rhs":{"name":"K"}}}
            })+"\n", encoding="utf-8")
            out=r.analyze(c,[e])
            self.assertEqual(out["summary"]["AST_EXACT_LOCAL_LINK"],1)

    def test_textual_link_is_weaker(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td); c=census(q); e=q/"e.jsonl"
            e.write_text(json.dumps({
                "kind":"below_stack","register":-1,"function_id":"F0","state_id":"S0",
                "site":{"local_values":{"x":-1},"index_ast":{"op":"Sub","repr":"x - K[W]"}}
            })+"\n", encoding="utf-8")
            out=r.analyze(c,[e])
            self.assertEqual(out["summary"]["TEXTUAL_LOCAL_LINK"],1)
            self.assertFalse(out["proof_gate"]["textual_link_proves_origin"])

    def test_cooccurrence_not_link(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td); c=census(q); e=q/"e.jsonl"
            e.write_text(json.dumps({
                "kind":"below_stack","register":-1,"function_id":"F0","state_id":"S0",
                "site":{"local_values":{"x":-1},"index_ast":{"op":"Sub","lhs":{"name":"K"},"rhs":{"name":"W"}}}
            })+"\n", encoding="utf-8")
            out=r.analyze(c,[e])
            self.assertEqual(out["summary"]["CO_OCCURRENCE_ONLY"],1)

    def test_wrong_function_same_state_ignored(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td); c=census(q); e=q/"e.jsonl"
            e.write_text(json.dumps({
                "kind":"below_stack","register":-1,"function_id":"OTHER","state_id":"S0",
                "site":{"local_values":{"x":-1},"index_ast":{"op":"Sub","lhs":{"local":"x"}}}
            })+"\n", encoding="utf-8")
            out=r.analyze(c,[e])
            self.assertEqual(out["summary"]["NO_LINK"],9)

    def test_key_tree_text_link(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td); c=census(q); e=q/"e.jsonl"
            e.write_text(json.dumps({
                "kind":"below_stack","register":-1,"function_id":"F0","state_id":"S0",
                "site":{"local_values":{"x":-1},"key_tree":{"repr":"Sub(x,K[W])"}}
            })+"\n", encoding="utf-8")
            out=r.analyze(c,[e])
            self.assertEqual(out["summary"]["TEXTUAL_LOCAL_LINK"],1)
    def test_decl_list_schema_exact_link(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td); c=census(q); e=q/"e.jsonl"
            e.write_text(json.dumps({
                "kind":"below_stack","register":-1,"function_id":"F0","state_id":"S0",
                "site":{
                    "local_values":[{"decl":{"name":"x","value":-1}}],
                    "index_ast":{"op":"Sub","lhs":{"local":"x"},"rhs":{"name":"K"}}
                }
            })+"\n", encoding="utf-8")
            out=r.analyze(c,[e])
            self.assertEqual(out["summary"]["AST_EXACT_LOCAL_LINK"],1)
            ev=out["sites"][0]["evidence"][0]
            self.assertEqual(ev["minus_one_local_entries"][0]["encoding"],"decl-name-value")

    def test_carried_locals_list_decl_schema(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td); c=census(q); e=q/"e.jsonl"
            e.write_text(json.dumps({
                "kind":"below_stack","register":-1,"function_id":"F0","state_id":"S0",
                "frame":{
                    "carried_locals":[
                        {"decl":{"name":"x","value":-1}},
                        {"decl":{"name":"y","value":7}}
                    ]
                },
                "site":{"index_ast":{"op":"Sub","rhs":{"identifier":"x"}}}
            })+"\n", encoding="utf-8")
            out=r.analyze(c,[e])
            self.assertEqual(out["summary"]["AST_EXACT_LOCAL_LINK"],1)
            self.assertEqual(out["sites"][0]["evidence"][0]["minus_one_locals"],["x"])

    def test_decl_name_value_nonminus_is_not_linked(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td); c=census(q); e=q/"e.jsonl"
            e.write_text(json.dumps({
                "kind":"below_stack","register":-1,"function_id":"F0","state_id":"S0",
                "site":{
                    "local_values":[{"decl":{"name":"x","value":3}}],
                    "index_ast":{"op":"Sub","lhs":{"local":"x"}}
                }
            })+"\n", encoding="utf-8")
            out=r.analyze(c,[e])
            self.assertEqual(out["summary"]["NO_LINK"],9)


if __name__ == "__main__":
    unittest.main()
