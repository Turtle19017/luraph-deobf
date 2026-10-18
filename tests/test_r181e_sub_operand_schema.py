import importlib.util,json,pathlib,tempfile,unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
P=ROOT/"tools"/"analyze_r181e_sub_operand_schema.py"
SPEC=importlib.util.spec_from_file_location("r181e",P); r=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(r)

def receipt(root):
    sites=[
        {"function_id":f"F{i}","state_id":f"S{i}","register":-1,"stack_base":1,
         "operation":"read","classification":"NO_LINK"} for i in range(7)
    ]+[
        {"function_id":"FS0","state_id":"SS0","register":-1,"stack_base":1,
         "operation":"store","classification":"AST_EXACT_LOCAL_LINK"},
        {"function_id":"FS1","state_id":"SS1","register":-1,"stack_base":1,
         "operation":"store","classification":"AST_EXACT_LOCAL_LINK"}
    ]
    obj={"schema":"luraph-deobf.r181d-index-local-linkage.v2",
         "checkpoint":{"expected":{"functions":78,"errors":64,"fallbacks":0,"requests":594}},
         "sites":sites}
    p=root/"r181d.json"; p.write_text(json.dumps(obj),encoding="utf-8"); return p

def evidence(root,layout=None):
    layout=layout or {"op":"Sub","lhs":{"repr":"K[W]"},"rhs":{"repr":"v(x)"}}
    p=root/"e.jsonl"
    p.write_text("\n".join(json.dumps({"kind":"below_stack","register":-1,
        "function_id":f"F{i}","state_id":f"S{i}","site":{"index_ast":layout}})
        for i in range(7))+"\n",encoding="utf-8")
    return p

class R181ETests(unittest.TestCase):
    def test_seven_read_sub_sites(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td); out=r.analyze(receipt(q),[evidence(q)],7)
            self.assertEqual(out["cohort_sites"],7)
            self.assertEqual(out["summary"]["sites_with_sub_ast"],7)

    def test_operand_fields_are_measured_not_interpreted(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td); out=r.analyze(receipt(q),[evidence(q)],7)
            self.assertEqual(out["child_fields"]["lhs"],7)
            self.assertEqual(out["child_fields"]["rhs"],7)
            self.assertFalse(out["interpretation_gate"]["sub_layout_proves_operand_semantics"])

    def test_args_list_layout_is_preserved(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td)
            out=r.analyze(receipt(q),[evidence(q,{"op":"Sub","args":[{"repr":"K[W]"},{"repr":"v(x)"}]})],7)
            self.assertEqual(out["child_fields"]["args"],7)
            self.assertTrue(any("args::list[2]"==k for k in out["child_shapes"]))

    def test_wrong_function_same_state_ignored_and_gate_fails(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td); c=receipt(q)
            p=q/"e.jsonl"
            p.write_text("\n".join(json.dumps({"kind":"below_stack","register":-1,
                "function_id":"OTHER","state_id":f"S{i}","site":{"index_ast":{"op":"Sub","lhs":1,"rhs":2}}})
                for i in range(7))+"\n",encoding="utf-8")
            with self.assertRaisesRegex(ValueError,"lacks frozen Sub AST evidence"):
                r.analyze(c,[p],7)

    def test_expected_cohort_gate(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td)
            with self.assertRaisesRegex(ValueError,"expected 6 read/NO_LINK"):
                r.analyze(receipt(q),[evidence(q)],6)

if __name__=="__main__":
    unittest.main()
