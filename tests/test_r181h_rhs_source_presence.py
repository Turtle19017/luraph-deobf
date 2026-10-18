import importlib.util,json,pathlib,tempfile,unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
P=ROOT/"tools"/"analyze_r181h_rhs_source_presence.py"
SPEC=importlib.util.spec_from_file_location("r181h",P); r=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(r)

def receipt(root):
    rows=[]
    for i in range(95):
        rows.append({
            "function_id":f"F{i%7}","state_id":f"S{i%7}","right_type":"AstExprIndexExpr",
            "rhs_local_dependencies":[
                {"binding":{"identity":{"names":[{"value":"K"}]},"matches":[{"value":"LTable#369"}]}},
                {"binding":{"identity":{"names":[{"value":"W"}]},"matches":[{"value":[165,356,1008,1490,1524][i%5]}]}},
            ],
        })
    for i in range(41):
        rows.append({
            "function_id":f"C{i%3}","state_id":f"CS{i%3}","right_type":"AstExprCall",
            "rhs_schema":{"argc":2},
            "rhs_local_dependencies":[
                {"binding":{"identity":{"names":[{"value":"v"}]},"matches":[{"value":"Builtin(bit32.bxor)"}]}}
            ],
        })
    obj={
        "schema":"luraph-deobf.r181g-rhs-local-dependency-census.v1",
        "checkpoint":{"expected":{"functions":78,"errors":64,"fallbacks":0,"requests":594}},
        "instances":rows,
    }
    p=root/"g.json";p.write_text(json.dumps(obj),encoding="utf-8");return p

class R181HTests(unittest.TestCase):
    def test_requirements_derived(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td); e=q/"e";e.mkdir()
            out=r.analyze(receipt(q),[e])
            self.assertEqual(out["requirements"]["table_lookup_instances"],95)
            self.assertEqual(out["requirements"]["call_instances"],41)
            self.assertEqual(set(out["requirements"]["required_table_keys"]),{"165","356","1008","1490","1524"})

    def test_table_content_candidate_found(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td); p=q/"e.json"
            p.write_text(json.dumps({"obj":"LTable#369","h":{"165":7,"356":8}}),encoding="utf-8")
            out=r.analyze(receipt(q),[p])
            self.assertGreater(out["summary"]["table_records_with_candidate_content"],0)
            self.assertTrue(any(path.endswith(".h") for path in out["table_candidate_content_paths"]))

    def test_table_tid_candidate_found_without_repr(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td); p=q/"e.json"
            p.write_text(json.dumps({"table_id":369,"entries":[{"key":165,"value":7}]}),encoding="utf-8")
            out=r.analyze(receipt(q),[p])
            self.assertGreater(out["summary"]["table_reference_records"],0)

    def test_call_arg_like_field_requires_exact_composite(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td); p=q/"e.jsonl"
            p.write_text(json.dumps({"kind":"below_stack","register":-1,"function_id":"C0","state_id":"CS0",
                "call":{"args":[11,22]}})+"\n",encoding="utf-8")
            out=r.analyze(receipt(q),[p])
            self.assertEqual(out["summary"]["call_sites_with_arg_like_fields"],1)

    def test_wrong_function_same_state_ignored(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td); p=q/"e.jsonl"
            p.write_text(json.dumps({"kind":"below_stack","register":-1,"function_id":"OTHER","state_id":"CS0",
                "call":{"args":[11,22]}})+"\n",encoding="utf-8")
            out=r.analyze(receipt(q),[p])
            self.assertEqual(out["summary"]["call_sites_with_arg_like_fields"],0)

    def test_zero_fields_are_capture_absence_only(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td); e=q/"e";e.mkdir()
            out=r.analyze(receipt(q),[e])
            self.assertTrue(out["interpretation_gate"]["zero_candidate_fields_means_not_captured_in_scanned_evidence_only"])
            self.assertFalse(out["interpretation_gate"]["arithmetic_origin_proved"])

if __name__=="__main__":
    unittest.main()
