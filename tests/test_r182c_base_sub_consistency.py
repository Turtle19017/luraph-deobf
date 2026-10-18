import importlib.util,json,pathlib,tempfile,unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
P=ROOT/"tools"/"analyze_r182c_base_sub_consistency.py"
SPEC=importlib.util.spec_from_file_location("r182c",P)
r=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(r)

def receipts(root, *, mismatch=False, late=False, duplicate_sha=False, string_w=True):
    fi=[]; gi=[]
    for i in range(136):
        is_index=i<95
        fid=f"F{i%7}"; sid=f"S{i%7}"
        left=3
        fi.append({
            "function_id":fid,"state_id":sid,
            "right_type":"AstExprIndexExpr" if is_index else "AstExprCall",
            "left_binding":{"classification":"STRUCTURED_MATCH_VALUE_OTHER",
                            "matched_local_entries":[{"name":"x","value":left}]}
        })
        if is_index:
            w="356" if string_w else 356
            deps=[
                {"binding":{"identity":{"names":[{"value":"K"}]},"matches":[{"value":"LTable#369"}]}},
                {"binding":{"identity":{"names":[{"value":"W"}]},"matches":[{"value":w}]}}
            ]
            rt="AstExprIndexExpr"
        else:
            deps=[{"binding":{"identity":{"names":[{"value":"v"}]},"matches":[{"value":"Builtin(bit32.bxor)"}]}}]
            rt="AstExprCall"
        gi.append({"instance_index":i,"function_id":("OTHER" if mismatch and i==0 else fid),
                   "state_id":sid,"right_type":rt,"rhs_local_dependencies":deps})

    cp={"expected":{"functions":78,"errors":64,"fallbacks":0,"requests":594}}
    fobj={"schema":"luraph-deobf.r181f-local-identity-rhs-census.v1","checkpoint":cp,"instances":fi}
    gobj={"schema":"luraph-deobf.r181g-rhs-local-dependency-census.v1","checkpoint":cp,"instances":gi}
    bfiles=[{
        "path":"good.protos.json","sha256":"7792d88311111111111111111111111111111111111111111111111185160aa6",
        "status":"TABLE_FOUND","table_id":369,
        "requested_keys":[{"key":356,"status":"FOUND_SCALAR","late":late,"value":{"value":4}}]
    }]
    if duplicate_sha:
        bfiles.append({
            "path":"other.protos.json","sha256":"7792d88322222222222222222222222222222222222222222222222222222222",
            "status":"TABLE_FOUND","table_id":369,
            "requested_keys":[{"key":356,"status":"FOUND_SCALAR","late":False,"value":{"value":4}}]
        })
    bobj={"schema":"luraph-deobf.r182b-base-table-resolution.v1","files":bfiles}
    paths=[]
    for name,obj in (("f.json",fobj),("g.json",gobj),("b.json",bobj)):
        p=root/name;p.write_text(json.dumps(obj),encoding="utf-8");paths.append(p)
    return paths

class R182CTests(unittest.TestCase):
    def test_all_index_instances_base_consistent(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td); f,g,b=receipts(q)
            out=r.analyze(f,g,b,"7792d883")
            self.assertEqual(out["summary"]["base_consistent_neg1"],95)
            self.assertEqual(out["summary"]["base_inconsistent_neg1"],0)
            self.assertEqual(out["summary"]["call_rhs_unresolved"],41)

    def test_string_w_is_accepted(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td); f,g,b=receipts(q,string_w=True)
            out=r.analyze(f,g,b,"7792d883")
            self.assertEqual(out["instances"][0]["w"],356)

    def test_exact_instance_identity_mismatch_fails(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td); f,g,b=receipts(q,mismatch=True)
            with self.assertRaisesRegex(ValueError,"join mismatch"):
                r.analyze(f,g,b,"7792d883")

    def test_ambiguous_sha_prefix_fails(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td); f,g,b=receipts(q,duplicate_sha=True)
            with self.assertRaisesRegex(ValueError,"matched 2"):
                r.analyze(f,g,b,"7792d883")

    def test_late_base_key_fails(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td); f,g,b=receipts(q,late=True)
            with self.assertRaisesRegex(ValueError,"late"):
                r.analyze(f,g,b,"7792d883")

    def test_base_match_is_not_failure_time_proof(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td); f,g,b=receipts(q)
            out=r.analyze(f,g,b,"7792d883")
            self.assertFalse(out["interpretation_gate"]["base_consistent_is_failure_time_proof"])
            self.assertFalse(out["interpretation_gate"]["arithmetic_origin_proved"])

if __name__=="__main__":
    unittest.main()
