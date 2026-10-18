import hashlib,importlib.util,json,pathlib,tempfile,unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
P=ROOT/"tools"/"analyze_r182f_bxor_candidates.py"
SPEC=importlib.util.spec_from_file_location("r182f",P)
r=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(r)

def make_protos(root, *, h_late=False):
    arr369=[None]*356;arr369[355]=4
    arr500=[None]*356;arr500[355]=3
    tables={
        "369":{"arr":arr369,"kv":[]},
        "500":{"arr":arr500,"kv":[],"late":[356] if h_late else []},
    }
    p=root/"x.protos.json";p.write_text(json.dumps({"tables":tables}),encoding="utf-8")
    sha=hashlib.sha256(p.read_bytes()).hexdigest()
    return p,sha

def arg_asts():
    arg0={"type":"AstExprIndexExpr","location":"A0",
          "expr":{"type":"AstExprLocal","location":"Kuse","name":"K","decl":"Kdecl"},
          "index":{"type":"AstExprLocal","location":"Wuse0","name":"W","decl":"Wdecl"}}
    inner={"type":"AstExprCall","location":"INNER",
           "func":{"type":"AstExprLocal","location":"vuse","name":"v","decl":"vdecl"},
           "argc":3,
           "args":[
               {"type":"AstExprLocal","location":"fuse","name":"f","decl":"fdecl"},
               {"type":"AstExprIndexExpr","location":"HI",
                "expr":{"type":"AstExprLocal","location":"huse","name":"h","decl":"hdecl"},
                "index":{"type":"AstExprLocal","location":"Wuse1","name":"W","decl":"Wdecl"}},
               {"type":"AstExprLocal","location":"Wuse2","name":"W","decl":"Wdecl"},
           ]}
    arg1={"type":"AstExprGroup","location":"G",
          "expr":{"type":"AstExprCall","location":"OUTER",
                  "func":{"type":"AstExprLocal","location":"ruse","name":"r","decl":"rdecl"},
                  "argc":2,
                  "args":[inner,{"type":"AstExprConstantNumber","location":"N","value":127}]}}
    return [arg0,arg1]

def receipts(root, *, h_late=False, r_value="Builtin(bit32.rshift)", missing_f=False, bad_sha=False):
    protos,sha=make_protos(root,h_late=h_late)
    cp={"expected":{"functions":78,"errors":64,"fallbacks":0,"requests":594}}
    crows=[];erows=[]
    for i in range(41):
        idx=95+i;fid=f"F{i%7}";sid=f"S{i%7}"
        crows.append({"instance_index":idx,"function_id":fid,"state_id":sid,
                      "right_type":"AstExprCall","left_snapshot":3,
                      "classification":"CALL_RHS_UNRESOLVED"})
        entries=[
            {"name":"K","value":"LTable#369"},
            {"name":"W","value":"356"},
            {"name":"h","value":"LTable#500"},
            {"name":"v","value":"Builtin(bit32.bxor)"},
            {"name":"r","value":r_value},
        ]
        if not missing_f:entries.append({"name":"f","value":"7"})
        erows.append({"instance_index":idx,"function_id":fid,"state_id":sid,
                      "call_location":"CALL","argc":2,
                      "arg_shapes":["AstExprIndexExpr","AstExprGroup"],
                      "args":arg_asts(),"local_snapshot_entries":entries})
    c={"schema":"luraph-deobf.r182c-base-sub-consistency.v1","checkpoint":cp,
       "selected_base_snapshot":{"path":str(protos),"sha256":("0"*64 if bad_sha else sha),
                                 "table_id":369,"base_values":{"356":4}},
       "instances":crows}
    e={"schema":"luraph-deobf.r182e-source-call-arg-recovery.v2","checkpoint":cp,
       "instances":erows}
    cp1=root/"c.json";ep=root/"e.json"
    cp1.write_text(json.dumps(c),encoding="utf-8");ep.write_text(json.dumps(e),encoding="utf-8")
    return cp1,ep

class R182FTests(unittest.TestCase):
    def test_full_candidate_neg1(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td);c,e=receipts(q)
            out=r.analyze(c,e)
            self.assertEqual(out["summary"]["full_candidate_neg1"],41)
            self.assertEqual(out["summary"]["argument_unresolved"],0)
            self.assertEqual(out["candidate_bxor_values"],{"4":41})
            self.assertEqual(out["candidate_sub_values"],{"-1":41})

    def test_integer_like_snapshot_W_and_f_are_numeric_context_only(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td);c,e=receipts(q)
            out=r.analyze(c,e)
            first=out["instances"][0]
            self.assertEqual(first["arg0"]["value"],4)
            self.assertEqual(first["candidate_bxor"],4)

    def test_late_h_key_stays_unresolved(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td);c,e=receipts(q,h_late=True)
            out=r.analyze(c,e)
            self.assertEqual(out["summary"]["argument_unresolved"],41)
            self.assertTrue(any("CALL_ARG_UNRESOLVED:bit32.bxor" in k for k in out["unresolved_reasons"]))

    def test_missing_snapshot_local_stays_unresolved(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td);c,e=receipts(q,missing_f=True)
            out=r.analyze(c,e)
            self.assertEqual(out["summary"]["argument_unresolved"],41)
            self.assertTrue(any("CALL_ARG_UNRESOLVED:bit32.bxor" in k for k in out["unresolved_reasons"]))

    def test_non_builtin_r_stays_unresolved(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td);c,e=receipts(q,r_value="LuaFunc#synthetic")
            out=r.analyze(c,e)
            self.assertEqual(out["summary"]["argument_unresolved"],41)
            self.assertTrue(any("CALL_FUNC_NOT_BUILTIN" in k or "CALL_ARG_UNRESOLVED" in k
                                for k in out["unresolved_reasons"]))

    def test_selected_protos_sha_is_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td);c,e=receipts(q,bad_sha=True)
            with self.assertRaisesRegex(ValueError,"SHA mismatch"):
                r.analyze(c,e)

    def test_gate_does_not_promote_candidate_to_runtime_proof(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td);c,e=receipts(q)
            out=r.analyze(c,e)
            self.assertFalse(out["interpretation_gate"]["candidate_bit32_evaluation_is_runtime_proof"])
            self.assertFalse(out["interpretation_gate"]["full_candidate_neg1_is_arithmetic_origin_proof"])
            self.assertFalse(out["interpretation_gate"]["frame_base_bug_proved"])

if __name__=="__main__":
    unittest.main()
