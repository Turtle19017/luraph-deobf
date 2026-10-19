import importlib.util,json,pathlib,tempfile,unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
P=ROOT/"tools"/"analyze_r183_exact_underflow_capture.py"
SPEC=importlib.util.spec_from_file_location("r183a",P)
r=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(r)

def receipt(q,collision=False):
    sites=[]
    for i in range(7):
        sites.append({"function_id":f"F{i}","state_id":f"S{i}",
                      "mode":1 if collision and i in (0,1) else i+10,
                      "pc":100 if collision and i in (0,1) else 100+i,
                      "operation":"read","sub_instances":i+1})
    obj={"schema":"luraph-deobf.r181f-local-identity-rhs-census.v1",
         "checkpoint":{"expected":{"functions":78,"errors":64,"fallbacks":0,"requests":594}},
         "sites":sites}
    p=q/"f.json";p.write_text(json.dumps(obj),encoding="utf-8");return p

def frame(mode,pc,left,right,result=-1,right_type="AstExprIndexExpr",**extra):
    rec={"kind":"below_stack","register":-1,"stack_base":1,
         "mode":mode,"pc":pc,"proto_tid":369,"vm_tag":"TAG",
         "index_ast":{"type":"AstExprBinary","op":"Sub","location":"SUB",
                      "left":{"type":"AstExprLocal"},
                      "right":{"type":right_type}},
         "index_ast_location":"SUB",
         "index_eval":{"location":"SUB","op":"Sub",
                       "left":{"type":"int","value":left},
                       "right":{"type":"int","value":right},
                       "result":{"type":"int","value":result}}}
    rec.update(extra);return rec

def write_log(q,records):
    p=q/"run.log"
    p.write_text("\n".join("[FRAMEFAIL] "+json.dumps(x) for x in records)+"\n",encoding="utf-8")
    return p

class R183ATests(unittest.TestCase):
    def test_all_seven_exact_neg1_opens_gate(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td);f=receipt(q)
            rs=[frame(10+i,100+i,3+i,4+i,right_type="AstExprCall" if i<2 else "AstExprIndexExpr") for i in range(7)]
            out=r.analyze(f,[write_log(q,rs)])
            self.assertEqual(out["summary"]["sites_with_matched_framefail"],7)
            self.assertEqual(out["summary"]["sites_all_exact_sub_neg1"],7)
            self.assertTrue(out["interpretation_gate"]["all_seven_sites_have_exact_failure_time_sub_neg1"])
            self.assertEqual(out["summary"]["right_ast_type_counts"]["AstExprCall"],2)
            self.assertEqual(out["summary"]["right_ast_type_counts"]["AstExprIndexExpr"],5)

    def test_missing_site_keeps_gate_closed(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td);f=receipt(q)
            rs=[frame(10+i,100+i,3,4) for i in range(6)]
            out=r.analyze(f,[write_log(q,rs)])
            self.assertEqual(out["summary"]["sites_with_matched_framefail"],6)
            self.assertFalse(out["interpretation_gate"]["all_seven_sites_have_exact_failure_time_sub_neg1"])

    def test_nonnumeric_exact_eval_is_nonexact(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td);f=receipt(q)
            rs=[frame(10+i,100+i,3,4) for i in range(7)]
            rs[3]["index_eval"]["right"]={"type":"Reg","repr":"r7"}
            out=r.analyze(f,[write_log(q,rs)])
            self.assertEqual(out["summary"]["sites_with_nonexact_records"],1)
            self.assertFalse(out["interpretation_gate"]["all_seven_sites_have_exact_failure_time_sub_neg1"])

    def test_duplicate_framefail_is_deduped(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td);f=receipt(q)
            rs=[frame(10+i,100+i,3,4) for i in range(7)]
            rs.append(dict(rs[0]))
            out=r.analyze(f,[write_log(q,rs)])
            self.assertEqual(out["summary"]["unique_matched_records"],7)

    def test_unrelated_neg1_framefail_does_not_join(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td);f=receipt(q)
            rs=[frame(10+i,100+i,3,4) for i in range(7)]
            rs.append(frame(999,999,3,4))
            out=r.analyze(f,[write_log(q,rs)])
            self.assertEqual(out["summary"]["unmatched_neg1_framefails"],1)
            self.assertTrue(out["interpretation_gate"]["all_seven_sites_have_exact_failure_time_sub_neg1"])

    def test_arithmetic_mismatch_closes_gate(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td);f=receipt(q)
            rs=[frame(10+i,100+i,3,4) for i in range(7)]
            rs[0]=frame(10,100,3,4,result=-2)
            out=r.analyze(f,[write_log(q,rs)])
            self.assertIn("ARITHMETIC_MISMATCH",out["summary"]["classification_counts"])
            self.assertFalse(out["interpretation_gate"]["all_seven_sites_have_exact_failure_time_sub_neg1"])

    def test_nonunique_mode_pc_in_receipt_fails(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td);f=receipt(q,collision=True)
            with self.assertRaisesRegex(ValueError,"mode/pc"):
                r.analyze(f,[write_log(q,[])])

if __name__=="__main__":
    unittest.main()
