import importlib.util,json,pathlib,tempfile,unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
P=ROOT/"tools"/"analyze_r183_exact_underflow_capture.py"
SPEC=importlib.util.spec_from_file_location("r183a",P)
r=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(r)

def receipt(q,null_mp=False):
    sites=[]
    for i in range(7):
        sites.append({"function_id":f"F{i}","state_id":f"S{i}",
                      "mode":None if null_mp else 93,
                      "pc":None if null_mp else 100+i,
                      "operation":"read","sub_instances":i+1})
    obj={"schema":"luraph-deobf.r181f-local-identity-rhs-census.v1",
         "checkpoint":{"expected":{"functions":78,"errors":64,"fallbacks":0,"requests":594}},
         "sites":sites}
    p=q/"f.json";p.write_text(json.dumps(obj),encoding="utf-8");return p

def baseline(q):
    errs=[f'error("devirt: read below the stack VM\'s frame (register -1) (at 93:{100+i})")' for i in range(7)]
    obj={"stats":{"functions":78,"errors":64,"fallbacks":0},"requests":594,
         "source_sha256":r.SOURCE_SHA,"output_sha256":r.OUTPUT_SHA,"errors":errs}
    p=q/"summary.json";p.write_text(json.dumps(obj),encoding="utf-8");return p

def frame(pc,left=3,right=4,result=-1,right_type="AstExprIndexExpr",mode=93):
    return {"kind":"below_stack","register":-1,"stack_base":1,"mode":mode,"pc":pc,
      "proto_tid":369,"vm_tag":"TAG",
      "index_ast":{"type":"AstExprBinary","op":"Sub","location":"SUB",
        "left":{"type":"AstExprLocal"},"right":{"type":right_type}},
      "index_ast_location":"SUB",
      "index_eval":{"location":"SUB","op":"Sub","left":{"type":"int","value":left},
        "right":{"type":"int","value":right},"result":{"type":"int","value":result}}}

def log(q,rs):
    p=q/"run.log";p.write_text("\n".join("[FRAMEFAIL] "+json.dumps(x) for x in rs)+"\n",encoding="utf-8");return p

class R183AV2Tests(unittest.TestCase):
    def test_complete_mode_pc_has_both_gates(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td);rs=[frame(100+i) for i in range(7)]
            out=r.analyze(receipt(q),baseline(q),[log(q,rs)])
            self.assertTrue(out["interpretation_gate"]["exact_accepted_location_gate_for_diagnostic_experiment"])
            self.assertTrue(out["interpretation_gate"]["canonical_composite_identity_gate"])

    def test_null_r181f_mode_pc_keeps_location_gate_but_not_canonical_gate(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td);rs=[frame(100+i) for i in range(7)]
            out=r.analyze(receipt(q,True),baseline(q),[log(q,rs)])
            self.assertTrue(out["interpretation_gate"]["exact_accepted_location_gate_for_diagnostic_experiment"])
            self.assertFalse(out["interpretation_gate"]["canonical_composite_identity_gate"])
            self.assertFalse(out["interpretation_gate"]["semantic_change_authorized"])

    def test_missing_location_closes_diagnostic_gate(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td);rs=[frame(100+i) for i in range(6)]
            out=r.analyze(receipt(q,True),baseline(q),[log(q,rs)])
            self.assertFalse(out["interpretation_gate"]["exact_accepted_location_gate_for_diagnostic_experiment"])

    def test_extra_neg1_location_closes_diagnostic_gate(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td);rs=[frame(100+i) for i in range(7)]+[frame(999)]
            out=r.analyze(receipt(q,True),baseline(q),[log(q,rs)])
            self.assertEqual(out["summary"]["extra_read_neg1_framefails"],1)
            self.assertFalse(out["interpretation_gate"]["exact_accepted_location_gate_for_diagnostic_experiment"])

    def test_nonnumeric_closes_gate(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td);rs=[frame(100+i) for i in range(7)]
            rs[2]["index_eval"]["right"]={"type":"Reg","repr":"r7"}
            out=r.analyze(receipt(q,True),baseline(q),[log(q,rs)])
            self.assertFalse(out["interpretation_gate"]["exact_accepted_location_gate_for_diagnostic_experiment"])

    def test_arithmetic_mismatch_closes_gate(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td);rs=[frame(100+i) for i in range(7)]
            rs[0]=frame(100,result=-2)
            out=r.analyze(receipt(q,True),baseline(q),[log(q,rs)])
            self.assertIn("ARITHMETIC_MISMATCH",out["summary"]["classification_counts"])
            self.assertFalse(out["interpretation_gate"]["exact_accepted_location_gate_for_diagnostic_experiment"])

    def test_duplicate_framefail_is_deduped(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td);rs=[frame(100+i) for i in range(7)];rs.append(dict(rs[0]))
            out=r.analyze(receipt(q,True),baseline(q),[log(q,rs)])
            self.assertEqual(out["summary"]["unique_matched_records"],7)

    def test_baseline_hash_is_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td);bp=baseline(q);o=json.loads(bp.read_text());o["output_sha256"]="0"*64;bp.write_text(json.dumps(o))
            with self.assertRaisesRegex(ValueError,"output SHA"):
                r.analyze(receipt(q,True),bp,[log(q,[frame(100+i) for i in range(7)])])

if __name__=="__main__": unittest.main()
