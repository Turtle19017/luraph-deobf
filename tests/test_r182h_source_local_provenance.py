import importlib.util,json,pathlib,tempfile,unittest
from unittest import mock
ROOT=pathlib.Path(__file__).resolve().parents[1]
P=ROOT/"tools"/"analyze_r182h_source_local_provenance.py"
SPEC=importlib.util.spec_from_file_location("r182h",P)
r=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(r)

def L(name,decl,use=None):
    return {"type":"AstExprLocal","name":name,"decl":decl,"location":use or ("U"+name)}

def receipt(root, *, missing=None, bad_checkpoint=False):
    args=[
        {"type":"AstExprIndexExpr","expr":L("K","DK"),"index":L("W","DW")},
        {"type":"AstExprGroup","expr":{
            "type":"AstExprCall","func":L("r","Dr"),
            "args":[
                {"type":"AstExprCall","func":{"type":"AstExprLocal","name":"v","decl":"Dv","location":"Uv"},
                 "args":[L("f","Df"),{"type":"AstExprIndexExpr","expr":L("h","Dh"),"index":L("W","DW")},L("W","DW")]},
                {"type":"AstExprConstantNumber","value":127},
            ]}}
    ]
    if missing=="h":
        args[1]["expr"]["args"][0]["args"][1]={"type":"AstExprConstantNumber","value":1}
    rows=[{"instance_index":95+i,"function_id":"F","state_id":"S","call_location":"CALL","args":args}
          for i in range(41)]
    cp={"expected":{"functions":78,"errors":64,"fallbacks":0,"requests":593 if bad_checkpoint else 594}}
    obj={"schema":"luraph-deobf.r182e-source-call-arg-recovery.v2","checkpoint":cp,"instances":rows}
    p=root/"e.json";p.write_text(json.dumps(obj),encoding="utf-8");return p

def source_root(*, duplicate_call=False, duplicate_decl=False, nested_k_write=False):
    fn={
        "type":"AstExprFunction","location":"FN",
        "args":[{"name":"W","location":"DW"}],
        "body":{"type":"AstStatBlock","location":"BODY","body":[]},
    }
    body=fn["body"]["body"]
    body.append({"type":"AstStatLocal","location":"SK","vars":[{"name":"K","location":"DK"}],
                 "values":[{"type":"AstExprGlobal","location":"GK","global":"BASEK"}]})
    body.append({"type":"AstStatLocal","location":"SF","vars":[{"name":"f","location":"Df"}],
                 "values":[{"type":"AstExprConstantNumber","location":"NF","value":7}]})
    body.append({"type":"AstStatAssign","location":"AF",
                 "vars":[{"type":"AstExprLocal","location":"UF","local":{"name":"f","location":"Df"}}],
                 "values":[{"type":"AstExprConstantNumber","location":"NF2","value":8}]})
    body.append({"type":"AstStatLocal","location":"SH","vars":[{"name":"h","location":"Dh"}],"values":[]})
    body.append({"type":"AstStatAssign","location":"AH",
                 "vars":[{"type":"AstExprLocal","location":"UH","local":{"name":"h","location":"Dh"}}],
                 "values":[{"type":"AstExprGlobal","location":"GH","global":"H"}]})
    body.append({"type":"AstStatLocalFunction","location":"SR","name":{"name":"r","location":"Dr"},
                 "func":{"type":"AstExprFunction","location":"RFN","args":[],"body":{"type":"AstStatBlock","location":"RB","body":[]}}})
    if nested_k_write:
        nested={"type":"AstExprFunction","location":"NEST","args":[],
                "body":{"type":"AstStatBlock","location":"NB","body":[{
                    "type":"AstStatAssign","location":"AKN",
                    "vars":[{"type":"AstExprLocal","location":"UKN","local":{"name":"K","location":"DK"}}],
                    "values":[{"type":"AstExprGlobal","location":"G2","global":"OTHER"}],
                }]}}
        body.append({"type":"AstStatLocal","location":"SN","vars":[{"name":"q","location":"Dq"}],"values":[nested]})
    call={"type":"AstExprCall","location":"CALL",
          "func":{"type":"AstExprGlobal","location":"GC","global":"sink"},"args":[]}
    body.append({"type":"AstStatExpr","location":"SC","expr":call})
    if duplicate_call:
        body.append({"type":"AstStatExpr","location":"SC2","expr":dict(call)})
    if duplicate_decl:
        body.append({"type":"AstStatLocal","location":"SX","vars":[{"name":"K2","location":"DK"}],
                     "values":[{"type":"AstExprConstantNumber","location":"NX","value":1}]})
    return {"type":"AstStatBlock","location":"ROOT","body":[fn]}

class R182HTests(unittest.TestCase):
    def analyze_with_root(self,q,root,**receipt_kw):
        ep=receipt(q,**receipt_kw)
        with mock.patch.object(r,"parse_source",return_value=("a"*64,root)):
            return r.analyze(ep,q/"script.txt","a"*64)

    def test_classifies_parameter_local_mutation_and_local_function(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td);out=self.analyze_with_root(q,source_root())
            rows={x["name"]:x for x in out["locals"]}
            self.assertEqual(rows["K"]["classification"],"LOCAL_SINGLE_INIT_NO_REASSIGN")
            self.assertEqual(rows["W"]["classification"],"PARAMETER")
            self.assertEqual(rows["f"]["classification"],"LOCAL_INIT_MUTATED")
            self.assertEqual(rows["h"]["classification"],"LOCAL_NO_INIT_ASSIGNED")
            self.assertEqual(rows["r"]["classification"],"LOCAL_FUNCTION")
            self.assertEqual(out["summary"]["single_static_origin_candidates"],2)

    def test_nested_closure_write_blocks_single_origin(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td);out=self.analyze_with_root(q,source_root(nested_k_write=True))
            row={x["name"]:x for x in out["locals"]}["K"]
            self.assertEqual(row["classification"],"LOCAL_INIT_MUTATED")
            self.assertEqual(row["nested_closure_write_count"],1)
            self.assertFalse(row["single_static_origin_candidate"])

    def test_duplicate_source_call_location_fails(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td);ep=receipt(q)
            with mock.patch.object(r,"parse_source",return_value=("a"*64,source_root(duplicate_call=True))):
                with self.assertRaisesRegex(ValueError,"matched 2 source calls"):
                    r.analyze(ep,q/"script.txt","a"*64)

    def test_duplicate_declaration_location_fails(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td);ep=receipt(q)
            with mock.patch.object(r,"parse_source",return_value=("a"*64,source_root(duplicate_decl=True))):
                with self.assertRaisesRegex(ValueError,"matched 2 declarations"):
                    r.analyze(ep,q/"script.txt","a"*64)

    def test_missing_required_local_fails(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td);ep=receipt(q,missing="h")
            with mock.patch.object(r,"parse_source",return_value=("a"*64,source_root())):
                with self.assertRaisesRegex(ValueError,"missing required locals"):
                    r.analyze(ep,q/"script.txt","a"*64)

    def test_checkpoint_gate(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td);ep=receipt(q,bad_checkpoint=True)
            with mock.patch.object(r,"parse_source",return_value=("a"*64,source_root())):
                with self.assertRaisesRegex(ValueError,"checkpoint"):
                    r.analyze(ep,q/"script.txt","a"*64)

    def test_static_origin_does_not_prove_runtime_value(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td);out=self.analyze_with_root(q,source_root())
            self.assertFalse(out["interpretation_gate"]["single_static_origin_candidate_proves_runtime_value"])
            self.assertFalse(out["interpretation_gate"]["source_provenance_authorizes_candidate_evaluation"])
            self.assertFalse(out["interpretation_gate"]["frame_base_bug_proved"])

if __name__=="__main__":
    unittest.main()
