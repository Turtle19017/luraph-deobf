import importlib.util,json,pathlib,tempfile,unittest
from unittest import mock
ROOT=pathlib.Path(__file__).resolve().parents[1]
P=ROOT/"tools"/"analyze_r182i_static_path_resolution.py"
SPEC=importlib.util.spec_from_file_location("r182i",P)
r=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(r)

def LG(name,loc):
    return {"type":"AstExprLocal","location":"U"+name,"local":{"name":name,"location":loc}}

def builtin(lib,name,loc):
    return {"type":"AstExprIndexName","location":loc,
            "expr":{"type":"AstExprGlobal","location":loc+"G","global":lib},
            "index":name,"op":"."}

def root(*, conflict=False, wrong_decl=False, mutate_r=False):
    body=[
        {"type":"AstStatLocal","location":"SB","vars":[{"name":"B","location":"DB"}],"values":[]},
        {"type":"AstStatAssign","location":"PB124",
         "vars":[{"type":"AstExprIndexExpr","location":"TB124","expr":LG("B","DB"),
                  "index":{"type":"AstExprConstantNumber","location":"N124","value":124}}],
         "values":[builtin("bit32","rshift","BR")]},
        {"type":"AstStatLocal","location":"SR","vars":[{"name":"r","location":"Dr"}],
         "values":[{"type":"AstExprIndexExpr","location":"RB","expr":LG("B","DB"),
                    "index":{"type":"AstExprConstantNumber","location":"R124","value":124}}]},
        {"type":"AstStatLocal","location":"SK","vars":[{"name":"K","location":"DK"}],"values":[]},
        {"type":"AstStatAssign","location":"AK","vars":[LG("K","DK")],
         "values":[{"type":"AstExprTable","location":"KT","items":[
             {"kind":"item","value":{"type":"AstExprConstantNumber","location":"K1","value":4}}
         ]}]},
        {"type":"AstStatLocal","location":"SH","vars":[{"name":"h","location":"Dh"}],"values":[]},
        {"type":"AstStatAssign","location":"AH","vars":[LG("h","Dh")],
         "values":[{"type":"AstExprTable","location":"HT","items":[]}]},
    ]
    if conflict:
        body.insert(2,{"type":"AstStatAssign","location":"PB124X",
            "vars":[{"type":"AstExprIndexExpr","location":"TB124X","expr":LG("B","DB"),
                     "index":{"type":"AstExprConstantNumber","location":"N124X","value":124}}],
            "values":[builtin("bit32","lshift","BL")]})
    if wrong_decl:
        body.insert(2,{"type":"AstStatLocal","location":"SB2","vars":[{"name":"B","location":"DB2"}],"values":[]})
        body.insert(3,{"type":"AstStatAssign","location":"PB124Y",
            "vars":[{"type":"AstExprIndexExpr","location":"TB124Y","expr":LG("B","DB2"),
                     "index":{"type":"AstExprConstantNumber","location":"N124Y","value":124}}],
            "values":[builtin("bit32","lshift","BL2")]})
    if mutate_r:
        body.append({"type":"AstStatAssign","location":"AR","vars":[LG("r","Dr")],
                     "values":[builtin("bit32","lshift","BR2")]})
    return {"type":"AstStatBlock","location":"ROOT","body":body}

def receipt(q):
    obj={"schema":"luraph-deobf.r182h-source-local-provenance.v1",
         "checkpoint":{"expected":{"functions":78,"errors":64,"fallbacks":0,"requests":594}},
         "locals":[
             {"name":"K","decl":"DK","classification":"LOCAL_NO_INIT_ASSIGNED"},
             {"name":"W","decl":"DW","classification":"LOCAL_INIT_MUTATED"},
             {"name":"f","decl":"Df","classification":"LOCAL_INIT_MUTATED"},
             {"name":"h","decl":"Dh","classification":"LOCAL_NO_INIT_ASSIGNED"},
             {"name":"r","decl":"Dr","classification":"LOCAL_SINGLE_INIT_NO_REASSIGN"},
         ]}
    p=q/"h.json";p.write_text(json.dumps(obj),encoding="utf-8");return p

class R182ITests(unittest.TestCase):
    def analyze_root(self,q,rt):
        hp=receipt(q)
        with mock.patch.object(r,"parse_source",return_value=("a"*64,rt)):
            return r.analyze(hp,q/"script.txt","a"*64)

    def test_resolves_r_through_exact_static_table_path(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td);out=self.analyze_root(q,root())
            rr={x["name"]:x for x in out["roots"]}["r"]["resolution"]
            self.assertEqual(rr["status"],"VALUE")
            self.assertEqual(rr["value"]["kind"],"builtin")
            self.assertEqual(rr["value"]["name"],"bit32.rshift")
            self.assertEqual(rr["index_path"],[124])

    def test_single_assignment_tables_are_static_candidates(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td);out=self.analyze_root(q,root())
            rows={x["name"]:x for x in out["roots"]}
            self.assertEqual(rows["K"]["resolution_class"],"STATIC_VALUE_CANDIDATE")
            self.assertEqual(rows["K"]["resolution"]["value"]["kind"],"table")
            self.assertEqual(rows["h"]["resolution_class"],"STATIC_VALUE_CANDIDATE")

    def test_conflicting_exact_path_writes_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td);out=self.analyze_root(q,root(conflict=True))
            rr={x["name"]:x for x in out["roots"]}["r"]["resolution"]
            self.assertEqual(rr["status"],"UNRESOLVED")
            self.assertEqual(rr["reason"],"CONFLICTING_STATIC_PATH_VALUES")
            self.assertEqual(len(rr["values"]),2)

    def test_wrong_declaration_same_name_does_not_contaminate_path(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td);out=self.analyze_root(q,root(wrong_decl=True))
            rr={x["name"]:x for x in out["roots"]}["r"]["resolution"]
            self.assertEqual(rr["status"],"VALUE")
            self.assertEqual(rr["value"]["name"],"bit32.rshift")

    def test_direct_reassignment_blocks_r_static_origin(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td);out=self.analyze_root(q,root(mutate_r=True))
            rr={x["name"]:x for x in out["roots"]}["r"]["resolution"]
            self.assertEqual(rr["status"],"UNRESOLVED")
            self.assertIn("MUTABLE_OR_COMPLEX",rr["reason"])

    def test_static_candidate_is_not_runtime_proof(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td);out=self.analyze_root(q,root())
            self.assertFalse(out["interpretation_gate"]["static_value_candidate_is_runtime_value"])
            self.assertFalse(out["interpretation_gate"]["candidate_builtin_authorizes_r182f_replay"])
            self.assertFalse(out["interpretation_gate"]["frame_base_bug_proved"])

if __name__=="__main__":
    unittest.main()
