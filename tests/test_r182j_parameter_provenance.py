import importlib.util,json,pathlib,tempfile,unittest
from unittest import mock
ROOT=pathlib.Path(__file__).resolve().parents[1]
P=ROOT/"tools"/"analyze_r182j_parameter_provenance.py"
SPEC=importlib.util.spec_from_file_location("r182j",P)
r=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(r)

def L(name,decl,loc=None):
    return {"type":"AstExprLocal","location":loc or ("U"+name),"local":{"name":name,"location":decl}}

def fn(args,body,loc):
    return {"type":"AstExprFunction","location":loc,
            "args":[{"name":n,"location":d} for n,d in args],
            "body":{"type":"AstStatBlock","location":loc+"B","body":body}}

def receipt(q):
    obj={
        "schema":"luraph-deobf.r182i-static-path-resolution.v1",
        "checkpoint":{"expected":{"functions":78,"errors":64,"fallbacks":0,"requests":594}},
        "roots":[
            {"name":"r","resolution":{"status":"UNRESOLVED","reason":"INDEX_BASE_UNRESOLVED",
                "base":{"status":"UNRESOLVED","reason":"PARAMETER","decl":"DB","decl_name":"B"}}},
            {"name":"K","resolution":{"status":"UNRESOLVED","reason":"INDEX_BASE_UNRESOLVED",
                "base":{"status":"UNRESOLVED","reason":"PARAMETER","decl":"Dc","decl_name":"c"}}},
            {"name":"h","resolution":{"status":"UNRESOLVED","reason":"INDEX_BASE_UNRESOLVED",
                "base":{"status":"UNRESOLVED","reason":"PARAMETER","decl":"Dc","decl_name":"c"}}},
        ]
    }
    p=q/"i.json";p.write_text(json.dumps(obj),encoding="utf-8");return p

def source_root(*,mutate_binding=False,missing_c_arg=False,alias=False,same_name_wrong_decl=False):
    target=fn([("B","DB"),("c","Dc")],[], "TARGET")
    body=[
        {"type":"AstStatLocal","location":"SMAKE",
         "vars":[{"name":"maker","location":"Dmake"}],
         "values":[target]},
    ]
    callee_decl="Dmake"
    if alias:
        body.append({"type":"AstStatLocal","location":"SALIAS",
                     "vars":[{"name":"alias","location":"Dalias"}],
                     "values":[L("maker","Dmake","Umakealias")]})
        callee_decl="Dalias"
    if mutate_binding:
        other=fn([("x","Dx")],[],"OTHERFN")
        body.append({"type":"AstStatAssign","location":"MUT",
                     "vars":[L("maker","Dmake","Umut")],"values":[other]})
    if same_name_wrong_decl:
        body.append({"type":"AstStatLocal","location":"SWRONG",
                     "vars":[{"name":"maker","location":"Dwrong"}],
                     "values":[fn([("z","Dz")],[],"WRONGFN")]})
        body.append({"type":"AstStatExpr","location":"CWRONGST",
                     "expr":{"type":"AstExprCall","location":"CWRONG",
                             "func":L("maker","Dwrong","Uwcall"),
                             "args":[{"type":"AstExprConstantNumber","location":"NW","value":999}]}})
    args=[
        {"type":"AstExprConstantNumber","location":"N1","value":11},
    ]
    if not missing_c_arg:
        args.append({"type":"AstExprConstantNumber","location":"N2","value":22})
    body.append({"type":"AstStatExpr","location":"CALLST",
                 "expr":{"type":"AstExprCall","location":"CALL",
                         "func":L("alias" if alias else "maker",callee_decl,"UCALL"),
                         "args":args}})
    return {"type":"AstStatBlock","location":"ROOT","body":body}

class R182JTests(unittest.TestCase):
    def run_with_root(self,q,root):
        ip=receipt(q)
        with mock.patch.object(r,"parse_source",return_value=("a"*64,root)):
            return r.analyze(ip,q/"script.txt","a"*64)

    def test_direct_static_calls_bind_parameter_arguments(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td);out=self.run_with_root(q,source_root())
            rows={x["name"]:x for x in out["parameters"]}
            self.assertEqual(rows["B"]["classification"],"DIRECT_STATIC_CALLS")
            self.assertEqual(rows["c"]["classification"],"DIRECT_STATIC_CALLS")
            self.assertEqual(rows["B"]["param_index"],0)
            self.assertEqual(rows["c"]["param_index"],1)
            self.assertEqual(rows["B"]["call_sites"][0]["argument"]["static_value_candidate"]["value"],11)
            self.assertEqual(rows["c"]["call_sites"][0]["argument"]["static_value_candidate"]["value"],22)

    def test_static_local_alias_to_function_is_followed(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td);out=self.run_with_root(q,source_root(alias=True))
            rows={x["name"]:x for x in out["parameters"]}
            self.assertEqual(rows["B"]["call_site_count"],1)
            self.assertEqual(rows["c"]["call_site_count"],1)

    def test_alias_resolution_surfaces_terminal_function_identity(self):
        rt=source_root(alias=True)
        idx=r.SourceIndex(rt)
        resolved=idx.static_local_origin("Dalias")
        self.assertEqual(resolved["status"],"FUNCTION")
        self.assertEqual(resolved["function_location"],"TARGET")
        self.assertEqual(resolved["next"]["function_location"],"TARGET")

    def test_reassigned_callee_binding_is_not_trusted(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td);out=self.run_with_root(q,source_root(mutate_binding=True))
            rows={x["name"]:x for x in out["parameters"]}
            self.assertEqual(rows["B"]["classification"],"NO_DIRECT_STATIC_CALLS")
            self.assertEqual(rows["c"]["classification"],"NO_DIRECT_STATIC_CALLS")

    def test_same_name_wrong_decl_does_not_contaminate(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td);out=self.run_with_root(q,source_root(same_name_wrong_decl=True))
            rows={x["name"]:x for x in out["parameters"]}
            self.assertEqual(rows["B"]["call_site_count"],1)
            self.assertEqual(rows["B"]["call_sites"][0]["call_location"],"CALL")

    def test_missing_parameter_argument_is_fail_closed_class(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td);out=self.run_with_root(q,source_root(missing_c_arg=True))
            rows={x["name"]:x for x in out["parameters"]}
            self.assertEqual(rows["B"]["classification"],"DIRECT_STATIC_CALLS")
            self.assertEqual(rows["c"]["classification"],"CALLS_WITH_MISSING_ARGUMENT")
            self.assertEqual(rows["c"]["call_sites"][0]["argument"]["status"],"MISSING_ARGUMENT")

    def test_parameter_roots_are_deduplicated_by_decl(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td);out=self.run_with_root(q,source_root())
            self.assertEqual(out["summary"]["parameters"],2)
            rows={x["name"]:x for x in out["parameters"]}
            self.assertEqual(rows["c"]["roots"],["K","h"])
            self.assertEqual(rows["B"]["roots"],["r"])

    def test_census_does_not_claim_dynamic_callgraph_or_runtime_values(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td);out=self.run_with_root(q,source_root())
            gate=out["interpretation_gate"]
            self.assertFalse(gate["direct_static_call_census_is_complete_dynamic_callgraph"])
            self.assertFalse(gate["argument_ast_is_runtime_parameter_value"])
            self.assertFalse(gate["parameter_recursion_authorized"])
            self.assertFalse(gate["frame_base_bug_proved"])

if __name__=="__main__":
    unittest.main()
