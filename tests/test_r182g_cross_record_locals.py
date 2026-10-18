import importlib.util,json,pathlib,tempfile,unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
P=ROOT/"tools"/"analyze_r182g_cross_record_locals.py"
SPEC=importlib.util.spec_from_file_location("r182g",P)
r=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(r)

def call_args():
    def L(name,decl):
        return {"type":"AstExprLocal","name":name,"decl":decl,"location":"use-"+name}
    return [
        {"type":"AstExprIndexExpr","expr":L("K","DK"),"index":L("W","DW")},
        {"type":"AstExprGroup","expr":{
            "type":"AstExprCall","func":L("r","Dr"),
            "args":[
                {"type":"AstExprCall","func":L("v","Dv"),
                 "args":[L("f","Df"),{"type":"AstExprIndexExpr","expr":L("h","Dh"),"index":L("W","DW")},L("W","DW")]},
                {"type":"AstExprConstantNumber","value":127},
            ],
        }},
    ]

def receipt(root, *, conflict_decl=False):
    rows=[]
    for i in range(41):
        args=call_args()
        if conflict_decl and i==40:
            args[0]["expr"]["decl"]="DK_OTHER"
        rows.append({"instance_index":95+i,"function_id":"F","state_id":"S","args":args})
    obj={"schema":"luraph-deobf.r182e-source-call-arg-recovery.v2",
         "checkpoint":{"expected":{"functions":78,"errors":64,"fallbacks":0,"requests":594}},
         "instances":rows}
    p=root/"e.json";p.write_text(json.dumps(obj),encoding="utf-8");return p

def evidence(root):
    rows=[
        # K: explicit entry carries exact declaration location.
        {"function_id":"F","state_id":"S",
         "local_values":[{"name":"K","value":"LTable#369","decl_location":"DK"}]},
        # W: name/value only, but same record has exact declaration read event.
        {"function_id":"F","state_id":"S",
         "local_values":[{"decl":{"name":"W","value":"356"}}],
         "local_events":[["read","DW","UW"]]},
        # f: unique by name only.
        {"function_id":"F","state_id":"S",
         "carried_locals":[{"decl":{"name":"f","value":"7"}}]},
        # h: conflicting name-only values.
        {"function_id":"F","state_id":"S",
         "local_values":[{"decl":{"name":"h","value":"LTable#500"}}]},
        {"function_id":"F","state_id":"S",
         "local_values":[{"decl":{"name":"h","value":"LTable#501"}}]},
        # v: pair/list entry and exact event, demonstrating pair adapter.
        {"function_id":"F","state_id":"S",
         "carried_locals":[["v","Builtin(bit32.bxor)"]],
         "local_events":[["read","Dv","Uv"]]},
        # Same state_id, wrong function: must never contaminate exact composite identity.
        {"function_id":"OTHER","state_id":"S",
         "local_values":[{"name":"r","value":"Builtin(bit32.rshift)","decl_location":"Dr"}]},
    ]
    p=root/"ev.jsonl";p.write_text("\n".join(json.dumps(x) for x in rows)+"\n",encoding="utf-8");return p

class R182GTests(unittest.TestCase):
    def test_cross_record_classification_ladder(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td)
            out=r.analyze(receipt(q),[evidence(q)])
            st=out["states"][0]["locals"]
            self.assertEqual(st["K"]["classification"],"EXACT_DECL_UNIQUE")
            self.assertEqual(st["K"]["chosen_value"],"LTable#369")
            self.assertEqual(st["W"]["classification"],"EVENT_PLUS_NAME_UNIQUE")
            self.assertEqual(st["W"]["chosen_value"],"356")
            self.assertEqual(st["f"]["classification"],"NAME_ONLY_UNIQUE")
            self.assertEqual(st["h"]["classification"],"NAME_ONLY_CONFLICT")
            self.assertEqual(st["r"]["classification"],"NO_VALUE")
            self.assertEqual(st["v"]["classification"],"EVENT_PLUS_NAME_UNIQUE")

    def test_wrong_function_same_state_is_ignored(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td)
            out=r.analyze(receipt(q),[evidence(q)])
            st=out["states"][0]["locals"]
            self.assertEqual(st["r"]["classification"],"NO_VALUE")

    def test_same_composite_source_decl_conflict_fails(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td)
            with self.assertRaisesRegex(ValueError,"conflicting source decl"):
                r.analyze(receipt(q,conflict_decl=True),[evidence(q)])

    def test_exact_decl_conflict_is_not_chosen(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td); e=evidence(q)
            with e.open("a",encoding="utf-8") as f:
                f.write(json.dumps({"function_id":"F","state_id":"S",
                    "local_values":[{"name":"K","value":"LTable#777","decl_location":"DK"}]})+"\n")
            out=r.analyze(receipt(q),[e])
            row=out["states"][0]["locals"]["K"]
            self.assertEqual(row["classification"],"EXACT_DECL_CONFLICT")
            self.assertIsNone(row["chosen_value"])

    def test_event_plus_name_conflict_is_not_chosen(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td); e=evidence(q)
            with e.open("a",encoding="utf-8") as f:
                f.write(json.dumps({"function_id":"F","state_id":"S",
                    "local_values":[{"decl":{"name":"W","value":"999"}}],
                    "local_events":[["read","DW","UW2"]]})+"\n")
            out=r.analyze(receipt(q),[e])
            row=out["states"][0]["locals"]["W"]
            self.assertEqual(row["classification"],"EVENT_PLUS_NAME_CONFLICT")
            self.assertIsNone(row["chosen_value"])

    def test_name_only_unique_is_not_decl_proof(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td)
            out=r.analyze(receipt(q),[evidence(q)])
            self.assertTrue(out["interpretation_gate"]["name_only_unique_is_decl_proof"] is False)
            self.assertFalse(out["interpretation_gate"]["candidate_evaluation_authorized"])

    def test_checkpoint_gate(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td); p=receipt(q)
            obj=json.loads(p.read_text());obj["checkpoint"]["expected"]["requests"]=593
            p.write_text(json.dumps(obj))
            with self.assertRaisesRegex(ValueError,"checkpoint"):
                r.analyze(p,[evidence(q)])

if __name__=="__main__":
    unittest.main()
