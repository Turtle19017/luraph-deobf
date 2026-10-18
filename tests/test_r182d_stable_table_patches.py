import importlib.util,json,pathlib,tempfile,unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
P=ROOT/"tools"/"analyze_r182d_stable_table_patches.py"
SPEC=importlib.util.spec_from_file_location("r182d",P)
r=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(r)

def setup_case(root, *, patch_text=None):
    protos=root/"x.protos.json"
    pobj={
        "tables":{"369":{"arr":[None]*400,"kv":[]}},
        "protos":{"p":{"__seq":1,"K":{"t":369}}},
        "overrides":[],
    }
    protos.write_text(json.dumps(pobj),encoding="utf-8")
    receipt=root/"r182b.json"
    robj={"schema":"luraph-deobf.r182b-base-table-resolution.v1","files":[{
        "path":str(protos),"sha256":"7792d883"+"1"*56,
        "status":"TABLE_FOUND","table_id":369,"requested_keys":[]
    }]}
    receipt.write_text(json.dumps(robj),encoding="utf-8")
    evidence=root/"e.log"
    evidence.write_text((patch_text or "")+"\n",encoding="utf-8")
    return receipt,evidence

class R182DTests(unittest.TestCase):
    def test_unique_numeric_patch_for_exact_table_path(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td); rec,e=setup_case(q,patch_text="1,K/=165:70/=356:5")
            out=r.analyze(rec,[e],"7792d883",369,(165,356))
            self.assertEqual(out["selected_snapshot"]["canonical_table_path"],"1,K")
            self.assertEqual(out["summary"]["unique_numeric_patch_keys"],2)

    def test_other_table_path_is_ignored(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td); rec,e=setup_case(q,patch_text="1,OTHER/=165:70")
            out=r.analyze(rec,[e],"7792d883",369,(165,))
            self.assertEqual(out["keys"][0]["classification"],"NO_SERIALIZED_PATCH")

    def test_conflicting_patch_values_are_not_resolved(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td); rec,e=setup_case(q,patch_text="1,K/=165:70\n1,K/=165:71")
            out=r.analyze(rec,[e],"7792d883",369,(165,))
            self.assertEqual(out["keys"][0]["classification"],"CONFLICTING_NUMERIC_PATCH_CANDIDATES")
            self.assertFalse(out["interpretation_gate"]["base_value_replacement_authorized"])

    def test_nested_json_patch_string_is_found(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td); rec,_=setup_case(q)
            e=q/"e.json";e.write_text(json.dumps({"patches":"1,K/=165:70"}),encoding="utf-8")
            out=r.analyze(rec,[e],"7792d883",369,(165,))
            self.assertEqual(out["summary"]["keys_with_any_patch"],1)

    def test_no_patch_is_scanned_absence_only(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td); rec,e=setup_case(q)
            out=r.analyze(rec,[e],"7792d883",369,(165,))
            self.assertEqual(out["keys"][0]["classification"],"NO_SERIALIZED_PATCH")
            self.assertTrue(out["interpretation_gate"]["absence_means_no_serialized_patch_in_scanned_evidence_only"])

    def test_child_table_path_is_derived(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td)
            protos=q/"x.protos.json"
            pobj={
                "tables":{
                    "100":{"arr":[{"t":369}],"kv":[]},
                    "369":{"arr":[],"kv":[]},
                },
                "protos":{"p":{"__seq":7,"root":{"t":100}}},
                "overrides":[],
            }
            protos.write_text(json.dumps(pobj),encoding="utf-8")
            receipt=q/"r182b.json"
            receipt.write_text(json.dumps({"schema":"luraph-deobf.r182b-base-table-resolution.v1","files":[{
                "path":str(protos),"sha256":"7792d883"+"2"*56,
                "status":"TABLE_FOUND","table_id":369,"requested_keys":[]
            }]}),encoding="utf-8")
            e=q/"e.log";e.write_text("7,root,1/=165:70\n",encoding="utf-8")
            out=r.analyze(receipt,[e],"7792d883",369,(165,))
            self.assertEqual(out["selected_snapshot"]["canonical_table_path"],"7,root,1")
            self.assertEqual(out["summary"]["unique_numeric_patch_keys"],1)

if __name__=="__main__":
    unittest.main()
