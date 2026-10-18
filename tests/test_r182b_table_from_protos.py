import importlib.util,json,pathlib,tempfile,unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
P=ROOT/"tools"/"resolve_r182b_table_from_protos.py"
SPEC=importlib.util.spec_from_file_location("r182b",P)
r=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(r)

def write(root,table,name="x.protos.json"):
    obj={"tables":{"369":table},"pid_of_table":{"369":"P369"}}
    p=root/name
    p.write_text(json.dumps(obj),encoding="utf-8")
    return p

class R182BTests(unittest.TestCase):
    def test_arr_entries_resolve(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td); arr=[None]*356
            arr[164]=4; arr[355]=9
            p=write(q,{"arr":arr,"kv":[]})
            out=r.analyze([p],369,(165,356))
            rows=out["files"][0]["requested_keys"]
            self.assertEqual([x["value"]["value"] for x in rows],[4,9])

    def test_kv_overrides_arr(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td); arr=[None]*165; arr[164]=4
            p=write(q,{"arr":arr,"kv":[[165,8]]})
            row=r.analyze([p],369,(165,))["files"][0]["requested_keys"][0]
            self.assertEqual(row["value"]["value"],8)
            self.assertEqual(row["source"],"kv")

    def test_late_key_is_marked(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td); arr=[None]*165; arr[164]=4
            p=write(q,{"arr":arr,"kv":[],"late":[165]})
            out=r.analyze([p],369,(165,))
            self.assertTrue(out["files"][0]["requested_keys"][0]["late"])
            self.assertTrue(out["interpretation_gate"]["late_value_is_reported_not_replayed"])

    def test_nonscalar_table_ref_is_not_claimed_scalar(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td); arr=[None]*165; arr[164]={"t":777}
            p=write(q,{"arr":arr,"kv":[]})
            row=r.analyze([p],369,(165,))["files"][0]["requested_keys"][0]
            self.assertEqual(row["status"],"FOUND_NONSCALAR")
            self.assertEqual(row["value"]["repr"],"LTable#777")

    def test_directory_discovers_only_protos_json(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td)
            write(q,{"arr":[],"kv":[]})
            (q/"other.json").write_text(json.dumps({"tables":{"369":{"arr":[],"kv":[]}}}))
            out=r.analyze([q],369,(165,))
            self.assertEqual(out["summary"]["candidate_files"],1)

    def test_missing_table_is_reported_not_fabricated(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td); p=q/"x.protos.json"
            p.write_text(json.dumps({"tables":{}}))
            out=r.analyze([p],369,(165,))
            self.assertEqual(out["files"][0]["status"],"TABLE_ABSENT")
            self.assertFalse(out["interpretation_gate"]["base_value_proves_failure_time_value"])

if __name__=="__main__":
    unittest.main()
