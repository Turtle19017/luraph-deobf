import importlib.util,json,pathlib,tempfile,unittest

ROOT=pathlib.Path(__file__).resolve().parents[1]
P=ROOT/"tools"/"run_r183_experiment_stats.py"
SPEC=importlib.util.spec_from_file_location("r183b",P)
r=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(r)

def receipt(q, **overrides):
    obj={
      "schema":"luraph-deobf.r183a-exact-sub-operands.v2",
      "summary":{
        "sites_with_matched_framefail":7,
        "sites_all_exact_sub_neg1":7,
        "sites_with_nonexact_records":0,
        "extra_read_neg1_framefails":0,
      },
      "accepted_baseline":{"source_sha256":r.SOURCE_SHA},
      "interpretation_gate":{
        "exact_accepted_location_gate_for_diagnostic_experiment":True,
        "canonical_composite_identity_gate":False,
        "semantic_change_authorized":False,
      },
    }
    for path,value in overrides.items():
        cur=obj
        parts=path.split(".")
        for p in parts[:-1]:cur=cur[p]
        cur[parts[-1]]=value
    p=q/"r183a.json";p.write_text(json.dumps(obj),encoding="utf-8");return p

class R183BTests(unittest.TestCase):
    def test_require_r183a_accepts_exact_diagnostic_receipt(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td);o=r.require_r183a(receipt(q))
            self.assertEqual(o["summary"]["sites_with_matched_framefail"],7)
            self.assertFalse(o["interpretation_gate"]["canonical_composite_identity_gate"])

    def test_require_r183a_rejects_missing_site(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td)
            with self.assertRaisesRegex(ValueError,"sites_with_matched_framefail"):
                r.require_r183a(receipt(q,**{"summary.sites_with_matched_framefail":6}))

    def test_require_r183a_rejects_semantic_authorization(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td)
            with self.assertRaisesRegex(ValueError,"semantic change"):
                r.require_r183a(receipt(q,**{"interpretation_gate.semantic_change_authorized":True}))

    def test_parse_stats_and_choose_last_collect(self):
        with tempfile.TemporaryDirectory() as td:
            p=pathlib.Path(td)/"x.log"
            p.write_text(
              '[R183STATS] {"kind":"collect_requests","functions":78,"errors":20,"fallbacks":0,"requests":100}\n'
              '[R183STATS] {"kind":"lift_program","functions":78,"errors":21,"fallbacks":0,"requests":101}\n'
              '[R183STATS] {"kind":"collect_requests","functions":78,"errors":22,"fallbacks":0,"requests":102}\n',
              encoding="utf-8")
            rows=r.parse_stats(p);sel,collect=r.choose_collect_stats(rows)
            self.assertEqual(len(collect),2)
            self.assertEqual(sel["errors"],22)
            self.assertEqual(sel["requests"],102)

    def test_choose_collect_stats_fails_without_marker(self):
        with self.assertRaisesRegex(ValueError,"no \[R183STATS\]"):
            r.choose_collect_stats([])

    def test_choose_collect_stats_requires_integer_totals(self):
        rows=[{"kind":"collect_requests","functions":78,"errors":None,"fallbacks":0,"requests":594}]
        with self.assertRaisesRegex(ValueError,"integer errors"):
            r.choose_collect_stats(rows)

    def test_git_blob_sha1_matches_git_blob_formula(self):
        with tempfile.TemporaryDirectory() as td:
            p=pathlib.Path(td)/"x";p.write_bytes(b"abc")
            self.assertEqual(r.git_blob_sha1(p),"f2ba8f84ab5c1bce84a7b441cb1959cfc7093b7f")

if __name__=="__main__":
    unittest.main()
