import importlib.util,json,pathlib,tempfile,unittest

ROOT=pathlib.Path(__file__).resolve().parents[1]
P=ROOT/"tools"/"run_r183_experiment_stats.py"
SPEC=importlib.util.spec_from_file_location("r183c",P)
r=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(r)

def capture_receipt(q,gate=True):
    o={
      "schema":"luraph-deobf.r183a-exact-sub-operands.v2",
      "checkpoint":{"expected":{"functions":78,"errors":64,"fallbacks":0,"requests":594}},
      "summary":{"sites_with_matched_framefail":7,"sites_all_exact_sub_neg1":7,
                 "sites_with_nonexact_records":0,"extra_read_neg1_framefails":0},
      "accepted_baseline":{"source_sha256":r.SOURCE_SHA,"output_sha256":r.OUTPUT_SHA,
                           "unique_read_neg1_locations":7},
      "interpretation_gate":{"exact_accepted_location_gate_for_diagnostic_experiment":gate,
                             "semantic_change_authorized":False},
    }
    p=q/"cap.json";p.write_text(json.dumps(o),encoding="utf-8");return p

class R183CStatsTests(unittest.TestCase):
    def test_capture_receipt_gate_accepts_canonical_false_case(self):
        with tempfile.TemporaryDirectory() as td:
            p=capture_receipt(pathlib.Path(td))
            o=r.require_capture_receipt(p)
            self.assertEqual(o["summary"]["sites_all_exact_sub_neg1"],7)

    def test_capture_receipt_false_gate_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            p=capture_receipt(pathlib.Path(td),False)
            with self.assertRaisesRegex(ValueError,"diagnostic gate"):
                r.require_capture_receipt(p)

    def test_final_complete_stats_marker_selected(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td);p=q/"x.log"
            p.write_text(
              '[R183STATS] {"kind":"collect_requests","functions":78,"errors":50,"fallbacks":0,"walked":642,"requests":610}\n'
              '[R183STATS] {"kind":"lift_program","functions":78,"errors":47,"fallbacks":0,"walked":null,"requests":612}\n',
              encoding="utf-8")
            ms=r.parse_stats_markers(p);sel=r.select_stats(ms)
            self.assertEqual(len(ms),2)
            self.assertEqual((sel["functions"],sel["errors"],sel["requests"]),(78,47,612))

    def test_incomplete_marker_does_not_prove_stats(self):
        with tempfile.TemporaryDirectory() as td:
            p=pathlib.Path(td)/"x.log"
            p.write_text('[R183STATS] {"functions":78,"errors":null,"requests":null}\n',encoding="utf-8")
            self.assertIsNone(r.select_stats(r.parse_stats_markers(p)))

    def test_generated_summary_consensus_fallback(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td);probe=q/"_probe";probe.mkdir();label="L";d=probe/label;d.mkdir()
            for i in range(2):
                (d/f"s{i}.json").write_text(json.dumps({
                  "stats":{"functions":78,"errors":52,"fallbacks":0},"requests":601}),encoding="utf-8")
            log=probe/"e.log";log.write_text("",encoding="utf-8")
            rec=r.receipt_from_log(log,label,probe,q/"cap.json")
            self.assertTrue(rec["exact_stats_proved"])
            self.assertEqual(rec["exact_stats_source"],"GENERATED_SUMMARY_CONSENSUS")
            self.assertEqual(rec["exact_stats"]["errors"],52)

    def test_conflicting_generated_summaries_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            q=pathlib.Path(td);probe=q/"_probe";probe.mkdir();label="L";d=probe/label;d.mkdir()
            (d/"a.json").write_text(json.dumps({"stats":{"functions":78,"errors":52,"fallbacks":0},"requests":601}),encoding="utf-8")
            (d/"b.json").write_text(json.dumps({"stats":{"functions":78,"errors":53,"fallbacks":0},"requests":601}),encoding="utf-8")
            log=probe/"e.log";log.write_text("",encoding="utf-8")
            rec=r.receipt_from_log(log,label,probe,q/"cap.json")
            self.assertFalse(rec["exact_stats_proved"])
            self.assertIsNone(rec["exact_stats"])

if __name__=="__main__":
    unittest.main()
