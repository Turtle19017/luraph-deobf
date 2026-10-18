import json
import pathlib
import tempfile
import unittest
import sys
sys.path.insert(0, "/mnt/data")
import analyze_r179b_underflow_artifacts as r


class R179BTests(unittest.TestCase):
    def test_framefail_jsonl_extracts_r0(self):
        with tempfile.TemporaryDirectory() as td:
            p = pathlib.Path(td) / "log.jsonl"
            p.write_text('[FRAMEFAIL] ' + json.dumps({
                "kind":"below_stack", "register":0, "stack_base":4,
                "proto":"p", "mode":7, "pc":20, "last_op":"(7, 9)",
                "jump_regs":[0, 8], "facts":"{0: ('c', None)}"
            }) + '\n', encoding='utf-8')
            out = r.analyze([p], 1)
            s = out['summary']
            self.assertEqual(s['unique_sites'], 1)
            self.assertEqual(s['zero_slot'], 1)
            self.assertEqual(s['in_jump_regs'], 1)
            self.assertEqual(s['zero_slot_nil_fact_hint'], 1)

    def test_negative_store_from_nested_json(self):
        with tempfile.TemporaryDirectory() as td:
            p = pathlib.Path(td) / "receipt.json"
            p.write_text(json.dumps({"x":[{"kind":"below_stack_store", "register":-2,
                                           "stack_base":3, "function":5, "walk":8}]}), encoding='utf-8')
            out = r.analyze([p])
            s = out['summary']
            self.assertEqual(s['stores'], 1)
            self.assertEqual(s['negative_slot'], 1)

    def test_duplicate_site_prefers_richer_record(self):
        with tempfile.TemporaryDirectory() as td:
            p = pathlib.Path(td) / "x.jsonl"
            base = {"kind":"below_stack", "register":0, "function":1, "walk":2, "state_key":"K"}
            rich = dict(base, stack_base=5, proto="p", mode=1, pc=2)
            p.write_text(json.dumps(base)+'\n'+json.dumps(rich)+'\n', encoding='utf-8')
            out = r.analyze([p], 1)
            self.assertEqual(out['summary']['duplicate_records'], 1)
            self.assertEqual(out['sites'][0]['stack_base'], 5)

    def test_text_fallback_keeps_incomplete_explicit(self):
        with tempfile.TemporaryDirectory() as td:
            p = pathlib.Path(td) / "REPORT.md"
            p.write_text('error: read below the stack VM\'s frame (register -1)\n', encoding='utf-8')
            out = r.analyze([p])
            self.assertEqual(out['summary']['unique_sites'], 1)
            self.assertEqual(out['summary']['missing_stack_base'], 1)

    def test_expect_count_is_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            p = pathlib.Path(td) / "x.log"
            p.write_text('read below the stack VM\'s frame (register 0)\n', encoding='utf-8')
            with self.assertRaises(ValueError):
                r.analyze([p], 49)


if __name__ == '__main__':
    unittest.main()
