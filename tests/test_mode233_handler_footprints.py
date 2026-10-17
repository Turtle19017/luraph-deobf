#!/usr/bin/env python3
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import extract_mode233_handler_footprints as fp


class Mode233HandlerFootprintTests(unittest.TestCase):
    def synthetic_source(self):
        return (
            "x=1;"
            "elseif cR==233 then "
            "if t==1 then BR[s[l]]=BR[H[l]];"
            "elseif t==7 then N,a,p=s[l],w[l],H[l];BR[N]=BR[N]();"
            "elseif t==21 then "
            + fp.OP21_EXACT_BODY +
            "else BR[s[l]]=BR[H[l]]<w[l];end;"
            "elseif cR==54 then x=2;"
        )

    def test_locate_and_split_guarded_mode233(self):
        src = self.synthetic_source()
        branch, start, end = fp.locate_mode233_branch(src)
        self.assertGreater(end, start)
        clauses = fp.split_t_dispatch(branch)
        self.assertEqual(set(clauses), {1, 7, 21})
        self.assertEqual(fp.compact(clauses[21]), fp.compact(fp.OP21_EXACT_BODY))

    def test_op21_write_footprint_is_mixed(self):
        row = fp.footprint(21, fp.OP21_EXACT_BODY)
        self.assertIn("s", row["direct_dest_lane_fields"])
        self.assertTrue(any(x["function"] == "k" for x in row["helper_calls_with_BR"]))
        self.assertEqual(row["classification"], "MIXED_OR_SIDE_EFFECT_GAP")

    def test_direct_s_write(self):
        row = fp.footprint(1, "BR[s[l]]=BR[H[l]];")
        self.assertEqual(row["direct_dest_lane_fields"], ["s"])
        self.assertEqual(row["classification"], "DIRECT_BR_WRITE_FOOTPRINT")


if __name__ == "__main__":
    unittest.main()
