#!/usr/bin/env python3
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import census_r177_producer_predecessors as census


class R177ProducerPredecessorCensusTests(unittest.TestCase):
    def test_scan_target_reports_literal_and_r37_cohit(self):
        n = 220
        S = [0] * n
        w = [0] * n
        s = [0] * n
        H = [0] * n

        # pc10: target-1 literal only.
        S[90], w[90], s[90], H[90] = 32, 99, 1, 2
        # pc20: 37 + target-1 co-hit.
        S[120], w[120], s[120], H[120] = 32, 37, 99, 0
        # target pc50 itself.
        S[100], w[100], s[100], H[100] = 7, 61, 0, 224

        row = census.scan_target(S, w, s, H, 100)
        hit_pcs = {x["pc"] for x in row["operand_literal_hits"]}
        cohit_pcs = {x["pc"] for x in row["r37_literal_cohits"]}

        self.assertEqual(hit_pcs, {90, 120})
        self.assertEqual(cohit_pcs, {120})
        self.assertEqual(row["producer_window"][5]["pc"], 100)

    def test_numeric_pc_order_is_not_encoded_as_proof(self):
        self.assertEqual(census.TARGETS, (2150, 3504, 3363))
        self.assertNotEqual(tuple(sorted(census.TARGETS)), census.TARGETS)


if __name__ == "__main__":
    unittest.main()
