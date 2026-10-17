#!/usr/bin/env python3
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import census_r177_producer_predecessors as census


class R177ProducerPredecessorCensusTests(unittest.TestCase):
    def test_scan_target_reports_literal_and_r37_cohit(self):
        n = 120
        S = [0] * n
        w = [0] * n
        s = [0] * n
        H = [0] * n

        # pc10: target-1 literal only.
        S[10], w[10], s[10], H[10] = 32, 49, 1, 2
        # pc20: 37 + target-1 co-hit.
        S[20], w[20], s[20], H[20] = 32, 37, 49, 0
        # target pc50 itself.
        S[50], w[50], s[50], H[50] = 7, 61, 0, 224

        row = census.scan_target(S, w, s, H, 50)
        hit_pcs = {x["pc"] for x in row["operand_literal_hits"]}
        cohit_pcs = {x["pc"] for x in row["r37_literal_cohits"]}

        self.assertEqual(hit_pcs, {10, 20})
        self.assertEqual(cohit_pcs, {20})
        self.assertEqual(row["producer_window"][5]["pc"], 50)

    def test_numeric_pc_order_is_not_encoded_as_proof(self):
        self.assertEqual(census.TARGETS, (2150, 3504, 3363))
        self.assertNotEqual(tuple(sorted(census.TARGETS)), census.TARGETS)


if __name__ == "__main__":
    unittest.main()
