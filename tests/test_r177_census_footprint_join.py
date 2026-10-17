#!/usr/bin/env python3
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import join_r177_census_footprints as joiner


class R177CensusFootprintJoinTests(unittest.TestCase):
    def setUp(self):
        self.present = {1, 21, 26, 34}
        self.absent = {11}
        self.footprints = {
            "1": {
                "direct_dest_lane_fields": ["w"],
                "helper_calls_with_BR": [],
                "calls_through_BR_values": [],
                "all_named_calls": [],
                "lane_self_rewrites": [],
                "unknown_direct_dest_expressions": [],
            },
            "21": {
                "direct_dest_lane_fields": ["s"],
                "helper_calls_with_BR": [{"function": "k"}],
                "calls_through_BR_values": [{"kind": "direct_BR_value_call"}],
                "all_named_calls": [{"name": "k"}],
                "lane_self_rewrites": [],
                "unknown_direct_dest_expressions": [],
            },
            "26": {
                "direct_dest_lane_fields": ["w"],
                "helper_calls_with_BR": [],
                "calls_through_BR_values": [],
                "all_named_calls": [{"name": "A"}],
                "lane_self_rewrites": [],
                "unknown_direct_dest_expressions": [],
            },
            "34": {
                "direct_dest_lane_fields": ["s", "w"],
                "helper_calls_with_BR": [],
                "calls_through_BR_values": [],
                "all_named_calls": [{"name": "T"}],
                "lane_self_rewrites": ["S"],
                "unknown_direct_dest_expressions": [],
            },
        }

    def hit(self, pc, op, S, w, s, H):
        return {
            "pc": pc,
            "opcode": op,
            "tuple": {"S": S, "w": w, "s": s, "H": H},
            "tracked_operand_fields": {},
        }

    def test_op1_h117_is_not_destination(self):
        row = joiner.classify_hit(
            self.hit(1577, 1, 1, 1, 0, 117),
            self.footprints, self.present, self.absent,
        )
        self.assertEqual(row["direct_tracked_destinations"], [])
        self.assertEqual(row["classification"], "NO_DIRECT_TRACKED_DEST")

    def test_op26_s177_is_not_destination(self):
        row = joiner.classify_hit(
            self.hit(2177, 26, 26, 201, 177, 164),
            self.footprints, self.present, self.absent,
        )
        self.assertEqual(row["direct_tracked_destinations"], [])
        self.assertEqual(row["classification"], "NO_DIRECT_TRACKED_DEST_BUT_SIDE_EFFECT_GAP")

    def test_op34_w177_is_direct_r177_candidate(self):
        row = joiner.classify_hit(
            self.hit(1229, 34, 34, 177, 0, 254),
            self.footprints, self.present, self.absent,
        )
        self.assertEqual(row["direct_tracked_destinations"], [{"field": "w", "register": 177}])
        self.assertEqual(row["classification"], "DIRECT_TRACKED_WRITE_PLUS_SIDE_EFFECT_GAP")

    def test_pc3784_is_boundary_write(self):
        row = joiner.classify_hit(
            self.hit(3784, 21, 21, 156, 177, 50),
            self.footprints, self.present, self.absent,
        )
        self.assertTrue(row["boundary"])
        self.assertEqual(row["direct_tracked_destinations"], [{"field": "s", "register": 177}])
        self.assertEqual(row["classification"], "BOUNDARY_DIRECT_TRACKED_WRITE")

    def test_absent_opcode_stays_mode_unresolved(self):
        row = joiner.classify_hit(
            self.hit(2868, 11, 11, 62, 117, 3005),
            self.footprints, self.present, self.absent,
        )
        self.assertEqual(row["classification"], "MODE_UNRESOLVED_ABSENT_FROM_MODE233")


if __name__ == "__main__":
    unittest.main()
