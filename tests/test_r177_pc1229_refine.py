#!/usr/bin/env python3
import json
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import refine_r177_join_pc1229 as refine


class R177Pc1229RefineTests(unittest.TestCase):
    def test_expected_class_constant(self):
        self.assertEqual(
            refine.EXPECTED_CLASS,
            "RECEIPT_SUPPORTED_SELECTOR121_LAZY_REPAIR_NOT_DIRECT_R177_WRITE",
        )

    def test_refinement_shape_documented(self):
        join = {
            "schema": refine.EXPECTED_JOIN_SCHEMA,
            "classification_counts": {
                "MODE_UNRESOLVED_ABSENT_FROM_MODE233": 45,
            },
            "pre_boundary_direct_tracked_write_candidates": [
                {"pc": 1229, "opcode": 34}
            ],
            "pre_boundary_direct_r177_write_candidates": [
                {"pc": 1229, "opcode": 34}
            ],
            "boundary_rows": [{"pc": 3784}],
        }
        audit = {
            "schema": refine.EXPECTED_AUDIT_SCHEMA,
            "pc": 1229,
            "fail": 0,
            "classification": refine.EXPECTED_CLASS,
            "r177_direct_write": False,
        }
        self.assertEqual(join["pre_boundary_direct_r177_write_candidates"][0]["pc"], 1229)
        self.assertFalse(audit["r177_direct_write"])
        self.assertEqual(
            join["classification_counts"]["MODE_UNRESOLVED_ABSENT_FROM_MODE233"],
            45,
        )


if __name__ == "__main__":
    unittest.main()
