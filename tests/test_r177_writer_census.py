#!/usr/bin/env python3
import json
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import extract_r177_writer_census as census


class R177WriterCensusBulkCollectorTests(unittest.TestCase):
    def test_selector107_semantic_labelled_bulk_xor_is_collected(self):
        path = ROOT / "receipts" / "luraph_VM68_mode233_selector107_buffer_continuation.json"
        obj = json.loads(path.read_text(encoding="utf-8"))
        rows = census.bulk_ops(obj, path.name)
        triples = {(r["seed"], r["start"], r["length"], r["end"]) for r in rows}
        self.assertIn((113, 639, 26, 664), triples)

    def test_pc652_expected_mask(self):
        # pc652 is the 14th element of the pc1582 XOR span 639..664.
        mask = (113 ^ (652 - 639 + 1)) & 0x7F
        self.assertEqual(mask, 127)
        self.assertEqual(50 ^ mask, 77)

    def test_unpromoted_s7_site_remains_mode_unresolved(self):
        promoted = {2150, 3504, 3363}
        self.assertEqual(
            census.opcode7_site_status(180, promoted),
            "MODE_UNRESOLVED_OPCODE7_LIKE_SITE",
        )
        self.assertEqual(
            census.opcode7_site_status(2150, promoted),
            "PROMOTED_MODE233_OPCODE7_PRODUCER",
        )


if __name__ == "__main__":
    unittest.main()
