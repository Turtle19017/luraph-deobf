"""Gated fresh-frame nil proof is not permission for arbitrary register zero."""
import pathlib
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "core"))
from obfuscators.luraph_v15 import devirt as d
from test_entry_facts_bridge import lifter


class ZeroSlotFactTests(unittest.TestCase):
    def test_fresh_table_creation_records_zero_nil(self):
        lf = lifter()
        lf.frame_entry_facts = {}
        lf.in_prologue = True
        self.assertIsInstance(lf.call_builtin(d.Builtin("table.create"), d.Multi([10]), None, False), d.RegFile)
        self.assertEqual(lf.frame_entry_facts, {0: ("c", None)})

    def test_only_proven_nil_can_avoid_raw_zero_read(self):
        lf = lifter()
        lf.stack_base = 1
        with patch.dict("os.environ", {"DEVIRT_ZERO_SLOT_FACT": "1"}):
            lf.step_facts = {0: ("c", None)}
            self.assertIsNone(lf.index(d.REGFILE, 0, None))
            for facts in ({}, {0: ("t",)}, {0: ("c", 3)}):
                lf.step_facts = facts
                with self.assertRaises(d.Unsupported):
                    lf.index(d.REGFILE, 0, None)

    def test_zero_stores_and_negative_reads_are_still_rejected(self):
        lf = lifter()
        lf.stack_base = 1
        lf.step_facts = {0: ("c", None)}
        with patch.dict("os.environ", {"DEVIRT_ZERO_SLOT_FACT": "1"}):
            for value in (d.Const(3), d.REGFILE):
                with self.assertRaises(d.Unsupported):
                    lf.newindex(d.REGFILE, 0, value, None)
            with self.assertRaises(d.Unsupported):
                lf.index(d.REGFILE, -1, None)

    def test_unknown_prologue_write_kills_initial_zero_proof(self):
        lf = lifter()
        lf.frame_entry_facts = {0: ("c", None)}
        lf.in_prologue = True
        lf.newindex(d.REGFILE, 0, d.Reg(9), None)
        self.assertNotIn(0, lf.frame_entry_facts)

    def test_indirect_effect_kills_zero_proof(self):
        facts = {0: ("c", None), 5: ("c", 1)}
        with patch.dict("os.environ", {"DEVIRT_ZERO_SLOT_FACT": "1"}):
            d.apply_stmt_facts(d.Assign(d.Index(d.Reg(2), d.Reg(3)), d.Const(1)), facts, lifter())
        self.assertNotIn(0, facts)
        self.assertEqual(facts[5], ("c", 1))


if __name__ == "__main__":
    unittest.main()
