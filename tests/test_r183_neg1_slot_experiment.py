"""Off-by-default diagnostic lane for the exact register=-1/stack_base=1 cohort."""
import os
import pathlib
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "core"))
from obfuscators.luraph_v15 import devirt as d
from test_entry_facts_bridge import lifter


class Neg1SlotExperimentTests(unittest.TestCase):
    def test_flag_off_preserves_read_rejection(self):
        lf=lifter();lf.stack_base=1
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(d.Unsupported):
                lf.index(d.REGFILE,-1,None)

    def test_flag_on_allows_exact_neg1_read_as_ordinary_reg(self):
        lf=lifter();lf.stack_base=1
        with patch.dict(os.environ, {"DEVIRT_NEG1_SLOT_EXPERIMENT":"1"}, clear=True):
            self.assertEqual(lf.index(d.REGFILE,-1,None),d.Reg(-1))

    def test_flag_on_allows_exact_neg1_store_as_ordinary_reg(self):
        lf=lifter();lf.stack_base=1
        with patch.dict(os.environ, {"DEVIRT_NEG1_SLOT_EXPERIMENT":"1"}, clear=True):
            lf.newindex(d.REGFILE,-1,d.Const(7),None)
        self.assertEqual(len(lf.out),1)
        self.assertEqual(lf.out[0].target,d.Reg(-1))
        self.assertEqual(lf.out[0].value,d.Const(7))

    def test_flag_does_not_allow_other_negative_slots(self):
        lf=lifter();lf.stack_base=1
        with patch.dict(os.environ, {"DEVIRT_NEG1_SLOT_EXPERIMENT":"1"}, clear=True):
            with self.assertRaises(d.Unsupported):
                lf.index(d.REGFILE,-2,None)
            with self.assertRaises(d.Unsupported):
                lf.newindex(d.REGFILE,-2,d.Const(7),None)

    def test_flag_does_not_allow_neg1_when_stack_base_is_not_one(self):
        lf=lifter();lf.stack_base=2
        with patch.dict(os.environ, {"DEVIRT_NEG1_SLOT_EXPERIMENT":"1"}, clear=True):
            with self.assertRaises(d.Unsupported):
                lf.index(d.REGFILE,-1,None)

    def test_flag_does_not_change_zero_slot_rules(self):
        lf=lifter();lf.stack_base=1;lf.step_facts={}
        with patch.dict(os.environ, {"DEVIRT_NEG1_SLOT_EXPERIMENT":"1"}, clear=True):
            with self.assertRaises(d.Unsupported):
                lf.index(d.REGFILE,0,None)
            with self.assertRaises(d.Unsupported):
                lf.newindex(d.REGFILE,0,d.Const(7),None)

if __name__=="__main__":
    unittest.main()
