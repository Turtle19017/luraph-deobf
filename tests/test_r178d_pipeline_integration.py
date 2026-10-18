#!/usr/bin/env python3
import pathlib, sys, unittest
ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "core")); sys.path.insert(0, str(ROOT / "tools"))
import luasym as S
from ir import Assign, Node, Ret
import export_r178b_cfg_footprints as r178b
import analyze_r178c_cfg_write_fates as r178c
import analyze_r178d_origin_consensus as r178d


class FakeState:
    def __init__(self, mode, pc): self.mode, self.pc = mode, pc
    def key(self, link): return (self.mode, self.pc, 0, (), 0, (), ())


class R178DPipelineIntegrationTests(unittest.TestCase):
    def test_common_prefix_negative_fates_merge_to_prunable_origin(self):
        key = FakeState(7, 10).key(None)
        node = Node([Assign(S.Reg(1), S.Const(7))], cond=S.Reg(4),
                    then=Node([Assign(S.Reg(1), S.Const(8))], outcome=Ret(S.Multi([]))),
                    els=Node([], outcome=Ret(S.Multi([]))))
        b = r178b.build_export([(key, node)], {}, {}, None,
                               {"restart": False, "reason": "complete"}, entry_key=key)
        c = r178c.analyze(b, [1])
        d = r178d.analyze(c)
        common = next(x for x in d["origins"] if x["instance_count"] == 2)
        self.assertEqual(common["classifications"], ["MUST_DEAD", "MUST_SHADOWED"])
        self.assertEqual(common["consensus"], "PROVEN_UNCONSUMED")
        self.assertTrue(common["prunable_origin"])
        self.assertIn(common["origin_id"], d["prunable_origins"])
        self.assertFalse(d["pruning_applied"])


if __name__ == "__main__": unittest.main()
