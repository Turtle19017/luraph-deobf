#!/usr/bin/env python3
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "core"))
sys.path.insert(0, str(ROOT / "tools"))

import luasym as S
from ir import Assign, CallStmt, Node, Next, Ret
import export_r178b_cfg_footprints as r178b


class FakeState:
    def __init__(self, mode, pc): self.mode, self.pc = mode, pc
    def key(self, link): return (self.mode, self.pc, 0, (), 0, (), ())


class R178BCFGFootprintTests(unittest.TestCase):
    def test_assignment_orders_reads_before_write(self):
        st = Assign(S.Reg(3), S.Bin("Add", S.Reg(1), S.Reg(2)))
        ev = r178b.stmt_events(st)
        self.assertEqual([(x["kind"], x.get("register")) for x in ev],
                         [("read", 1), ("read", 2), ("write", 3)])

    def test_indirect_assignment_is_not_a_register_write(self):
        st = Assign(S.Index(S.Reg(9), S.Reg(10)), S.Reg(11))
        ev = r178b.stmt_events(st)
        self.assertEqual({x["register"] for x in ev if x["kind"] == "read"}, {9, 10, 11})
        self.assertFalse([x for x in ev if x["kind"] == "write"])
        self.assertTrue(any(x["kind"] == "side-effect-gap" for x in ev))

    def test_branch_micro_paths_stay_separate(self):
        a, b = FakeState(7, 20), FakeState(7, 30)
        node = Node([], cond=S.Reg(4),
                    then=Node([Assign(S.Reg(5), S.Const(1))], outcome=Next(a)),
                    els=Node([Assign(S.Reg(6), S.Const(2))], outcome=Next(b)))
        paths = r178b.flatten_node(node, None)
        self.assertEqual(len(paths), 2)
        by_branch = {tuple(p["branch_trace"]): p for p in paths}
        self.assertEqual(r178b._event_summary(by_branch[(True,)]["events"])["writes"], [5])
        self.assertEqual(r178b._event_summary(by_branch[(False,)]["events"])["writes"], [6])
        for p in paths:
            self.assertIn(4, r178b._event_summary(p["events"])["reads"])

    def test_return_is_a_real_register_consumer(self):
        node = Node([], outcome=Ret(S.Multi([S.Reg(8)])))
        p = r178b.flatten_node(node, None)[0]
        self.assertEqual(r178b._event_summary(p["events"])["reads"], [8])
        self.assertEqual(p["outcome"]["kind"], "return")

    def test_plain_call_has_barrier_but_not_fabricated_register_writes(self):
        st = CallStmt("t0", S.Reg(1), S.Multi([S.Reg(2)]))
        ev = r178b.stmt_events(st)
        self.assertEqual({x["register"] for x in ev if x["kind"] == "read"}, {1, 2})
        self.assertFalse([x for x in ev if x["kind"] == "write"])
        self.assertEqual(sum(x["kind"] == "call-barrier" for x in ev), 1)


    def test_call_marks_captured_register_write_barrier(self):
        st = CallStmt("t0", S.Reg(1), S.Multi([S.Reg(2)]))
        summary = r178b._event_summary(r178b.stmt_events(st, captured_regs={9, 11}))
        self.assertEqual(summary["may_write_registers"], [9, 11])
        self.assertFalse(summary["may_write_all_registers"])

    def test_frame_like_argument_marks_wild_read(self):
        class FrameArg(S.Expr):
            def __init__(self, reg): self.reg = reg
        st = CallStmt("t0", S.Const("f"), S.Multi([FrameArg(12)]))
        summary = r178b._event_summary(r178b.stmt_events(st))
        self.assertTrue(summary["may_read_all_registers"])
        self.assertIn(12, summary["reads"])
        self.assertTrue(summary["may_write_all_registers"])

    def test_exact_frame_eval_emits_proved_writes_but_keeps_read_barrier(self):
        class FrameArg(S.Expr):
            pass
        st = CallStmt("t0", S.Const("f"), S.Multi([FrameArg()]))
        st.frame_eval = {3: 10, 7: 20}
        summary = r178b._event_summary(r178b.stmt_events(st))
        self.assertEqual(summary["writes"], [3, 7])
        self.assertTrue(summary["may_read_all_registers"])
        self.assertFalse(summary["may_write_all_registers"])
        events = r178b.stmt_events(st)
        barrier = next(i for i, e in enumerate(events) if e["kind"] == "call-barrier")
        first_write = next(i for i, e in enumerate(events) if e["kind"] == "write")
        self.assertLess(barrier, first_write)

    def test_build_export_uses_cfg_not_order(self):
        k1, k2 = FakeState(7, 10).key(None), FakeState(7, 20).key(None)
        node1 = Node([Assign(S.Reg(1), S.Const(7))], outcome=Next(FakeState(7, 20)))
        node2 = Node([], outcome=Ret(S.Multi([S.Reg(1)])))
        # Reverse traversal order deliberately.
        out = r178b.build_export([(k2, node2), (k1, node1)], {k1: {k2}}, {}, None,
                                 {"restart": False, "reason": "complete"}, entry_key=k1)
        self.assertTrue(out["graph_complete"])
        self.assertFalse(out["traversal_order_is_execution_order"])
        self.assertEqual(out["edge_mismatches"], [])
        n1 = next(n for n in out["nodes"] if n["key"]["pc"] == 10)
        self.assertEqual(n1["cfg_successors"][0]["pc"], 20)

    def test_missing_cfg_target_is_reported_not_invented(self):
        k1, k2 = FakeState(7, 10).key(None), FakeState(7, 20).key(None)
        node1 = Node([], outcome=Next(FakeState(7, 20)))
        out = r178b.build_export([(k1, node1)], {k1: {k2}}, {}, None,
                                 {"restart": False, "reason": "walk limit"})
        self.assertFalse(out["graph_complete"])
        self.assertEqual(len(out["missing_edge_targets"]), 1)
        self.assertFalse(out["r178a_ledger_ready"])

    def test_transport_provenance_kept_separately(self):
        k1 = FakeState(7, 10).key(None); k2 = FakeState(7, 20).key(None); ks = FakeState(7, 11).key(None)
        node1 = Node([], outcome=Next(FakeState(7, 20)))
        node2 = Node([], outcome=Ret(S.Multi([])))
        out = r178b.build_export([(k1, node1), (k2, node2)], {k1: {k2}}, {(k1, k2): (ks,)}, None,
                                 {"restart": False, "reason": "complete"})
        self.assertEqual(out["transport_edge_count"], 1)
        self.assertEqual(out["transport_edges"][0]["skipped"][0]["pc"], 11)

    def test_common_prefix_write_keeps_same_origin_across_branch_leaves(self):
        root = Node([Assign(S.Reg(3), S.Const(9))], cond=S.Reg(4),
                    then=Node([], outcome=Next(FakeState(7, 20))),
                    els=Node([], outcome=Next(FakeState(7, 30))))
        origin = r178b._origin_root(FakeState(7, 10).key(None))
        paths = r178b.flatten_node(root, None, origin_root=origin)
        ids = [next(e["origin_id"] for e in p["events"]
                    if e.get("kind") == "write" and e.get("register") == 3)
               for p in paths]
        self.assertEqual(len(set(ids)), 1)

    def test_branch_specific_writes_have_distinct_origins(self):
        root = Node([], cond=S.Reg(4),
                    then=Node([Assign(S.Reg(5), S.Const(1))], outcome=Next(FakeState(7, 20))),
                    els=Node([Assign(S.Reg(5), S.Const(2))], outcome=Next(FakeState(7, 30))))
        origin = r178b._origin_root(FakeState(7, 10).key(None))
        paths = r178b.flatten_node(root, None, origin_root=origin)
        ids = [next(e["origin_id"] for e in p["events"] if e.get("kind") == "write") for p in paths]
        self.assertEqual(len(set(ids)), 2)


if __name__ == "__main__":
    unittest.main()
