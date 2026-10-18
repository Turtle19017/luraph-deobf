"""Assigned predicates must retain facts before a later VM branch reads them."""
import pathlib
import sys
import types
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "core"))
from obfuscators.luraph_v15 import devirt as d


class AssignedFactTests(unittest.TestCase):
    def apply(self, value, facts=None, dest=42):
        facts = dict(facts or {})
        d.apply_stmt_facts(d.Assign(d.Reg(dest), value), facts,
                           types.SimpleNamespace(captured_regs=set()))
        return facts

    def test_assigned_compare_preserves_known_result(self):
        facts = self.apply(d.Bin("CompareLe", d.Reg(40), d.Const(14)), {40: ("c", 11)})
        self.assertEqual(facts[42], ("c", True))

    def test_predicate_self_assignment_reads_old_fact(self):
        facts = self.apply(d.Bin("CompareLe", d.Reg(40), d.Const(14)),
                           {40: ("c", 11)}, dest=40)
        self.assertEqual(facts[40], ("c", True))

    def test_assigned_compare_false(self):
        facts = self.apply(d.Bin("CompareLe", d.Reg(40), d.Const(6)), {40: ("c", 11)})
        self.assertEqual(facts[42], ("c", False))

    def test_assigned_compare_two_registers(self):
        facts = self.apply(d.Bin("CompareEq", d.Reg(40), d.Reg(41)),
                           {40: ("c", 11), 41: ("c", 11)})
        self.assertEqual(facts[42], ("c", True))

    def test_assigned_not_uses_lua_truthiness_for_zero(self):
        facts = self.apply(d.Un("Not", d.Reg(40)), {40: ("c", 0)})
        self.assertEqual(facts[42], ("c", False))

    def test_assigned_not_of_nil(self):
        self.assertEqual(self.apply(d.Un("Not", d.Reg(40)), {40: ("c", None)})[42],
                         ("c", True))

    def test_unknown_compare_kills_stale_destination_fact(self):
        facts = self.apply(d.Bin("CompareLe", d.Reg(40), d.Const(14)), {42: ("c", True)})
        self.assertNotIn(42, facts)

    def test_invalid_ordering_does_not_invent_fact(self):
        facts = self.apply(d.Bin("CompareLe", d.Reg(40), d.Const(14)), {40: ("c", None)})
        self.assertNotIn(42, facts)

    def test_existing_copy_and_table_truthiness_remain_supported(self):
        self.assertEqual(self.apply(d.Reg(40), {40: ("c", 7)})[42], ("c", 7))
        self.assertEqual(self.apply(d.S.NewTable())[42], ("t",))

    def test_assigned_predicate_prunes_infeasible_successor(self):
        yes, no = d.State(99, 100, None), d.State(99, 200, None)
        node = d.Node([d.Assign(d.Reg(42), d.Bin("CompareLe", d.Reg(40), d.Const(14)))],
                      cond=d.Un("Not", d.Reg(42)),
                      then=d.Node([], outcome=d.Next(yes)),
                      els=d.Node([], outcome=d.Next(no)))
        succ = []
        d.propagate(node, {40: ("c", 11)}, succ, types.SimpleNamespace(captured_regs=set()))
        self.assertEqual([s.pc for s, _ in succ], [200])

    def test_unknown_predicate_keeps_both_successors(self):
        node = d.Node([d.Assign(d.Reg(42), d.Bin("CompareLe", d.Reg(40), d.Const(14)))],
                      cond=d.Reg(42),
                      then=d.Node([], outcome=d.Next(d.State(99, 100, None))),
                      els=d.Node([], outcome=d.Next(d.State(99, 200, None))))
        succ = []
        d.propagate(node, {}, succ, types.SimpleNamespace(captured_regs=set()))
        self.assertEqual({s.pc for s, _ in succ}, {100, 200})

    def test_assigned_predicates_do_not_invent_sixteen_stack_depths(self):
        # Four known predicates model a dispatcher that otherwise fans out to
        # sixteen temporary stack heights (more than MAX_STACK_DEPTHS=8).
        paths = [(0, {40: ("c", 11)})]
        for bit in range(4):
            successors = []
            for depth, facts in paths:
                unchanged = d.State(99, bit + 1, None, locs=(("sp", depth),))
                impossible = d.State(99, bit + 1, None, locs=(("sp", depth + (1 << bit)),))
                node = d.Node([
                    d.Assign(d.Reg(42), d.Bin("CompareLe", d.Reg(40), d.Const(14)))
                ], cond=d.Reg(42),
                    then=d.Node([], outcome=d.Next(unchanged)),
                    els=d.Node([], outcome=d.Next(impossible)))
                d.propagate(node, dict(facts), successors,
                            types.SimpleNamespace(captured_regs=set()))
            paths = [(state.locs[0][1], facts) for state, facts in successors]
        self.assertEqual({depth for depth, _ in paths}, {0})


if __name__ == "__main__":
    unittest.main()
