"""Entry constants reach interpreter reads, with write kills and cache weakening."""
import pathlib
import os
import sys
import types
import unittest
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "core"))
from obfuscators.luraph_v15 import devirt as d


def lifter():
    lf = d.ProtoLifter.__new__(d.ProtoLifter)
    lf.step_facts = {}
    lf.out = []
    lf.temp_defs = {}
    lf.jvals = {}
    lf.jread = set()
    lf.packs = {}
    lf.pack_copies = {}
    lf.pack_read = set()
    lf.pack_killed = set()
    lf.jump_regs = set()
    lf.captured_regs = set()
    lf.stack_base = None
    return lf


class EntryFactsTests(unittest.TestCase):
    def test_graph_initialization_does_not_inherit_previous_instruction_facts(self):
        lf = types.SimpleNamespace(stack_base=None, walk_only=False, jump_regs=set(),
                                   captured_regs=set(), pack_killed=set(), pack_unstable=set(),
                                   step_facts={6: ("c", 99)})
        test = self

        class Stepper:
            new_carry = False
            def initial(self):
                test.assertIsNone(lf.step_facts)
                return d.State(0, 0, None)
            def step(self, state, prefix, facts=None):
                return d.Node([], outcome=d.Ret(d.Multi([])))

        prog = d.Program.__new__(d.Program)
        prog._walk(types.SimpleNamespace(kstack_link=None), lf, Stepper(), 10)

    def test_truthiness_fact_decides_branch_without_becoming_register_value(self):
        lf = lifter()
        it = d.S.Interp(lf)
        lf.step_facts = {6: ("f",)}
        self.assertEqual(lf.index(d.REGFILE, 6, None), d.Reg(6))
        self.assertIs(it.cond_true(d.Reg(6)), False)
        lf.step_facts = {6: ("t",)}
        self.assertEqual(lf.index(d.REGFILE, 6, None), d.Reg(6))
        self.assertIs(it.cond_true(d.Reg(6)), True)
        self.assertEqual(it.dlog, [])

    def test_constant_condition_observes_lua_zero_and_false_truthiness(self):
        it = d.S.Interp(lifter())
        self.assertIs(it.cond_true(d.Const(0)), True)
        self.assertIs(it.cond_true(d.Const(False)), False)
        self.assertIs(it.cond_true(d.Const(None)), False)

    def test_jval_wins_entry_fact_and_records_jread(self):
        lf = lifter()
        lf.jump_regs = {39}
        lf.jvals = {39: 11944}
        lf.step_facts = {39: ("c", 11944)}
        self.assertEqual(lf.index(d.REGFILE, 39, None), 11944)
        self.assertIn(39, lf.jread)

    def test_pack_wins_entry_fact_and_records_pack_read(self):
        lf = lifter()
        lf.packs = {6: d.SymList([], d.TempTail("pack"), nkey=b"n")}
        lf.step_facts = {6: ("c", 1)}
        self.assertIsInstance(lf.index(d.REGFILE, 6, None), d.SymList)
        self.assertIn(6, lf.pack_read)

    def test_disabled_bridge_does_not_start_tracking_writes(self):
        lf = lifter()
        lf.step_facts = None
        lf.emit(d.Assign(d.Reg(6), d.Const(3)))
        self.assertIsNone(lf.step_facts)
        self.assertEqual(lf.index(d.REGFILE, 6, None), d.Reg(6))

    def test_entry_constant_including_zero_false_and_nil(self):
        lf = lifter()
        for value in (0, False, None, 7):
            lf.step_facts = {6: ("c", value)}
            self.assertIs(lf.index(d.REGFILE, 6, None), value)

    def test_truthiness_is_not_a_value(self):
        lf = lifter()
        for fact in (("t",), ("f",), ("t", object())):
            lf.step_facts = {6: fact}
            self.assertEqual(lf.index(d.REGFILE, 6, None), d.Reg(6))

    def test_unknown_write_kills_entry_constant(self):
        lf = lifter()
        lf.step_facts = {6: ("c", 0)}
        lf.emit(d.Assign(d.Reg(6), d.Reg(9)))
        self.assertEqual(lf.index(d.REGFILE, 6, None), d.Reg(6))

    def test_constant_write_refreshes_fact(self):
        lf = lifter()
        lf.step_facts = {6: ("c", 0)}
        lf.emit(d.Assign(d.Reg(6), d.Const(3)))
        self.assertEqual(lf.index(d.REGFILE, 6, None), 3)

    def test_alias_copies_fact_before_destination_write(self):
        lf = lifter()
        lf.step_facts = {6: ("c", 4), 9: ("c", 7)}
        lf.emit(d.Assign(d.Reg(6), d.Reg(9)))
        self.assertEqual(lf.index(d.REGFILE, 6, None), 7)

    def test_call_kills_captured_register_fact(self):
        lf = lifter()
        lf.step_facts = {6: ("c", 4)}
        lf.captured_regs = {6}
        lf.emit(d.CallStmt("t", d.Reg(2), d.Multi([])))
        self.assertEqual(lf.index(d.REGFILE, 6, None), d.Reg(6))

    def test_concrete_tmove_copies_exactly_requested_count(self):
        for count in (0, 1):
            with self.subTest(count=count):
                lf = lifter()
                lf.step_facts = {6: ("c", count)}
                src = d.SymList([], d.TempTail("T"), nkey=b"n")
                end = lf.index(d.REGFILE, 6, None)
                self.assertEqual(end, count)
                lf.tmove(d.Multi([src, 1, end, 3, d.REGFILE]))
                self.assertEqual(len(lf.out), count)
                if count:
                    self.assertEqual(lf.out[0].target, d.Reg(3))
                    self.assertEqual(lf.out[0].value, d.TempVal("T", 1))

    def test_join_weakening_rebuilds_cached_specialized_node(self):
        class Stepper:
            new_carry = False
            def initial(self):
                return d.State(0, 0, None)
            def step(self, state, prefix, facts=None):
                if state.pc == 0:
                    return d.Node([], cond=d.Reg(99),
                                  then=d.Node([], outcome=d.Next(d.State(0, 1, None))),
                                  els=d.Node([], outcome=d.Next(d.State(0, 2, None))))
                if state.pc in (1, 2):
                    return d.Node([d.Assign(d.Reg(6), d.Const(state.pc))],
                                  outcome=d.Next(d.State(0, 3, None)))
                fact = (facts or {}).get(6)
                value = d.Const(fact[1]) if fact and fact[0] == "c" else d.Reg(6)
                return d.Node([d.Assign(d.Reg(8), value)], outcome=d.Ret(d.Multi([])))

        lf = types.SimpleNamespace(stack_base=None, walk_only=False, jump_regs=set(),
                                   captured_regs=set(), pack_killed=set(), pack_unstable=set())
        prog = d.Program.__new__(d.Program)
        with patch.dict(os.environ, {"DEVIRT_ENTRY_FACTS_BRIDGE": "1"}), \
                patch.object(d, "thread_transport", lambda state, facts, *args: (state, facts, ())):
            _, order, restart = prog._walk(types.SimpleNamespace(kstack_link=None), lf, Stepper(), 100)
        self.assertFalse(restart)
        node = next(node for key, node in order if key[1] == 3)
        self.assertEqual(node.stmts[0].value, d.Reg(6))

    def retry_graph(self, right_value=1, jump_regs=(), mutation=False):
        calls = []
        lf = types.SimpleNamespace(stack_base=None, walk_only=False, jump_regs=set(jump_regs),
                                   captured_regs=set(), pack_killed=set(), pack_unstable=set(),
                                   mutated=False, ov=None)

        class Stepper:
            new_carry = False
            def initial(self):
                return d.State(0, 0, None)
            def step(self, state, prefix, facts=None):
                calls.append((state.pc, facts))
                if state.pc == 0:
                    return d.Node([], cond=d.Reg(99),
                                  then=d.Node([], outcome=d.Next(d.State(0, 1, None))),
                                  els=d.Node([], outcome=d.Next(d.State(0, 2, None))))
                if state.pc in (1, 2):
                    value = 1 if state.pc == 1 else right_value
                    return d.Node([d.Assign(d.Reg(6), d.Const(value))],
                                  outcome=d.Next(d.State(0, 3, None)))
                if facts is None or 6 not in facts or facts[6][0] != "c":
                    lf.mutated = mutation
                    raise d.Unsupported("test concrete-demand boundary")
                return d.Node([d.Assign(d.Reg(8), d.Const(facts[6][1]))],
                              outcome=d.Ret(d.Multi([])))

        prog = d.Program.__new__(d.Program)
        with patch.dict(os.environ, {"DEVIRT_ENTRY_FACTS_BRIDGE": "retry"}), \
                patch.object(d, "thread_transport", lambda state, facts, *args: (state, facts, ())):
            _, order, restart = prog._walk(types.SimpleNamespace(kstack_link=None), lf, Stepper(), 100)
        self.assertFalse(restart)
        return next(node for key, node in order if key[1] == 3), calls

    def test_retry_only_specializes_failed_nodes(self):
        node, calls = self.retry_graph()
        self.assertFalse(getattr(node, "error", None))
        self.assertIsInstance(node.stmts[0].value, d.Const)
        self.assertEqual(node.stmts[0].value.v, 1)
        self.assertTrue(all(facts is None for pc, facts in calls if pc != 3))

    def test_retry_becomes_error_if_join_loses_constant(self):
        node, _ = self.retry_graph(right_value=2)
        self.assertIn("concrete-demand", node.error)

    def test_retry_can_resolve_reused_register_without_bypassing_jval(self):
        node, calls = self.retry_graph(jump_regs={6})
        self.assertFalse(getattr(node, "error", None))
        self.assertTrue(all(facts is None for pc, facts in calls if pc != 3))

    def test_retry_does_not_replay_failed_mutating_decoder(self):
        node, calls = self.retry_graph(mutation=True)
        self.assertTrue(getattr(node, "error", None))
        self.assertTrue(all(facts is None for _, facts in calls))


if __name__ == "__main__":
    unittest.main()
