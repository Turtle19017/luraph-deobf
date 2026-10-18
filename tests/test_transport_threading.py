"""Strict state/fact preservation and worklist graph consistency regressions."""
import os
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
from obfuscators.luraph_v15 import devirt as d


class TransportTests(unittest.TestCase):
    def setUp(self):
        self.s = d.State(7, 10, None, jregs=((1, 12),), locs=(("sp", 3),))
        self.ns = d.State(7, 11, None, jregs=((1, 12),), locs=(("sp", 3),))
        self.node = d.Node([], outcome=d.Next(self.ns))
        self.facts = {1: ("c", 12)}
        self.lf = types.SimpleNamespace(captured_regs=set())

    def check(self, ns=None, node=None, before=None, after=None):
        return d.transparent_transport(node or self.node, self.s,
            [(ns or self.ns, self.facts if after is None else after)],
            self.facts if before is None else before, None)

    def test_exact_fallthrough_is_transparent(self):
        self.assertTrue(self.check())

    def test_ir_is_not_transparent(self):
        self.node.stmts = [d.Assign(d.Reg(1), d.Const(1))]
        self.assertFalse(self.check())

    def test_changed_facts_are_not_transparent(self):
        self.assertFalse(self.check(after={1: ("c", 13)}))

    def test_locs_jregs_packs_overlay_and_kdepth_changes_stop(self):
        for field, value in (
                ("locs", (("sp", 4),)), ("jregs", ((1, 13),)),
                ("packs", ((2, d.S.SymList([d.Const(3)])),)),
                ("ov", d.Overlay()), ("kstack", d.LTable())):
            with self.subTest(field=field):
                ns = d.State(7, 11, None, jregs=self.s.jregs, locs=self.s.locs)
                if field == "ov":
                    value.h = 123
                setattr(ns, field, value)
                self.assertFalse(self.check(ns=ns, node=d.Node([], outcome=d.Next(ns))))

    def test_conditional_is_not_transparent_even_if_one_edge_is_known(self):
        self.node.cond = d.Const(True)
        self.assertFalse(self.check())

    def test_error_and_overlay_effect_flags_stop(self):
        self.node.error = "unknown semantics"
        self.assertFalse(self.check())
        del self.node.error
        self.node.transport_effects = True
        self.assertFalse(self.check())

    def test_mode_change_and_nonsequential_pc_stop(self):
        self.ns.mode = 8
        self.assertFalse(self.check())
        self.ns.mode, self.ns.pc = 7, 12
        self.assertFalse(self.check())

    def test_requires_exactly_one_successor_and_next_outcome(self):
        self.assertFalse(d.transparent_transport(self.node, self.s, [], self.facts, None))
        self.assertFalse(d.transparent_transport(self.node, self.s,
            [(self.ns, self.facts), (self.ns, self.facts)], self.facts, None))
        self.node.outcome = d.Ret(d.Multi([]))
        self.assertFalse(self.check())

    def test_branch_children_are_not_transparent(self):
        self.node.then = d.Node([])
        self.assertFalse(self.check())

    def test_thread_stops_at_pop_and_preserves_facts(self):
        def get_node(s):
            ns = d.State(s.mode, s.pc + 1, None, jregs=s.jregs, locs=s.locs)
            if s.pc == 13:
                ns.pc, ns.locs = 100, (("sp", 2),)
            return d.Node([], outcome=d.Next(ns))
        end, facts, path = d.thread_transport(self.s, self.facts, None, get_node, self.lf)
        self.assertEqual(end.pc, 13)
        self.assertEqual(end.locs, self.s.locs)
        self.assertEqual(facts, self.facts)
        self.assertEqual([key[1] for key in path], [10, 11, 12])

    def test_cycle_terminates_without_dropping_boundary(self):
        calls = []
        def get_node(s):
            calls.append(s.pc)
            ns = d.State(s.mode, 11 if s.pc == 10 else 10, None,
                         jregs=s.jregs, locs=s.locs)
            return d.Node([], outcome=d.Next(ns))
        end, _, path = d.thread_transport(self.s, self.facts, None, get_node, self.lf)
        self.assertEqual(end.pc, 11)
        self.assertEqual(calls, [10, 11])
        self.assertEqual(len(path), 1)

    def test_chain_limit_retains_the_next_state(self):
        def get_node(s):
            return d.Node([], outcome=d.Next(d.State(s.mode, s.pc + 1, None,
                                                   jregs=s.jregs, locs=s.locs)))
        end, _, path = d.thread_transport(self.s, self.facts, None, get_node, self.lf,
                                          max_chain=3)
        self.assertEqual(end.pc, 13)
        self.assertEqual(len(path), 3)

    def test_pending_carry_restart_stops_threading(self):
        end, facts, path = d.thread_transport(self.s, self.facts, None,
                                               lambda state: None, self.lf)
        self.assertIs(end, self.s)
        self.assertEqual(facts, self.facts)
        self.assertFalse(path)

    def test_in_place_source_state_mutation_stops_threading(self):
        def get_node(s):
            s.locs = (("sp", 4),)
            ns = d.State(s.mode, s.pc + 1, None, jregs=s.jregs, locs=s.locs)
            return d.Node([], outcome=d.Next(ns))
        end, _, path = d.thread_transport(self.s, self.facts, None, get_node, self.lf)
        self.assertIs(end, self.s)
        self.assertFalse(path)

    def test_propagation_restart_is_not_transparent(self):
        with patch.object(d, "propagate", return_value="restart required"):
            end, _, path = d.thread_transport(self.s, self.facts, None,
                lambda state: self.node, self.lf)
        self.assertIs(end, self.s)
        self.assertFalse(path)

    def test_redirect_updates_branch_ir_outcomes(self):
        replacement = d.State(7, 20, None, jregs=self.ns.jregs, locs=self.ns.locs)
        source = d.Node([], cond=d.Reg(2), then=d.Node([], outcome=d.Next(self.ns)),
                        els=d.Node([], outcome=d.Next(self.s)))
        d.redirect_transport(source, self.ns, replacement)
        self.assertIs(source.then.outcome.state, replacement)
        self.assertIs(source.els.outcome.state, self.s)


class WorklistTransportTests(unittest.TestCase):
    def walk(self):
        # Generic synthetic VM: nine serial callers, each passing through forty
        # NOPs to a genuine pop/jump hub. No target PCs, opcodes or snapshots.
        class Stepper:
            new_carry = False
            carry = {"sp"}
            def initial(self):
                return d.State(7, 0, None, jregs=((1, 0),), locs=(("sp", 0),))
            def step(self, s, prefix, facts=None):
                counter = dict(s.jregs)[1]
                if s.pc < 10:
                    if counter == 9:
                        return d.Node([], outcome=d.Ret(d.Multi([])))
                    ns = d.State(7, 10, None, jregs=((1, counter + 1),),
                                 locs=(("sp", counter + 1),))
                elif 10 <= s.pc < 50:
                    ns = d.State(7, s.pc + 1, None, jregs=s.jregs, locs=s.locs)
                else:
                    ns = d.State(7, counter, None, jregs=s.jregs,
                                 locs=(("sp", s.locs[0][1] - 1),))
                return d.Node([], outcome=d.Next(ns))
        prog = d.Program.__new__(d.Program)
        lf = types.SimpleNamespace(stack_base=0, walk_only=False, jump_regs=set(),
                                   captured_regs=set(), pack_killed=set(), pack_unstable=set())
        with patch.dict(os.environ, {"DEVIRT_STACK_DEBUG": ""}):
            _, order, restart = prog._walk(types.SimpleNamespace(kstack_link=None), lf, Stepper(), 1000)
        return prog, order, restart

    def test_nine_depths_reach_pop_without_enqueuing_transport_prefix(self):
        prog, order, restart = self.walk()
        self.assertFalse(restart)
        self.assertFalse([n.error for _, n in order if getattr(n, "error", None)])
        self.assertEqual(sum(key[1] == 50 for key, _ in order), 9)
        self.assertFalse([key for key, _ in order if 10 <= key[1] < 50])
        self.assertEqual(prog.walk_metrics["skipped_transport_nodes"], 360)
        self.assertLess(len(order), 25)
        keys = {key for key, _ in order}
        for _, node in order:
            if isinstance(node.outcome, d.Next):
                self.assertIn(node.outcome.state.key(None), keys)

    def test_without_threading_old_guard_rejects_ninth_prefix_depth(self):
        with patch.object(d, "thread_transport", lambda state, facts, *args: (state, facts, ())):
            _, order, _ = self.walk()
        self.assertTrue(any("stack depth" in getattr(n, "error", "") for _, n in order))


if __name__ == "__main__":
    unittest.main()
