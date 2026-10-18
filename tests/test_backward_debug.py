"""Diagnostic provenance meets all incoming paths conservatively."""
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "core"))
from obfuscators.luraph_v15 import devirt as d
from obfuscators.luraph_v15.backward_debug import census


class BackwardDebugTests(unittest.TestCase):
    def run_graph(self, left, right, complete=True):
        entry, a, b, fail = [(0, i) for i in range(4)]
        nodes = {entry: d.Node([]), a: d.Node(left), b: d.Node(right)}
        reverse = {a: {entry}, b: {entry}, fail: {a, b}}
        return census(d, nodes, reverse, [(fail, 5, ())], entry, {},
                      complete=complete)[0]

    def test_agreeing_constants_join(self):
        report = self.run_graph([d.Assign(d.Reg(5), d.Const(2))],
                                [d.Assign(d.Reg(5), d.Const(2))])
        self.assertEqual(report["result"], ("CONST", 2))
        self.assertEqual(report["incoming_predecessors"], 2)

    def test_disagreeing_constants_are_unknown(self):
        report = self.run_graph([d.Assign(d.Reg(5), d.Const(2))],
                                [d.Assign(d.Reg(5), d.Const(3))])
        self.assertEqual(report["result"][0], "UNKNOWN")

    def test_constant_and_entry_are_unknown(self):
        report = self.run_graph([d.Assign(d.Reg(5), d.Const(2))], [])
        self.assertEqual(report["result"][0], "UNKNOWN")

    def test_alias_uses_value_before_assignment(self):
        seq = [d.Assign(d.Reg(8), d.Const(2)), d.Assign(d.Reg(5), d.Reg(8)),
               d.Assign(d.Reg(8), d.Const(99))]
        report = self.run_graph(seq, seq)
        self.assertEqual(report["result"], ("CONST", 2))

    def test_indirect_store_clobbers_proof(self):
        seq = [d.Assign(d.Reg(5), d.Const(2)),
               d.Assign(d.Index(d.Reg(9), d.Reg(10)), d.Const(0))]
        self.assertEqual(self.run_graph(seq, seq)["result"][0], "UNKNOWN")

    def test_incomplete_walk_withholds_constant(self):
        seq = [d.Assign(d.Reg(5), d.Const(2))]
        self.assertEqual(self.run_graph(seq, seq, complete=False)["result"][0], "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
