"""Const wrappers are concrete at numeric-for and register-store boundaries."""
import pathlib
import sys
import types
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "core"))
import luasym as s
from ir import Assign
from obfuscators.luraph_v15 import devirt as d


class ConstBoundaryTests(unittest.TestCase):
    def numeric_for(self, to_bound):
        lifter = types.SimpleNamespace(special={}, out=[])
        it = s.Interp(lifter)
        from_node, to_node, step_node = {}, {}, {}
        values = {id(from_node): 1, id(to_node): to_bound, id(step_node): 1}
        it.eval = lambda node, _scope: values[id(node)]
        stmt = {
            "type": "AstStatFor",
            "from": from_node,
            "to": to_node,
            "step": step_node,
            "var": {"location": "i"},
            "body": {"body": []},
        }
        it.exec_stmt(stmt, s.Scope())

    def test_numeric_for_unwraps_const_bound(self):
        self.numeric_for(s.Const(3))

    def test_numeric_for_symbolic_bound_stays_fail_closed(self):
        with self.assertRaisesRegex(s.Unsupported, "numeric for with symbolic bounds"):
            self.numeric_for(s.Reg(7))

    def register_lifter(self):
        lf = types.SimpleNamespace(out=[], stack_base=None)
        lf.reg_array = lambda _key: None
        lf.value_of = lambda value: value
        lf.emit = lf.out.append
        lf.newindex = d.ProtoLifter.newindex.__get__(lf)
        return lf

    def test_const_register_store_emits_concrete_register_assignment(self):
        lf = self.register_lifter()
        lf.newindex(d.REGFILE, s.Const(5), d.Reg(33), None)
        self.assertEqual(len(lf.out), 1)
        self.assertIsInstance(lf.out[0], Assign)
        self.assertEqual(lf.out[0].target, d.Reg(5))
        self.assertEqual(lf.out[0].value, d.Reg(33))

    def test_symbolic_register_store_remains_fail_closed(self):
        lf = self.register_lifter()
        with self.assertRaisesRegex(s.Unsupported, "symbolic register store"):
            lf.newindex(d.REGFILE, d.Reg(5), d.Reg(33), None)


if __name__ == "__main__":
    unittest.main()
