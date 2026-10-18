"""Concrete Const operands are unwrapped at the concrete-builtin boundary."""
import pathlib
import sys
import types
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "core"))
from ir import CallStmt
from luasym import Builtin, Const
from obfuscators.luraph_v15 import devirt as d


class ConcreteBuiltinTests(unittest.TestCase):
    def setUp(self):
        self.lf = types.SimpleNamespace(out=[], tcount=0, temp_prefix="")
        self.lf.call_builtin = d.ProtoLifter.call_builtin.__get__(self.lf)
        self.lf.new_temp = d.ProtoLifter.new_temp.__get__(self.lf)
        self.lf.value_of = d.ProtoLifter.value_of.__get__(self.lf)
        self.lf.as_expr = lambda value: value
        self.lf.emit = self.lf.out.append

    def call(self, name, args):
        return self.lf.call_builtin(Builtin(name), d.Multi(args), None, False)

    def test_constant_bit32_call_is_evaluated_without_materialization(self):
        result = self.call("bit32.bxor", [Const(10), Const(3)])
        self.assertEqual(result, 9)
        self.assertEqual(self.lf.out, [])

    def test_symbolic_bit32_call_still_materializes(self):
        result = self.call("bit32.bxor", [d.Reg(7), Const(3)])
        self.assertIsInstance(result, d.Multi)
        self.assertIsInstance(result.tail, d.TempTail)
        self.assertTrue(any(isinstance(stmt, CallStmt) for stmt in self.lf.out))

    def test_other_concrete_builtin_unwraps_const(self):
        self.assertEqual(self.call("math.floor", [Const(3.8)]), 3)

    def test_bytes_argument_is_unwrapped(self):
        self.assertEqual(self.call("string.len", [Const(b"abc")]), 3)

    def test_bit32_result_is_a_concrete_upvalue_index(self):
        index = self.call("bit32.bxor", [Const(10), Const(3)])
        self.assertIsInstance(index, int)
        self.assertNotIsInstance(d.UpList().get(index), d.TempVal)


if __name__ == "__main__":
    unittest.main()
