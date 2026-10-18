"""Constant wrappers are concrete operands for interpreter binary operators."""
import pathlib
import sys
import types
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "core"))
import luasym as s


class ConstBinopTests(unittest.TestCase):
    def setUp(self):
        def as_expr(value):
            return value if isinstance(value, s.Expr) else s.Const(value)

        lifter = types.SimpleNamespace(
            sym_binop=lambda op, a, b: s.Bin(op, as_expr(a), as_expr(b)))
        self.it = s.Interp(lifter)

    def test_concrete_arithmetic_folds(self):
        self.assertEqual(self.it.binop("Sub", s.Const(10), s.Const(3)), 7)
        self.assertEqual(self.it.binop("Add", s.Const(10), s.Const(3)), 13)
        self.assertEqual(self.it.binop("Mul", s.Const(4), s.Const(5)), 20)

    def test_mixed_symbolic_operand_stays_symbolic(self):
        result = self.it.binop("Sub", s.Const(10), s.Reg(2))
        self.assertIsInstance(result, s.Bin)
        self.assertEqual(result.op, "Sub")
        self.assertIsInstance(result.a, s.Const)
        self.assertEqual(result.a.v, 10)
        self.assertIsInstance(result.b, s.Reg)

    def test_constant_comparison_folds(self):
        self.assertIs(self.it.binop("CompareEq", s.Const(5), s.Const(5)), True)


if __name__ == "__main__":
    unittest.main()
