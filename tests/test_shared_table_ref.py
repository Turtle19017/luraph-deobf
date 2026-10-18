"""SharedTableRef: one emitted declaration per captured tid, fail-closed elsewhere."""
import pathlib
import sys
import types
import unittest
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "core"))
from obfuscators.luraph_v15 import devirt as d
from luasym import Const, Global, LTable
from obfuscators.luraph_v15.devirt import OpaqueFn, SharedFn


class FakeDump:
    def __init__(self):
        self.shared = {}
        self.shared_tables = {}
        self.tid_of = {}
        self.pid_of_table = {}
        self.lazy = set()
        self.buf_loc = {}
        self.misses = {}
        self.overrides = {}
        self.late = {}

    def paths(self):
        return {}

    def miss(self, *_a):
        self.misses[True] = self.misses.get(True, 0) + 1

    def fetch(self, *_a):
        return None

    def same_operand(self, *_a):
        return None


def fake_as_expr(dump):
    """Mirrors the real as_expr for the value kinds used in these tests."""
    def as_expr(v):
        if isinstance(v, OpaqueFn):
            n = dump.shared.setdefault(v.lfid, len(dump.shared) + 1)
            return SharedFn(v, n)
        if isinstance(v, (d.Expr,)):
            return v
        if v is None or isinstance(v, (bool, int, float, bytes)):
            return Const(v)
        raise d.Unsupported("value %r in an expression" % (v,))
    return as_expr


def lifter(dump=None, proto_arrays=(), proto=None):
    dump = dump or FakeDump()
    lf = types.SimpleNamespace(
        dump=dump, proto_arrays=set(proto_arrays), proto=proto,
        library_name=lambda v: None, captured_regs=set(),
        vm=None, vmobj=None, ov_base=None, walk_only=False,
        requests=set(), frame_uses=set(), children=[],
    )
    # Real lifter methods, bound to the minimal stand-in state.
    lf.value_of = d.ProtoLifter.value_of.__get__(lf)
    lf.index = d.ProtoLifter.index.__get__(lf)
    lf.symlist_get = d.ProtoLifter.symlist_get.__get__(lf)
    lf.newindex = d.ProtoLifter.newindex.__get__(lf)
    lf.packed_proto_table = d.ProtoLifter.packed_proto_table.__get__(lf)
    lf.make_closure = d.ProtoLifter.make_closure.__get__(lf)
    lf.as_expr = fake_as_expr(dump)
    lf.cur_ov = lambda: d.Overlay()
    lf.emit = lambda _stmt: None
    return lf


def captured(lf, dump, tid, contents, pid=None, lazy=False):
    table = LTable(contents, tid=tid)
    dump.tid_of[id(table)] = tid
    if pid is not None:
        dump.pid_of_table[tid] = pid
    if lazy:
        dump.lazy.add(tid)
    lf.dump = dump
    return table


class SharedTableRefTests(unittest.TestCase):
    def setUp(self):
        self.dump = FakeDump()
        self.lf = lifter(self.dump)
        self.fn = OpaqueFn(b"fn-1")

    def test_same_tid_yields_one_ref(self):
        table = captured(self.lf, self.dump, 840, {b"__index": self.fn})
        first = self.lf.value_of(table)
        second = self.lf.value_of(table)
        self.assertIsInstance(first, d.SharedTableRef)
        self.assertIs(first, second)
        self.assertEqual(first.name, "luraph_table1")
        self.assertEqual(first.tid, 840)
        self.assertEqual([k for k, _ in first.items], ["__index"])

    def test_repeated_calls_do_not_duplicate_refs(self):
        table = captured(self.lf, self.dump, 840, {b"__index": self.fn})
        refs = [self.lf.value_of(table) for _ in range(11)]
        self.assertEqual(len({id(r) for r in refs}), 1)
        self.assertEqual(len(self.dump.shared_tables), 1)

    def test_distinct_tids_get_distinct_refs(self):
        a = captured(self.lf, self.dump, 1, {b"__index": self.fn})
        b = captured(self.lf, self.dump, 2, {b"__index": self.fn})
        self.assertIsNot(self.lf.value_of(a), self.lf.value_of(b))
        self.assertEqual(self.lf.value_of(a).name, "luraph_table1")
        self.assertEqual(self.lf.value_of(b).name, "luraph_table2")

    def test_proto_table_still_rejects(self):
        table = captured(self.lf, self.dump, 5, {b"__index": self.fn})
        self.lf.proto = table
        with self.assertRaises(d.Unsupported):
            self.lf.value_of(table)

    def test_lazy_and_pid_tables_reject(self):
        lazy = captured(self.lf, self.dump, 7, {b"__index": self.fn}, lazy=True)
        with self.assertRaises(d.Unsupported):
            self.lf.value_of(lazy)
        owned = captured(self.lf, self.dump, 8, {b"__index": self.fn}, pid=3)
        with self.assertRaises(d.Unsupported):
            self.lf.value_of(owned)

    def test_proto_array_member_rejects(self):
        table = captured(self.lf, self.dump, 9, {b"__index": self.fn})
        lf = lifter(self.dump, proto_arrays=[id(table)])
        lf.as_expr = self.lf.as_expr
        with self.assertRaises(d.Unsupported):
            lf.value_of(table)

    def test_ephemeral_table_keeps_previous_lane(self):
        empty = self.lf.value_of(LTable())
        self.assertIsInstance(empty, d.S.NewTable)
        with self.assertRaises(d.Unsupported):
            self.lf.value_of(LTable({b"a": 1}))

    def test_unsupported_key_and_value_reject(self):
        bad_key = captured(self.lf, self.dump, 10, {"a": 1})
        with self.assertRaises(d.Unsupported):
            self.lf.value_of(bad_key)
        bad_value = captured(self.lf, self.dump, 11, {b"k": LTable({1: 2})})
        with self.assertRaises(d.Unsupported):
            self.lf.value_of(bad_value)

    def test_concrete_read_returns_captured_value(self):
        table = captured(self.lf, self.dump, 12, {b"__index": self.fn})
        ref = self.lf.value_of(table)
        self.assertIs(self.lf.index(ref, b"__index", None), self.fn)

    def test_symbolic_read_of_shared_ref_is_dynamic_index(self):
        table = captured(self.lf, self.dump, 14, {b"__index": self.fn})
        ref = self.lf.value_of(table)
        expr = self.lf.index(ref, d.Reg(3), None)
        self.assertIsInstance(expr, d.Index)
        self.assertIs(expr.obj, ref)
        self.assertIsInstance(expr.key, d.Reg)

    def test_const_key_unwraps_for_pack_then_concrete_table(self):
        pack = d.SymList([Const(i) for i in range(1, 21)] + [Const(57)], None, nkey=b"n")
        table = LTable({57: b"HIT"}, tid=18)

        value = self.lf.index(pack, Const(21), None)
        self.assertIsInstance(value, Const)
        self.assertEqual(value.v, 57)
        self.assertEqual(self.lf.index(table, value, None), b"HIT")

    def test_const_literal_keys_cover_int_float_and_bytes(self):
        table = LTable({57: b"HIT", b"x": 123}, tid=19)
        self.assertEqual(self.lf.index(table, Const(57), None), b"HIT")
        self.assertEqual(self.lf.index(table, Const(57.0), None), b"HIT")
        self.assertEqual(self.lf.index(table, Const(b"x"), None), 123)

    def test_reg_key_remains_symbolic_for_shared_and_fails_for_concrete(self):
        table = LTable({57: b"HIT"}, tid=20)
        with self.assertRaises(d.Unsupported):
            self.lf.index(table, d.Reg(4), None)

        ref = d.SharedTableRef(table, 1, [])
        expr = self.lf.index(ref, d.Reg(4), None)
        self.assertIsInstance(expr, d.Index)
        self.assertIs(expr.obj, ref)
        self.assertIsInstance(expr.key, d.Reg)

    def test_packed_proto_adapter_reifies_valid_fixed_list(self):
        packed = d.SymList([Const(i) for i in range(1, 30)] + [Const(57)], None, nkey=b"n")
        table = self.lf.packed_proto_table(packed)
        self.assertIsInstance(table, LTable)
        self.assertIsNone(table.tid)
        self.assertEqual(table.get(30), 57)
        self.assertEqual(table.get(b"n"), 30)

    def test_packed_proto_reifies_empty_descriptor_literal(self):
        descriptor = d.S.NewTable()
        descriptors = d.SymList([descriptor], None, nkey=b"n")
        table = self.lf.packed_proto_table(d.SymList([descriptors], None))
        value = table.get(1).items[0]
        self.assertIsInstance(value, LTable)
        self.assertEqual(d.S.Interp(self.lf).unop("Len", value), 0)
        self.assertIs(descriptors.items[0], descriptor)

    def test_packed_proto_empty_literal_aliases_are_preserved(self):
        descriptor = d.S.NewTable()
        table = self.lf.packed_proto_table(d.SymList([descriptor, descriptor], None))
        self.assertIs(table.get(1), table.get(2))

    def test_gated_pack_provenance_restores_table_identity_and_hidden_fields(self):
        hidden = LTable({1: 42}, tid=51)
        source = LTable({0: hidden, 1: 20, b"n": 7}, tid=52)
        with patch.dict("os.environ", {"DEVIRT_PACKED_TABLE_PROVENANCE": "1"}):
            packed = self.lf.value_of(source)
            restored = self.lf.packed_proto_table(packed)
        self.assertIs(restored, source)
        self.assertIs(restored.get(0), hidden)
        self.assertEqual(restored.get(b"n"), 7)
        self.assertEqual(restored.tid, 52)

    def test_gated_pack_provenance_restores_nested_empty_descriptor(self):
        descriptor = LTable({}, tid=61)
        source = LTable({1: descriptor}, tid=62)
        with patch.dict("os.environ", {"DEVIRT_PACKED_TABLE_PROVENANCE": "1"}):
            packed = self.lf.value_of(source)
            proto = self.lf.packed_proto_table(d.SymList([packed], None))
        self.assertIs(proto.get(1), source)
        self.assertIs(proto.get(1).get(1), descriptor)

    def test_gated_pack_provenance_rejects_a_changed_materialization(self):
        source = LTable({1: 20}, tid=72)
        with patch.dict("os.environ", {"DEVIRT_PACKED_TABLE_PROVENANCE": "1"}):
            packed = self.lf.value_of(source)
            packed.items[0] = Const(99)
            self.assertIsNone(self.lf.packed_proto_table(packed))
        self.assertEqual(source.get(1), 20)

    def test_general_closed_proto_arrays_keep_pack_semantics_and_aliases(self):
        array = d.SymList([Const(10), Const(20)], None, nkey=b"n")
        proto = self.lf.packed_proto_table(d.SymList([array, array], None))
        result = proto.get(1)
        self.assertIsInstance(result, d.SymList)
        self.assertIs(result, proto.get(2))
        self.assertEqual(result.items[0].v, 10)
        self.assertEqual(result.nkey, b"n")
        self.assertEqual(array.items[0].v, 10)

    def test_packed_proto_does_not_reify_dynamic_or_nonempty_tables(self):
        nonempty = d.S.NewTable([(Const(1), d.Reg(3))])
        open_pack = d.SymList([d.S.NewTable()], d.TempTail("dynamic"), nkey=b"n")
        captured_table = LTable({1: 2}, tid=42)
        table = self.lf.packed_proto_table(d.SymList([nonempty, open_pack, captured_table], None))
        self.assertIs(table.get(1), nonempty)
        self.assertIs(table.get(2), open_pack)
        self.assertIs(table.get(3), captured_table)

    def test_packed_proto_adapter_rejects_open_or_unsupported_shapes(self):
        tail = d.SymList([Const(1)], d.TempTail(1), nkey=b"n")
        extra = d.SymList([Const(1)], None, nkey=b"n")
        extra.extra[b"x"] = Const(2)
        bad_nkey = d.SymList([Const(1)], None, nkey=b"other")
        missing = d.SymList([Const(1), d.Missing(2)], None, nkey=b"n")
        for packed in (tail, extra, bad_nkey, missing):
            with self.subTest(packed=type(packed).__name__):
                self.assertIsNone(self.lf.packed_proto_table(packed))

    def test_packed_proto_feature_gate_is_off_by_default(self):
        packed = d.SymList([Const(1)], None)
        vm = types.SimpleNamespace(proto_index=lambda: 0, upvals_index=lambda: 1,
                                   maker={"args": []})
        with patch.dict("os.environ", {"DEVIRT_PACKED_PROTO": ""}):
            with self.assertRaisesRegex(d.Unsupported, "closure of non-proto"):
                self.lf.make_closure(d.Multi([packed]), vm)

    def test_make_closure_keeps_existing_ltable_proto(self):
        proto = LTable({b"p": 7}, tid=77)
        vm = types.SimpleNamespace(proto_index=lambda: 0, upvals_index=lambda: 1,
                                   maker={"args": []})
        closure = self.lf.make_closure(d.Multi([proto]), vm)
        self.assertIs(closure.proto, proto)

    def test_store_into_shared_ref_rejects(self):
        lf = lifter(self.dump)
        ref = d.SharedTableRef(LTable({}, tid=13), 1, [])
        with self.assertRaises(d.Unsupported):
            lf.newindex(ref, b"k", 1, None)

    def test_identity_equality_folds_by_tid(self):
        a = d.SharedTableRef(LTable({}, tid=20), 1, [])
        b = d.SharedTableRef(LTable({}, tid=20), 1, [])
        c = d.SharedTableRef(LTable({}, tid=21), 2, [])
        self.assertEqual(d.eval_fact(d.Bin("CompareEq", a, b), {}), ("c", True))
        self.assertEqual(d.eval_fact(d.Bin("CompareNe", a, c), {}), ("c", True))

    def test_prelude_declares_tables_once_after_runtime_fns(self):
        source = pathlib.Path(d.__file__).read_text(encoding="utf-8")
        self.assertIn('local %s = {" % ref.name', source)
        self.assertLess(source.index("luraph_runtime%d"), source.index("luraph_table"))


if __name__ == "__main__":
    unittest.main()
