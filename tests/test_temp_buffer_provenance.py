"""TempVal buffer provenance preserves Buf identity and overlay writes."""
import pathlib
import sys
import types
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "core"))
from ir import CallStmt
from luasym import Buf, Builtin, Multi, TempVal, Unsupported
from obfuscators.luraph_v15 import devirt as d


def buffer_lifter(temp_bufs=None, overlay=None):
    lf = types.SimpleNamespace(
        out=[], temp_prefix="buf_", tcount=0,
        temp_bufs=temp_bufs if temp_bufs is not None else {},
        ov_base=overlay if overlay is not None else d.Overlay(), ov=None,
    )
    for method in ("new_temp", "as_expr", "value_of", "call_builtin", "resolve_temp_buf",
                   "cur_ov", "write_ov", "buffer_op", "_ov_keys"):
        setattr(lf, method, getattr(d.ProtoLifter, method).__get__(lf))
    lf.emit = lf.out.append
    return lf


class TempBufferProvenanceTests(unittest.TestCase):
    def test_tempval_buffer_read_uses_original_buf(self):
        lf = buffer_lifter()
        buf = Buf(b"abc")
        temp = lf.value_of(buf)
        self.assertIsInstance(temp, TempVal)
        self.assertTrue(any(isinstance(stmt, CallStmt) for stmt in lf.out))
        self.assertEqual(
            lf.call_builtin(Builtin("buffer.readu8"), Multi([temp, 1]), None, False),
            ord("b"),
        )

    def test_write_through_temp_is_visible_to_read(self):
        lf = buffer_lifter()
        buf = Buf(b"abc")
        temp = lf.value_of(buf)
        lf.call_builtin(Builtin("buffer.writeu8"), Multi([temp, 1, 90]), None, False)
        self.assertEqual(
            lf.call_builtin(Builtin("buffer.readu8"), Multi([temp, 1]), None, False),
            90,
        )
        self.assertEqual(buf.data[1], ord("b"))

    def test_two_temps_for_same_buf_share_overlay_identity(self):
        lf = buffer_lifter()
        buf = Buf(b"abc")
        first = lf.value_of(buf)
        second = lf.value_of(buf)
        self.assertIs(lf.resolve_temp_buf(first), buf)
        self.assertIs(lf.resolve_temp_buf(second), buf)
        lf.call_builtin(Builtin("buffer.writeu8"), Multi([first, 2, 77]), None, False)
        self.assertEqual(
            lf.call_builtin(Builtin("buffer.readu8"), Multi([second, 2]), None, False),
            77,
        )

    def test_provenance_is_shared_across_proto_lifters(self):
        provenance = {}
        overlay = d.Overlay()
        producer = buffer_lifter(provenance, overlay)
        consumer = buffer_lifter(provenance, overlay)
        buf = Buf(b"abc")
        temp = producer.value_of(buf)
        self.assertIs(consumer.resolve_temp_buf(temp), buf)

    def test_tempval_without_provenance_remains_fail_closed(self):
        lf = buffer_lifter()
        with self.assertRaisesRegex(Unsupported, "builtin buffer.readu8 on symbolic values"):
            lf.call_builtin(Builtin("buffer.readu8"), Multi([TempVal("unknown", 1), 0]), None, False)


if __name__ == "__main__":
    unittest.main()
