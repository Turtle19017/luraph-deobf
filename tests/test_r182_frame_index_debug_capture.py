import os
import pathlib
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "core"))
import luasym as S


class FakeLifter:
    def __init__(self):
        self.special = {}
        self.last_frame_failure = None

    def index(self, obj, key, interp):
        self.last_frame_failure = {"kind": "below_stack", "register": key}
        raise S.Unsupported("synthetic underflow")


class FrameIndexDebugCaptureTests(unittest.TestCase):
    def test_call_fingerprint_keeps_argument_asts(self):
        node = {
            "type": "AstExprCall",
            "location": "call",
            "func": {"type": "AstExprLocal", "location": "f-use",
                     "local": {"name": "v", "location": "f-decl"}},
            "args": [
                {"type": "AstExprConstantNumber", "location": "a0", "value": 7},
                {"type": "AstExprLocal", "location": "a1-use",
                 "local": {"name": "x", "location": "x-decl"}},
            ],
        }
        out = S._debug_ast_index(node)
        self.assertEqual(out["argc"], 2)
        self.assertEqual(len(out["args"]), 2)
        self.assertEqual(out["args"][0]["value"], 7)
        self.assertEqual(out["args"][1]["name"], "x")
        self.assertEqual(out["args"][1]["decl"], "x-decl")

    def test_binary_debug_captures_evaluated_operands_and_result(self):
        lifter = FakeLifter()
        interp = S.Interp(lifter)
        scope = S.Scope()
        node = {
            "type": "AstExprBinary", "op": "Sub", "location": "sub",
            "left": {"type": "AstExprConstantNumber", "value": 3},
            "right": {"type": "AstExprConstantNumber", "value": 4},
        }
        with mock.patch.dict(os.environ, {"DEVIRT_FRAME_DEBUG": "1"}):
            result = interp.eval(node, scope)
        self.assertEqual(result, -1)
        rec = interp.last_frame_binary_eval
        self.assertEqual(rec["op"], "Sub")
        self.assertEqual(rec["left"], {"type": "int", "value": 3})
        self.assertEqual(rec["right"], {"type": "int", "value": 4})
        self.assertEqual(rec["result"], {"type": "int", "value": -1})

    def test_underflow_attaches_matching_binary_eval(self):
        lifter = FakeLifter()
        interp = S.Interp(lifter)
        scope = S.Scope()
        frame = object()
        scope.vars["frame-decl"] = frame
        idx = {
            "type": "AstExprBinary", "op": "Sub", "location": "sub",
            "left": {"type": "AstExprConstantNumber", "value": 3},
            "right": {"type": "AstExprConstantNumber", "value": 4},
        }
        node = {
            "type": "AstExprIndexExpr", "location": "index-use",
            "expr": {"type": "AstExprLocal", "location": "frame-use",
                     "local": {"name": "frame", "location": "frame-decl"}},
            "index": idx,
        }
        with mock.patch.dict(os.environ, {"DEVIRT_FRAME_DEBUG": "1"}):
            with self.assertRaises(S.Unsupported):
                interp.eval(node, scope)
        rec = lifter.last_frame_failure
        self.assertEqual(rec["index_ast"]["op"], "Sub")
        self.assertEqual(rec["index_eval"]["left"]["value"], 3)
        self.assertEqual(rec["index_eval"]["right"]["value"], 4)
        self.assertEqual(rec["index_eval"]["result"]["value"], -1)

    def test_debug_off_does_not_capture_binary_values(self):
        lifter = FakeLifter()
        interp = S.Interp(lifter)
        scope = S.Scope()
        node = {
            "type": "AstExprBinary", "op": "Sub", "location": "sub",
            "left": {"type": "AstExprConstantNumber", "value": 3},
            "right": {"type": "AstExprConstantNumber", "value": 4},
        }
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(interp.eval(node, scope), -1)
        self.assertIsNone(interp.last_frame_binary_eval)


if __name__ == "__main__":
    unittest.main()
