import importlib.util
import json
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
P = ROOT / "tools" / "analyze_r179b_underflow_artifacts.py"
SPEC = importlib.util.spec_from_file_location("r179b", P)
r = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(r)


def identities():
    out = []
    for i in range(64):
        # 64 composite IDs, deliberately only 61 raw state hashes.
        state = f"S{i}" if i < 61 else f"S{i - 61}"
        out.append((f"F{i}", state))
    return out


def error_for(i):
    if i < 49:
        op = "read" if i < 35 else "store"
        reg = 0 if i < 30 else -(i - 29)
        mode = 93 + i % 2
        return f"{op} below the stack VM's frame (register {reg}) (at {mode}:{100+i})"
    if i < 54:
        return f"symbolic next pc/mode: r{i} / 93 (at 93:{500+i})"
    if i < 63:
        return f"needs a constant that is not decoded yet (at 99:{600+i})"
    return "bit32.bxor failed: NoneType (at 223:700)"


def checkpoint(root):
    (root / "summary.json").write_text(json.dumps({
        "stats": {"functions": 78, "errors": 64, "fallbacks": 0},
        "requests": 594,
        "output_sha256": "x",
    }), encoding="utf-8")


def graph(root, with_errors=True):
    rows = []
    for i, (fid, sid) in enumerate(identities()):
        row = {"function_id": fid, "state_id": sid}
        if with_errors:
            row["error"] = error_for(i)
        rows.append(row)
    (root / "graph_error_states.json").write_text(json.dumps({"states": rows}), encoding="utf-8")


class R179BV4Tests(unittest.TestCase):
    def test_61_state_ids_but_64_composite_ids(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td); checkpoint(root); graph(root)
            out = r.analyze([root], 49)
            ids = out["canonical_error_nodes"]
            self.assertEqual(ids["unique_state_ids"], 61)
            self.assertEqual(ids["unique_composite_ids"], 64)
            self.assertEqual(out["summary"]["unique_sites"], 49)

    def test_explicit_nested_composite_adapter(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td); checkpoint(root); graph(root, False)
            rows = []
            for i, (fid, sid) in enumerate(identities()):
                rows.append({"error": error_for(i), "provenance": {"function_id": fid, "state_id": sid}})
            (root / "resolved.json").write_text(json.dumps({"records": rows}), encoding="utf-8")
            out = r.analyze([root], 49)
            self.assertTrue(all(x["provenance_join"] == "explicit_function_state_reference" for x in out["sites"]))

    def test_bare_state_id_cannot_bridge_functions(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td); checkpoint(root); graph(root, False)
            rows = [{"error": error_for(i), "state_id": sid} for i, (_, sid) in enumerate(identities())]
            (root / "resolved.json").write_text(json.dumps(rows), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "refusing bare-state/order/diagnostic"):
                r.analyze([root], 49)

    def test_wrong_function_same_state_does_not_enrich(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td); checkpoint(root); graph(root)
            # S0 exists in F0 and F61. This auxiliary record points to F61 only.
            (root / "frame.jsonl").write_text(json.dumps({
                "kind": "below_stack", "register": 0,
                "function_id": "F61", "state_id": "S0", "stack_base": 7,
            }) + "\n", encoding="utf-8")
            out = r.analyze([root], 49)
            f0 = next(x for x in out["sites"] if x["function_id"] == "F0" and x["state_id"] == "S0")
            self.assertIsNone(f0.get("stack_base"))

    def test_exact_composite_enrichment(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td); checkpoint(root); graph(root)
            (root / "frame.jsonl").write_text(json.dumps({
                "kind": "below_stack", "register": 0,
                "function_id": "F0", "state_id": "S0",
                "stack_base": 7, "jump_regs": [0],
            }) + "\n", encoding="utf-8")
            out = r.analyze([root], 49)
            row = next(x for x in out["sites"] if x["function_id"] == "F0" and x["state_id"] == "S0")
            self.assertEqual(row["stack_base"], 7)
            self.assertTrue(row["in_jump_regs"])

    def test_duplicate_composite_identity_fails(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td); checkpoint(root)
            rows = []
            for i, (fid, sid) in enumerate(identities()):
                rows.append({"function_id": fid, "state_id": sid, "error": error_for(i)})
            rows[-1]["function_id"], rows[-1]["state_id"] = rows[0]["function_id"], rows[0]["state_id"]
            (root / "graph_error_states.json").write_text(json.dumps(rows), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "64 unique \\(function_id, state_id\\) pairs"):
                r.analyze([root], 49)


if __name__ == "__main__":
    unittest.main()
