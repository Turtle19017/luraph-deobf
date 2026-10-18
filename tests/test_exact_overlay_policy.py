from pathlib import Path
import sys
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
from obfuscators.luraph_v15 import exact_overlay as policy


class ExactOverlayTests(unittest.TestCase):
    def test_full_path_and_operand_are_not_interchangeable(self):
        source = {"31,b,1@7": {"s": "6869"}, "31,b,2@7": 8}
        accepted, rejected = policy.select_exact_scalars(["31,b,1@7"], source, {"31,b,1@7", "31,b,2@7"})
        self.assertEqual(accepted, {"31,b,1@7": b"hi"})
        self.assertEqual(rejected, {})

    def test_table_function_and_vector_labels_are_not_transplanted(self):
        source = {"t": {"t": 12}, "f": {"lf": 9}, "v": {"vec": [1, 2, 3]}}
        accepted, rejected = policy.select_exact_scalars(source, source, set(source))
        self.assertFalse(accepted)
        self.assertEqual(set(rejected), set(source))

    def test_false_zero_and_empty_string_are_valid_values(self):
        source = {"false": False, "zero": 0, "empty": {"s": ""}, "nil": None}
        accepted, rejected = policy.select_exact_scalars(source, source, set(source))
        self.assertEqual(accepted, {"false": False, "zero": 0, "empty": b""})
        self.assertIn("nil", rejected)

    def test_missing_key_or_not_current_request_is_rejected(self):
        accepted, rejected = policy.select_exact_scalars(["missing", "not_requested"], {"not_requested": 7}, {"missing"})
        self.assertFalse(accepted)
        self.assertEqual(len(rejected), 2)


if __name__ == "__main__":
    unittest.main()
