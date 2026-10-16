from __future__ import annotations

import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from decode_a321_phase4_through_fourth_table import integer_path  # noqa: E402


CASES = {
    1: bytes([0x05]),
    2: bytes([0x81, 0x02]),
    3: bytes([0x81, 0x82, 0x03]),
    4: bytes([0x81, 0x82, 0x83, 0x04]),
}

EXPECTED_PATHS = {
    "C": {
        1: [388, 395, 485],
        2: [388, 148, 498, 485],
        3: [388, 148, 274, 105, 485],
        4: [388, 148, 274, 65, 485],
    },
    "D": {
        1: [485, 199, 340],
        2: [485, 510, 511, 340],
        3: [485, 510, 208, 326, 340],
        4: [485, 510, 208, 122, 340],
    },
    "E": {
        1: [340, 26, 129],
        2: [340, 230, 206, 129],
        3: [340, 230, 441, 424, 129],
        4: [340, 230, 441, 125, 129],
    },
    "FOURTH": {
        1: [43, 80, 475, 169],
        2: [43, 200, 371, 475, 169],
        3: [43, 200, 18, 120, 475, 169],
        4: [43, 200, 18, 487, 475, 169],
    },
}


class Phase5IntegerPathTests(unittest.TestCase):
    def test_all_width_paths(self):
        for family, widths in EXPECTED_PATHS.items():
            for width, expected_path in widths.items():
                with self.subTest(family=family, width=width):
                    value, end, got_width, path = integer_path(
                        CASES[width], 0, family
                    )
                    self.assertEqual(got_width, width)
                    self.assertEqual(end, width)
                    self.assertEqual(path, expected_path)
                    self.assertGreaterEqual(value, 0)

    def test_block1_scalar_c(self):
        value, end, width, path = integer_path(bytes.fromhex("8102"), 0, "C")
        self.assertEqual((value, end, width), (130, 2, 2))
        self.assertEqual(path, [388, 148, 498, 485])

    def test_block1_scalar_d(self):
        value, end, width, path = integer_path(bytes.fromhex("44"), 0, "D")
        self.assertEqual((value, end, width), (68, 1, 1))
        self.assertEqual(path, [485, 199, 340])

    def test_block1_scalar_e(self):
        value, end, width, path = integer_path(bytes.fromhex("1d"), 0, "E")
        self.assertEqual((value, end, width), (29, 1, 1))
        self.assertEqual(path, [340, 26, 129])


if __name__ == "__main__":
    unittest.main()
