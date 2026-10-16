from __future__ import annotations

import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from decode_a321_post_table_branch import secondary_integer_path  # noqa: E402


class SecondaryIntegerPathTests(unittest.TestCase):
    def test_width1_low_first_byte_goes_328(self):
        value, end, width, path = secondary_integer_path(bytes([6]), 0)
        self.assertEqual((value, end, width), (6, 1, 1))
        self.assertEqual(path, [10, 328, 237])

    def test_width2_high_then_low_goes_425_88(self):
        value, end, width, path = secondary_integer_path(bytes([0xA2, 0x65]), 0)
        self.assertEqual((value, end, width), (4453, 2, 2))
        self.assertEqual(path, [10, 425, 88, 237])

    def test_width3_goes_425_473_482(self):
        data = bytes([0x81, 0x82, 0x03])
        value, end, width, path = secondary_integer_path(data, 0)
        self.assertEqual(width, 3)
        self.assertEqual(end, 3)
        self.assertEqual(path, [10, 425, 473, 482, 237])
        self.assertEqual(value, 128 + 2 + 3 * 16384)

    def test_width4_goes_425_473_101(self):
        data = bytes([0x81, 0x82, 0x83, 0x04])
        value, end, width, path = secondary_integer_path(data, 0)
        self.assertEqual(width, 4)
        self.assertEqual(end, 4)
        self.assertEqual(path, [10, 425, 473, 101, 237])
        self.assertGreater(value, 0)


if __name__ == "__main__":
    unittest.main()
