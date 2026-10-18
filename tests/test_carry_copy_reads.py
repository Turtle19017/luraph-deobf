"""Dead local-copy initializers do not force VM temporaries into State.locs."""
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "core"))
from obfuscators.luraph_v15.devirt import useful_scope_reads


class CarryCopyReadTests(unittest.TestCase):
    def test_unused_local_copy_is_not_a_carried_read(self):
        self.assertEqual(useful_scope_reads({"H"}, {("H", "copy")}, {"copy": "V"}, set()), set())

    def test_used_local_copy_keeps_source_read(self):
        reads = {("H", "copy"), ("V", "use")}
        self.assertEqual(useful_scope_reads({"H"}, reads, {"copy": "V"}, set()), {"H"})

    def test_any_other_source_read_keeps_dependency(self):
        reads = {("H", "copy"), ("H", "direct-use")}
        self.assertEqual(useful_scope_reads({"H"}, reads, {"copy": "V"}, set()), {"H"})

    def test_captured_copy_target_keeps_source_read(self):
        self.assertEqual(useful_scope_reads({"H"}, {("H", "copy")}, {"copy": "V"}, {"V"}), {"H"})

    def test_unattributed_scope_read_remains_conservative(self):
        self.assertEqual(useful_scope_reads({"H"}, set(), {}, set()), {"H"})

    def test_read_after_overwrite_does_not_keep_dead_copy(self):
        events = [("read", "H", "copy"), ("write", "V", None),
                  ("write", "V", None), ("read", "V", "later")]
        self.assertEqual(useful_scope_reads({"H"}, set(), {"copy": "V"}, set(), events), set())

    def test_read_before_overwrite_keeps_copy_dependency(self):
        events = [("read", "H", "copy"), ("write", "V", None),
                  ("read", "V", "use"), ("write", "V", None)]
        self.assertEqual(useful_scope_reads({"H"}, set(), {"copy": "V"}, set(), events), {"H"})

    def test_later_source_reads_do_not_create_entry_dependencies(self):
        events = [("read", "H", "copy"), ("write", "V", None),
                  ("write", "H", None), ("read", "H", "new-value")]
        self.assertEqual(useful_scope_reads({"H"}, set(), {"copy": "V"}, set(), events), set())


if __name__ == "__main__":
    unittest.main()
