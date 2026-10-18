"""Large literal packs retain validation; structural/edge explosion stays bounded."""
import pathlib
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "core"))
from obfuscators.luraph_v15 import devirt as d
from test_shared_table_ref import lifter


class PackedSourceWorkTests(unittest.TestCase):
    def test_over_100k_immutable_leaves_do_not_consume_container_budget(self):
        packed = d.SymList([d.Const(i) for i in range(100005)], None)
        validator = d.PackedSourceValidator()
        self.assertTrue(validator.validate(packed))
        self.assertEqual(validator.checked, 100006)
        self.assertEqual(validator.containers, 1)
        with patch.dict("os.environ", {"DEVIRT_PACKED_TABLE_PROVENANCE": "1"}):
            proto = lifter().packed_proto_table(packed)
        self.assertIsInstance(proto, d.LTable)
        self.assertEqual(proto.get(100005), 100004)

    def test_mismatch_after_100k_checked_leaves_is_still_rejected(self):
        lf = lifter()
        with patch.dict("os.environ", {"DEVIRT_PACKED_TABLE_PROVENANCE": "1"}):
            bad = lf.value_of(d.LTable({1: 7}, tid=71))
            bad.items[0] = d.Const(8)
            # LIFO scan reaches the nested bad source only AFTER all leaves.
            nested = d.SymList([d.SymList([bad], None)], None)
            packed = d.SymList([nested] + [d.Const(i) for i in range(100005)], None)
            validator = d.PackedSourceValidator()
            self.assertFalse(validator.validate(packed))
            self.assertGreater(validator.checked, 100000)
            self.assertEqual(validator.failure, "source_items_changed")
            self.assertIsNone(lf.packed_proto_table(packed))

    def test_provenance_marker_on_late_leaf_is_not_skipped(self):
        leaf = d.Const(42)
        leaf.source_table = d.LTable()
        packed = d.SymList([leaf] + [d.Const(i) for i in range(100005)], None)
        validator = d.PackedSourceValidator()
        self.assertFalse(validator.validate(packed))
        self.assertEqual(validator.failure, "source_pack_shape")
        self.assertGreater(validator.checked, 100000)

    def test_cycle_and_shared_container_are_not_expanded_repeatedly(self):
        shared = d.SymList([], None)
        shared.items.append(shared)
        root = d.SymList([shared] * 20, None)
        validator = d.PackedSourceValidator(max_containers=2, max_edges=21)
        self.assertTrue(validator.validate(root))
        self.assertEqual(validator.containers, 2)
        self.assertEqual(validator.edges, 21)

    def test_source_cycle_preserves_original_table_identity(self):
        source = d.LTable()
        source.set(1, source)
        packed = d.SymList([], None)
        packed.items.append(packed)
        packed.source_table = source
        packed.source_items = tuple(packed.items)
        packed.source_nkey = None
        with patch.dict("os.environ", {"DEVIRT_PACKED_TABLE_PROVENANCE": "1"}):
            self.assertIs(lifter().packed_proto_table(packed), source)

    def test_duplicate_edges_still_consume_edge_budget(self):
        shared = d.SymList([], None)
        root = d.SymList([shared] * 100, None)
        validator = d.PackedSourceValidator(max_containers=2, max_edges=99)
        self.assertFalse(validator.validate(root))
        self.assertEqual(validator.failure, "edge_budget")

    def test_distinct_container_explosion_still_fails_closed(self):
        root = d.SymList([d.SymList([], None), d.SymList([], None)], None)
        validator = d.PackedSourceValidator(max_containers=2)
        self.assertFalse(validator.validate(root))
        self.assertEqual(validator.failure, "container_budget")

    def test_recursive_source_validation_work_is_also_budgeted(self):
        child = d.SymList([d.Const(i) for i in range(10)], None)
        child.source_table = d.LTable()
        child.source_items = tuple(child.items)
        child.source_nkey = None
        root = d.SymList([child], None)
        validator = d.PackedSourceValidator(max_edges=20)
        self.assertFalse(validator.validate(root))
        self.assertEqual(validator.failure, "edge_budget")

    def test_validator_reuse_cannot_keep_a_previous_source_on_failure(self):
        packed = d.SymList([], None)
        packed.source_table = d.LTable()
        packed.source_items = ()
        packed.source_nkey = None
        validator = d.PackedSourceValidator(max_containers=1)
        self.assertTrue(validator.validate(packed))
        self.assertTrue(validator.sources)
        self.assertFalse(validator.validate(d.SymList([d.SymList([], None)], None)))
        self.assertFalse(validator.sources)

    def test_shared_large_source_local_checks_are_not_repeated_per_parent(self):
        def source(items):
            pack = d.SymList(items, None)
            pack.source_table = d.LTable()
            pack.source_items = tuple(items)
            pack.source_nkey = None
            return pack
        shared = source([d.Const(i) for i in range(100005)])
        root = d.SymList([source([shared]) for _ in range(100)], None)
        validator = d.PackedSourceValidator(max_edges=500000)
        self.assertTrue(validator.validate(root))
        self.assertGreater(validator.checked, 100000)
        self.assertLess(validator.edges, 500000)

    def test_cached_local_check_cannot_bypass_deep_source_guard(self):
        def source(items):
            pack = d.SymList(items, None)
            pack.source_table = d.LTable()
            pack.source_items = tuple(items)
            pack.source_nkey = None
            return pack
        leaf = source([])
        chain = leaf
        for _ in range(17):
            chain = source([chain])
        # LIFO discovery validates the shallow leaf before the deep root.
        root = d.SymList([chain, leaf], None)
        validator = d.PackedSourceValidator()
        self.assertFalse(validator.validate(root))
        self.assertEqual(validator.failure, "source_depth")

    def test_source_local_check_cache_is_scoped_to_one_validation(self):
        pack = d.SymList([d.Const(1)], None)
        pack.source_table = d.LTable()
        pack.source_items = tuple(pack.items)
        pack.source_nkey = None
        validator = d.PackedSourceValidator()
        self.assertTrue(validator.validate(pack))
        pack.items[0] = d.Const(2)
        self.assertFalse(validator.validate(pack))
        self.assertEqual(validator.failure, "source_items_changed")


if __name__ == "__main__":
    unittest.main()
