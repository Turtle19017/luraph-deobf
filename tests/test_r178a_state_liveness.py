#!/usr/bin/env python3
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import analyze_r178a_state_liveness as r178a


def ledger(events, *, complete=True, control=True):
    doc = {
        "schema": r178a.SCHEMA,
        "source_commit": "729391a",
        "control_order_complete": control,
        "events": events,
    }
    if complete:
        doc["complete_for_locations"] = ["BR:177"]
    return doc


class R178AStateLivenessTests(unittest.TestCase):
    def test_live_on_definite_read(self):
        doc = ledger([
            {"seq": 1, "kind": "write", "register": 177, "pc": 100},
            {"seq": 2, "kind": "read", "register": 177, "pc": 101},
            {"seq": 3, "kind": "boundary", "pc": 200},
        ], complete=False, control=False)
        row = r178a.analyze(doc)["writes"][0]
        self.assertEqual(row["classification"], "LIVE")
        self.assertEqual(row["consumer"]["pc"], 101)

    def test_shadowed_requires_completeness(self):
        events = [
            {"seq": 1, "kind": "write", "register": 177, "pc": 100},
            {"seq": 2, "kind": "write", "register": 177, "pc": 110},
            {"seq": 3, "kind": "boundary", "pc": 200},
        ]
        rows = r178a.analyze(ledger(events))["writes"]
        self.assertEqual(rows[0]["classification"], "SHADOWED")
        self.assertEqual(rows[1]["classification"], "DEAD")

        rows = r178a.analyze(ledger(events, complete=False))["writes"]
        self.assertEqual(rows[0]["classification"], "UNKNOWN")
        self.assertEqual(rows[1]["classification"], "UNKNOWN")

    def test_dead_only_at_explicit_boundary(self):
        doc = ledger([
            {"seq": 1, "kind": "write", "register": 177, "pc": 100},
            {"seq": 2, "kind": "boundary", "pc": 200},
        ])
        row = r178a.analyze(doc)["writes"][0]
        self.assertEqual(row["classification"], "DEAD")

        no_boundary = ledger([
            {"seq": 1, "kind": "write", "register": 177, "pc": 100},
        ])
        row = r178a.analyze(no_boundary)["writes"][0]
        self.assertEqual(row["classification"], "UNKNOWN")

    def test_dynamic_read_forces_unknown(self):
        doc = ledger([
            {"seq": 1, "kind": "write", "register": 177, "pc": 100},
            {"seq": 2, "kind": "read", "alias": "MAY", "alias_space": "BR", "pc": 105},
            {"seq": 3, "kind": "write", "register": 177, "pc": 110},
            {"seq": 4, "kind": "boundary", "pc": 200},
        ])
        rows = r178a.analyze(doc)["writes"]
        self.assertEqual(rows[0]["classification"], "UNKNOWN")
        self.assertIn("could consume", rows[0]["classification_reason"])

    def test_dynamic_write_forces_unknown(self):
        doc = ledger([
            {"seq": 1, "kind": "write", "register": 177, "pc": 100},
            {"seq": 2, "kind": "write", "alias": "MAY", "alias_space": "BR", "pc": 105},
            {"seq": 3, "kind": "boundary", "pc": 200},
        ])
        rows = r178a.analyze(doc)["writes"]
        self.assertEqual(rows[0]["classification"], "UNKNOWN")
        self.assertIsNone(rows[1]["location"])
        self.assertEqual(rows[1]["classification"], "UNKNOWN")

    def test_packed_provenance_is_preserved_exactly(self):
        prov = {
            "packed_source": "A321.block1",
            "table": 42,
            "key": 9,
            "decode": {"kind": "lazy", "guarded": True},
        }
        doc = ledger([
            {"seq": 1, "kind": "write", "register": 177, "pc": 100,
             "packed_provenance": prov},
            {"seq": 2, "kind": "read", "register": 177, "pc": 101},
            {"seq": 3, "kind": "boundary", "pc": 200},
        ])
        out = r178a.analyze(doc)
        row = out["writes"][0]
        self.assertEqual(row["packed_provenance"], prov)
        self.assertTrue(row["packed_provenance_preserved"])
        self.assertEqual(out["summary"]["with_packed_provenance"], 1)

    def test_opcode7_bank_range_expands_and_r177_can_be_live(self):
        doc = ledger([
            {"seq": 1, "kind": "opcode7-return-bank", "register_start": 155,
             "register_end": 202, "pc": 3363},
            {"seq": 2, "kind": "read", "register": 177, "pc": 3784},
            {"seq": 3, "kind": "boundary", "pc": 3784},
        ])
        out = r178a.analyze(doc)
        rows177 = [x for x in out["writes"] if x["location"] == "BR:177"]
        self.assertEqual(len(rows177), 1)
        self.assertEqual(rows177[0]["classification"], "LIVE")

    def test_nested_r177_chain_shadow_shadow_live_when_complete(self):
        doc = ledger([
            {"seq": 1, "kind": "opcode7-return-bank", "register_start": 61,
             "register_end": 284, "pc": 2150},
            {"seq": 2, "kind": "opcode7-return-bank", "register_start": 117,
             "register_end": 206, "pc": 3504},
            {"seq": 3, "kind": "opcode7-return-bank", "register_start": 155,
             "register_end": 202, "pc": 3363},
            {"seq": 4, "kind": "read", "register": 177, "pc": 3784},
            {"seq": 5, "kind": "boundary", "pc": 3784},
        ])
        out = r178a.analyze(doc)
        rows177 = [x for x in out["writes"] if x["location"] == "BR:177"]
        self.assertEqual([x["pc"] for x in rows177], [2150, 3504, 3363])
        self.assertEqual(
            [x["classification"] for x in rows177],
            ["SHADOWED", "SHADOWED", "LIVE"],
        )

    def test_host_effect_read_is_a_consumer(self):
        doc = ledger([
            {"seq": 1, "kind": "write", "register": 177, "pc": 100},
            {"seq": 2, "kind": "host-effect-read", "register": 177, "pc": 150},
            {"seq": 3, "kind": "boundary", "pc": 200},
        ], complete=False, control=False)
        row = r178a.analyze(doc)["writes"][0]
        self.assertEqual(row["classification"], "LIVE")
        self.assertTrue(row["host_effect_relevant"])

    def test_explicit_host_relevance_blocks_dead_claim(self):
        doc = ledger([
            {"seq": 1, "kind": "write", "register": 177, "pc": 100,
             "host_effect_relevant": True},
            {"seq": 2, "kind": "boundary", "pc": 200},
        ])
        row = r178a.analyze(doc)["writes"][0]
        self.assertEqual(row["classification"], "UNKNOWN")
        self.assertTrue(row["host_effect_relevant"])

    def test_source_commit_guard_logic_is_prefix_safe(self):
        # analyze itself passes through the commit; CLI performs the prefix guard.
        out = r178a.analyze(ledger([
            {"seq": 1, "kind": "write", "register": 177},
            {"seq": 2, "kind": "boundary"},
        ]))
        self.assertEqual(out["source_commit"], "729391a")

    def test_duplicate_or_non_increasing_seq_fails(self):
        doc = ledger([
            {"seq": 2, "kind": "write", "register": 177},
            {"seq": 1, "kind": "boundary"},
        ])
        with self.assertRaises(ValueError):
            r178a.analyze(doc)


if __name__ == "__main__":
    unittest.main()
