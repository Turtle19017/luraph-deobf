#!/usr/bin/env python3
import pathlib, sys, unittest
ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import analyze_r178d_origin_consensus as r178d


def doc(rows):
    return {"schema": r178d.IN_SCHEMA, "source_commit": "x", "proto_key": "p", "write_instances": rows}


def row(origin, cls, *, safe=False, fate=None, path=0):
    return {"origin_id": origin, "statement_origin": origin.rsplit("/", 1)[0], "register": 1,
            "classification": cls, "safe_negative_claim": safe,
            "possible_fates": [fate or cls], "node": {"pc": 10}, "path_index": path,
            "branch_trace": [bool(path)], "event_index": 0}


class R178DOriginConsensusTests(unittest.TestCase):
    def one(self, rows): return r178d.analyze(doc(rows))["origins"][0]

    def test_two_shadowed_duplicates_are_prunable(self):
        x = self.one([row("O", "MUST_SHADOWED", safe=True, fate="CLOBBER", path=0),
                      row("O", "MUST_SHADOWED", safe=True, fate="CLOBBER", path=1)])
        self.assertEqual(x["consensus"], "PROVEN_UNCONSUMED"); self.assertTrue(x["prunable_origin"])

    def test_dead_and_shadowed_are_both_negative(self):
        x = self.one([row("O", "MUST_DEAD", safe=True, fate="DEAD", path=0),
                      row("O", "MUST_SHADOWED", safe=True, fate="CLOBBER", path=1)])
        self.assertEqual(x["consensus"], "PROVEN_UNCONSUMED")

    def test_live_branch_blocks_pruning(self):
        x = self.one([row("O", "MUST_LIVE", fate="READ", path=0),
                      row("O", "MUST_DEAD", safe=True, fate="DEAD", path=1)])
        self.assertEqual(x["consensus"], "PATH_DEPENDENT"); self.assertFalse(x["prunable_origin"])

    def test_unknown_blocks_pruning(self):
        x = self.one([row("O", "MUST_DEAD", safe=True, fate="DEAD"), row("O", "UNKNOWN", fate="BARRIER")])
        self.assertEqual(x["consensus"], "UNKNOWN")

    def test_all_live_is_proven_live(self):
        x = self.one([row("O", "MUST_LIVE", fate="READ", path=0), row("O", "MUST_LIVE", fate="READ", path=1)])
        self.assertEqual(x["consensus"], "PROVEN_LIVE")

    def test_missing_origin_is_reported_not_grouped(self):
        r = row("O", "MUST_DEAD", safe=True, fate="DEAD"); r["origin_id"] = None
        out = r178d.analyze(doc([r]))
        self.assertEqual(out["summary"]["missing_origin_instances"], 1)
        self.assertEqual(out["origins"], [])


if __name__ == "__main__": unittest.main()
