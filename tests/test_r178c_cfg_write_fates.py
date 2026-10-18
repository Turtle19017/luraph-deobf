#!/usr/bin/env python3
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import analyze_r178c_cfg_write_fates as r178c


def key(pc):
    return {"repr": f"K{pc}", "pc": pc, "mode": 7}


def path(i, events, outcome, branch=None):
    return {"path_index": i, "events": events, "branch_trace": branch or [], "outcome": outcome}


def node(pc, paths):
    return {"key": key(pc), "opcode": 1, "error": None, "cfg_successors": [], "micro_paths": paths}


def cfg(nodes, *, complete=True, mismatches=None):
    return {
        "schema": r178c.IN_SCHEMA,
        "source_commit": "x",
        "proto_key": "p",
        "graph_complete": complete,
        "edge_mismatches": mismatches or [],
        "missing_edge_targets": [],
        "nodes": nodes,
    }


class R178CWriteFateTests(unittest.TestCase):
    def row(self, doc, reg=1):
        rows = r178c.analyze(doc, [reg])["write_instances"]
        self.assertEqual(len(rows), 1)
        return rows[0]

    def row_at(self, doc, pc, reg=1):
        rows = r178c.analyze(doc, [reg])["write_instances"]
        hits = [r for r in rows if r["node"].get("pc") == pc]
        self.assertEqual(len(hits), 1)
        return hits[0]

    def test_same_path_read_is_must_live(self):
        d = cfg([node(10, [path(0, [
            {"kind": "write", "register": 1, "role": "assign"},
            {"kind": "read", "register": 1, "role": "rhs"},
        ], {"kind": "return"})])])
        self.assertEqual(self.row(d)["classification"], "MUST_LIVE")

    def test_same_path_overwrite_is_must_shadowed(self):
        d = cfg([node(10, [path(0, [
            {"kind": "write", "register": 1, "role": "first"},
            {"kind": "write", "register": 1, "role": "second"},
        ], {"kind": "return"})])])
        rows = r178c.analyze(d, [1])["write_instances"]
        self.assertEqual([r["classification"] for r in rows], ["MUST_SHADOWED", "MUST_DEAD"])

    def test_terminal_without_consumer_is_must_dead(self):
        d = cfg([node(10, [path(0, [
            {"kind": "write", "register": 1, "role": "assign"},
        ], {"kind": "return"})])])
        self.assertEqual(self.row(d)["classification"], "MUST_DEAD")

    def test_branch_read_vs_clobber_is_path_dependent(self):
        n10 = node(10, [path(0, [
            {"kind": "write", "register": 1, "role": "assign"},
        ], {"kind": "next", "successor": key(20)})])
        n20 = node(20, [
            path(0, [{"kind": "read", "register": 1}], {"kind": "return"}, [True]),
            path(1, [{"kind": "write", "register": 1}], {"kind": "return"}, [False]),
        ])
        self.assertEqual(self.row_at(cfg([n10, n20]), 10)["classification"], "PATH_DEPENDENT")

    def test_call_barrier_blocks_negative_proof(self):
        d = cfg([node(10, [path(0, [
            {"kind": "write", "register": 1},
            {"kind": "call-barrier", "may_read_all_registers": False,
             "may_write_all_registers": False, "may_write_registers": [1]},
            {"kind": "write", "register": 1},
        ], {"kind": "return"})])])
        rows = r178c.analyze(d, [1])["write_instances"]
        self.assertEqual(rows[0]["classification"], "UNKNOWN")

    def test_cycle_without_decisive_effect_is_unknown(self):
        n10 = node(10, [path(0, [{"kind": "write", "register": 1}],
                                  {"kind": "next", "successor": key(20)})])
        n20 = node(20, [path(0, [], {"kind": "next", "successor": key(20)})])
        row = self.row(cfg([n10, n20]))
        self.assertEqual(row["classification"], "UNKNOWN")
        self.assertIn("LOOP", row["possible_fates"])

    def test_cycle_with_immediate_clobber_is_shadowed(self):
        n10 = node(10, [path(0, [{"kind": "write", "register": 1}],
                                  {"kind": "next", "successor": key(20)})])
        n20 = node(20, [path(0, [{"kind": "write", "register": 1}],
                                  {"kind": "next", "successor": key(20)})])
        rows = r178c.analyze(cfg([n10, n20]), [1])["write_instances"]
        first = next(r for r in rows if r["node"]["pc"] == 10)
        self.assertEqual(first["classification"], "MUST_SHADOWED")

    def test_missing_successor_is_unknown(self):
        n10 = node(10, [path(0, [{"kind": "write", "register": 1}],
                                  {"kind": "next", "successor": key(99)})])
        row = self.row(cfg([n10], complete=False))
        self.assertEqual(row["classification"], "UNKNOWN")
        self.assertIn("INCOMPLETE", row["possible_fates"])

    def test_edge_mismatch_blocks_successor_negative_proof(self):
        n10 = node(10, [path(0, [{"kind": "write", "register": 1}],
                                  {"kind": "next", "successor": key(20)})])
        n20 = node(20, [path(0, [], {"kind": "return"})])
        row = self.row(cfg([n10, n20], mismatches=[{"source": key(10)}]))
        self.assertEqual(row["classification"], "UNKNOWN")
        self.assertIn("INCONSISTENT_CFG", row["possible_fates"])

    def test_unrelated_incomplete_graph_does_not_hide_local_read(self):
        n10 = node(10, [path(0, [
            {"kind": "write", "register": 1},
            {"kind": "read", "register": 1},
        ], {"kind": "return"})])
        n99 = node(99, [path(0, [], {"kind": "none"})])
        row = self.row(cfg([n10, n99], complete=False))
        self.assertEqual(row["classification"], "MUST_LIVE")


if __name__ == "__main__":
    unittest.main()
