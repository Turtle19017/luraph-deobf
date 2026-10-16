from __future__ import annotations

import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import level3_state_graph as l3  # noqa: E402


def successors(fn_src: str, formal: str, state: int) -> set[int]:
    toks, body = l3.parse_body(fn_src)
    returns, fall = l3.reachable_returns(body, toks, formal, state)
    if fall:
        raise AssertionError(f"unexpected fallthrough: {fall}")
    out: set[int] = set()
    for ret in returns:
        vals = l3.constant_options(ret[0])
        if vals is None:
            raise AssertionError(f"unresolved return: {ret[0]}")
        out |= vals
    return out


class Level3ShadowingTests(unittest.TestCase):
    def test_unshadowed_state_condition_is_evaluated(self):
        src = (
            "function(B,I)"
            "if I<=5 then return 10;else return 20;end;"
            "end"
        )
        self.assertEqual(successors(src, "I", 5), {10})

    def test_local_shadow_turns_later_condition_runtime_unknown(self):
        src = (
            "function(B,I)"
            "if I<=5 then "
            "local B,I,r=v[1],v[4],v[3];"
            "if I then return 228;else return 78;end;"
            "else return 1;end;"
            "end"
        )
        self.assertEqual(successors(src, "I", 5), {78, 228})

    def test_shadowed_comparison_is_not_folded_from_dispatch_state(self):
        src = (
            "function(B,c)"
            "if c<=143 then "
            "local c=B[117](r,v+1);"
            "if c>=128 then return 104;else return 169;end;"
            "else return 217;end;"
            "end"
        )
        self.assertEqual(successors(src, "c", 143), {104, 169})


if __name__ == "__main__":
    unittest.main()
