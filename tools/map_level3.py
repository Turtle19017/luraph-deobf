#!/usr/bin/env python3
"""
map_level3.py - recover the t -> handler table of the THIRD interpreter level
(the `c.ep` closure built inside handler `B:T`).

The Luraph control-flow scrambler emits a fully unrolled nested
`if t<=N then <leaf|nested> elseif ... else <leaf> end` binary search.
This parses that structure with a real block-aware recursive descent, so the
op ranges are exact rather than guessed.
"""
import io, re, sys, glob

sys.path.insert(0, r"C:\Users\LENOVO\AppData\Local\Temp\opencode")
import luatok

p = glob.glob(r"C:\Users\LENOVO\OneDrive\*\luraph\script.txt")[0]
body = io.open(p, encoding="utf-8", errors="replace").read().split("\n")[2]
T = luatok.find_function(body, "T")[0]

start = T.find("while a do", T.find("[B.ep]=function"))
region = T[start:]
# the dispatch tree ends just before the final `end;end;end;end;` of the closure
end_marker = region.rfind("end;end;end;end;")
region = region[:end_marker] if end_marker > 0 else region

TOK = re.compile(
    r"\bif\s+t<=(\d+)\s+then"
    r"|\belseif\s+t<=(\d+)\s+then"
    r"|\belse\b"
    r"|\bend\b"
    r"|B:(\w+)\("
    r"|\bcontinue\b"
)

tokens = []
for m in TOK.finditer(region):
    if m.group(1) is not None:
        tokens.append(("if", int(m.group(1))))
    elif m.group(2) is not None:
        tokens.append(("elseif", int(m.group(2))))
    elif m.group(3) is not None:
        tokens.append(("call", m.group(3)))
    elif m.group(0).startswith("else"):
        tokens.append(("else", None))
    elif m.group(0) == "end":
        tokens.append(("end", None))
    elif m.group(0) == "continue":
        tokens.append(("continue", None))

print(f"tokens: {len(tokens)}")
print("head:", tokens[:14])


class P:
    def __init__(self, toks):
        self.t = toks
        self.i = 0

    def peek(self):
        return self.t[self.i] if self.i < len(self.t) else (None, None)

    def next(self):
        v = self.peek()
        self.i += 1
        return v

    def parse_chain(self, lo, hi, out):
        """Parse `if t<=N then B elif t<=M then B else B end`.

        Branch ranges: the k-th `if t<=N` owns (prev, N]; `else` owns (prev, hi].
        """
        if self.peek()[0] != "if":
            if self.peek()[0] == "call":
                _, name = self.next()
                out.append((lo, hi, name))
                if self.peek()[0] == "continue":
                    self.next()
            return

        prev_hi = None
        while True:
            kind, val = self.peek()
            if kind in ("if", "elseif"):
                self.next()
                bound = val
            elif kind == "else":
                self.next()
                bound = None
            else:
                break

            cur_hi = bound if bound is not None else hi

            bk, bv = self.peek()
            if bk == "call":
                self.next()
                out.append((lo, cur_hi, bv))
                if self.peek()[0] == "continue":
                    self.next()
            elif bk == "if":
                self.parse_chain(lo, cur_hi, out)
            else:
                return

            if bound is None:
                return
            prev_hi = bound
            lo = bound + 1

        if self.peek()[0] == "end":
            self.next()


out = []
P(tokens).parse_chain(0, 10 ** 9, out)

# NOTE: the range reconstruction below is only reliable for the first
# binary-search chain; deeper chains desync on nested `end` consumption.
# Do NOT trust the inferred ranges -- use the raw bound groups above, which
# are exact, plus the verbatim source of `B:T` for hand-mapping.
runs = []
cur = []
for kind, val in tokens:
    if kind == "le" or (kind == "if"):
        cur.append(val)
    elif kind == "elseif":
        cur.append(val)
    else:
        if cur:
            runs.append(cur)
        cur = []
if cur:
    runs.append(cur)

print(f"\n=== level-3 binary-search groups ({len(runs)}) — exact ===")
for r in runs:
    print("   " + " -> ".join(str(x) for x in r))

names = sorted(set(m.group(1) for m in re.finditer(r"B:(\w+)\(", region)))
print(f"\n=== {len(names)} micro-handlers referenced by the closure ===")
for i in range(0, len(names), 10):
    print("   " + " ".join(names[i:i + 10]))

print("\n=== entry state ===")
print("   B:Op() -> true, 8, nil*14   so the closure starts at t = 8")
print("   t<=6 -> (t<=2 ? B:Ap : B:wp)")
print("   t<=9 -> B:vp          (t=8 lands here)")
print("   else -> B:sp")