# 006 — Runtime harness (Luau CLI, out of Roblox)

Everything in reports 001–005 was produced without executing the target. This
report covers the pieces that only exist because a runtime was needed to settle
questions the static model could not answer.

## Why a runtime at all

The static `B:A` replay reported an out-of-bounds read at `438 → 365`
(`buffer.readu8(f, 43238)` against a 20,936-byte buffer). Two hypotheses:

- the replay has a wrong register mapping, or
- the static model walks a path the real target never takes.

Running the target settled it for hypothesis (2).

## Running the target outside Roblox

The protected script binds exactly four Roblox-only globals at table-construction
time:

```text
B[970]  = Vector2.new
B[2135] = Vector3.new
B[90]   = setfenv
B[39]   = getfenv
```

`tools/roblox_shim.luau` provides those plus the Roblox namespace objects the
target resolves dynamically. A stock `luau.exe` 0.742 CLI is enough; no Roblox
Studio and no `syn`.

Gotchas, each of which cost a run:

| symptom | cause | fix |
|---|---|---|
| `attempt to index nil with 'cancel'` around A228 iteration ~20904 | `cancel` is built at runtime via the dynamic resolver `e=function(B,...)return(...)[...];end`; it is not a literal anywhere in `script.txt` | add `task`, `game`, `workspace`, `Instance`, `RunService`, `Debris` to the shim |
| `attempt to modify a readonly table` | assigning `os.clock` or `_G.x` | `os` and `_G` are read-only in Luau; bind globals directly |
| `Error opening .../Máy tính/...` | Luau cannot open non-ASCII paths | run from an ASCII-only directory |
| `Cannot use '...' outside of a vararg function` | harness wrapped the target in `function() … end`, but the chunk ends in `(...)` | keep the target at chunk top level; wrap in `do … end` |
| probe output lost entirely on timeout | Luau block-buffers stdout when not a TTY, and the process is then killed | emit ~4 KB of padding after each marker to force a flush |
| `luau.exe` drops into its interactive debug REPL | runner signalled `CTRL_BREAK_EVENT` | `proc.kill()` |

`tools/run_luau_capture.py` streams output line-by-line to a file so a timeout
never discards the trace.

## What the runtime settled

1. `[A99]` and `[A321]` reproduce the static model exactly:

   ```text
   [A99]   seed_in 164  xor 240  scratch 20936  cursor 20935  key0 1
   [A228]  mult 148  inc 155  state 93  xor 240  srcoff 35915  key 95  cipher 174
           ... exactly 20,936 iterations ...
   [A321]  len 20936  first 1  next 145
   [A438]  (never reached)
   [A365]  (never reached)
   ```

   The LCG is `key[0] = (seed_in + 240) % 256`,
   `key[n+1] = (155 + key[n] * 93) % 256`; first three keystream bytes
   95 / 30 / 129.

2. State `438` is never executed, so the impossible offset was never produced.

3. **The decode fires eleven times, not once:**

   ```text
   seed_in: 164 325 229 129 305 339 347 281 187 283 211
   size:  20936 186 462 7397 2479 231 640 578 738 250 3693
   total: 37590 bytes
   ```

   Every block is followed by `[A321] first=1 next=145`, so `145` is the common
   continuation, not a one-off.

## Offset base — scope and limits

`srcoff` as printed by the live probes is **buffer-relative**. For block 1 in
this sample:

```text
block1_stage1_offset = block1_srcoff + 1274
```

`tools/verify_block1_offset_base.py` does not assert this constant. It searches
`stage1.bin` for the offset whose LCG-XOR decryption reproduces the reference
digest and then reports the base that offset implies:

```text
VERIFIED block 1
  stage1 offset        : 37189
  implied base         : 1274
  H(cipher)            : 7.9914
  H(plain)             : 7.3002
```

**This constant is fitted from block 1 alone.** It is *not* established for the
other ten blocks. The decode source buffer may differ per block, and when the
other ten candidate offsets were computed with `+1274`, five produced a byte
profile unlike the verified block (under 1% low bytes versus 11%), while the
remaining five are consistent but unverified by digest. Do not generalise `+1274`
without per-block evidence — use `tools/derive_lcg_manifest.py` for the offline
offset derivation.

Using `srcoff` with no correction is the easiest mistake in this chain: the
plaintext entropy stays at ~7.99, which looks like a plausible result while being
entirely wrong. The verifier exists to make that failure loud.

The blocks are **scattered** through `stage1.bin`, not laid out contiguously; the
contiguous hypothesis was tested and disproved.

## Static successor chain after `A321`

Read from the dispatch tree of `A` and the handlers it calls:

```text
A321 → 145 → B:p      → 212
              B:ny(212) → 437   if r ≠ 2   (else 201)
              B:mW(437) → 283   if Y ≠ 0   (else 389)
              B:Jy(283) → 314
              B:ay(314) → 121   if Y ≥ 128  (else 84)
              B:Z(121)  → 42
              B:T(42)   → 48  → third interpreter level
```

Three of the nine steps are conditional, so this is the *plausible* path, not an
observed one. The `121 → 42 → 48` leg is unconditional and directly contradicts
the earlier `121 → 9 → 438` reading, which is what produced the phantom
out-of-bounds read.

## Third interpreter level

`tools/map_level3.py` slices handler `B:T` with `tools/luatok.py` and reports the
structure of the `c.ep` closure. **It is an exploratory mapper.** Two of its
outputs are exact:

- the binary-search bound groups, e.g. `118 → 58 → 28 → 13 → 6 → 2`
- a census of **73** micro-handlers referenced by the closure:

```text
A9 Ap Bp Cp Dp Ep Fp G9 Gp Hp Ip Jp K9 L9 Lp Mp Np O9 Pp Qp
Rp S9 Sp T9 Tp U9 Up V9 Wp Xp Yp Zp _p ap b9 bp c9 d9 e9 f9
fp gp hp i9 ip jp k9 kp lp m9 mp n9 np o9 op pp q9 qp rp s9
sp t9 tp up v9 vp w9 wp x9 xp y9 z9 zp
```

It deliberately does **not** emit per-opcode ranges. An earlier version inferred
them and they were wrong: the dispatch is nested `if/elseif/else/end` and the
parser desynchronised on nested `end` consumption, yielding ranges like `[14, 9]`
and mapping every opcode ≥ 25 to a single handler. Wrong ranges that look
plausible are worse than no ranges, so they were removed rather than caveated.

Entry state is `t = 8` (`B:Op()` returns `true, 8, nil*14`); the first bands of
the dispatch are `t ≤ 118` and `t ≤ 58`, both opening on `B:Ap`, with `t = 8`
landing in the second band on `B:vp`.

For authoritative opcode ranges, read the dispatch tree verbatim in `B:T`
(search the target for `local c={[B.ep]=function`).

## Probe generators

`tools/make_A_probe.py` is the canonical census probe and injects exactly two
markers — `[A99]` (seed, size, and source base, once per block) and `[A321]`
(first byte and the common continuation). `tools/make_A_trace_probe.py` records
the `B:A` successor stream after `A321`, suppressing the hot LCG-XOR states
99/323/228/321 so the trace budget is not consumed by byte-by-byte decoding.

Both are sample-specific and fail-closed: every anchor must match exactly once or
nothing is written.