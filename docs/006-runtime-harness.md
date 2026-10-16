# 006 — Runtime harness (Luau CLI, out of Roblox)

Everything up to report 005 was produced without executing the target. This
report covers the pieces that only exist because we needed a runtime to settle
questions the static model could not answer.

## Why a runtime at all

The static `B:A` replay reported an out-of-bounds read at `438 → 365`
(`buffer.readu8(f, 43238)` against a 20,936-byte buffer). Two hypotheses:

- the Python replay has a wrong register mapping, or
- the static model walks a path the real target never takes.

Running the target settles it in one shot, and the answer was hypothesis (2).

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
target resolves dynamically. A bare `luau.exe` 0.742 CLI is sufficient; no
Roblox Studio and no `syn`.

Gotchas encountered, each of which cost a run:

| symptom | cause | fix |
|---|---|---|
| `attempt to index nil with 'cancel'` around A228 iteration ~20904 | `cancel` is built at runtime through the dynamic resolver `e=function(B,...)return(...)[...];end`; it is not a literal anywhere in `script.txt` | add `task`, `game`, `workspace`, `Instance`, `RunService`, `Debris` to the shim |
| `attempt to modify a readonly table` | `os.clock = ...` and `_G.x = ...` | `os` and `_G` are read-only in Luau; bind globals directly |
| `Error opening .../Máy tính/...` | Luau cannot open paths containing non-ASCII characters | run from an ASCII-only directory |
| `Cannot use '...' outside of a vararg function` | the harness wrapped the target in `function() ... end`, but the chunk ends in `(...)` | keep the target at chunk top level, wrap in `do ... end` |
| probe output lost entirely on timeout | Luau block-buffers stdout when not a TTY, and the process is killed | emit ~4 KB of padding after each marker to force a flush |
| `luau.exe` drops into its interactive debug REPL | runner signalled `CTRL_BREAK_EVENT` on timeout | `proc.kill()` instead |

`tools/run_luau_capture.py` captures output line-by-line to a file so a timeout
never discards the trace.

## Answers the runtime produced

1. `[A99]` and `[A321]` reproduce the static model exactly:
   ```text
   [A99]   seed_in 164  xor 240  scratch 20936  cursor 20935  key0 1
   [A228]  mult 148  inc 155  state 93  xor 240  srcoff 35915  key 95  cipher 174
           ... exactly 20,936 iterations ...
   [A321]  len 20936  first 1  next 145
   [A438]  (never reached)
   [A365]  (never reached)
   ```
   The LCG was confirmed as `key[n+1] = (155 + key[n] * 93) % 256` with
   `key[0] = (seed_in + 240) % 256`, first three keystream bytes 95 / 30 / 129.

2. State `438` is never executed, so the impossible offset was never produced.

3. **The decode fires eleven times**, not once:

   ```text
   seed_in: 164 325 229 129 305 339 347 281 187 283 211
   size:  20936 186 462 7397 2479 231 640 578 738 250 3693
   total: 37590 bytes
   ```

   Every block is followed by `[A321] first=1 next=145`, so `145` is the
   common continuation, not a one-off.

## `srcoff` is not a `stage1.bin` offset

The probe prints `srcoff = Y + Z`, where `Z` is the scratch-buffer write cursor.
It is relative to the decode buffer. The mapping for this sample is:

```text
stage1_offset = srcoff + 1274
```

Block 1 confirms it: `35915 + 1274 = 37189`, and decrypting
`stage1.bin[37189 : 37189+20936]` with `seed_in = 164` reproduces the reference
SHA-256 exactly.

Using `srcoff` directly produces a result whose entropy still sits at ~7.99 —
a plausible-looking answer that is completely wrong. This is the single easiest
mistake in the whole chain, which is why
`tools/verify_block1_offset_base.py` exists and exits non-zero on mismatch.

## Getting all eleven offsets in one run

`B:Sy` writes into the scratch buffer at cursor `Z`:

```lua
B[2](I, Z, B[121](X, r, B[117](a, Y+Z)))
```

For a fresh block `Z` starts at `0`, so gating on `Z == 0` prints the block base
once instead of 20,936 times:

```lua
if Z==0 then print('[SRC]','srcoff',Y+Z) end
```

`tools/make_offsets_probe.py` does this and yields the full table in one run.
Note that the blocks are **scattered** through `stage1.bin`, not laid out
contiguously — the contiguous hypothesis was tested and disproved.

## Third interpreter level

`tools/map_level3.py` recovers the structure of the `c.ep` closure built inside
handler `B:T`: 38 binary-search groups and 73 micro-handlers. Entry state is
`t = 8` (`B:Op()` returns `true, 8, nil*14`), which lands on `B:vp`.

The opener script.txt contains 73 micro-handlers referenced by the closure:

```text
A9 Ap Bp Cp Dp Ep Fp G9 Gp Hp Ip Jp K9 L9 Lp Mp Np O9 Pp Qp
Rp S9 Sp T9 Tp U9 Up V9 Wp Xp Yp Zp _p ap b9 bp c9 d9 e9 f9
fp gp hp i9 ip jp k9 kp lp m9 mp n9 np o9 op pp q9 qp rp s9
sp t9 tp up v9 vp w9 wp x9 xp y9 z9 zp
```

The opener script prints the binary-search bounds; the inferred `t` ranges for
the deeper chains are **not** reliable (nested `end` consumption desyncs the
parser) and should be read from the verbatim source of `B:T` instead.

## Static successor chain after `A321`

Read directly from the dispatch tree of `A` and the handlers it calls:

```text
A321 -> 145 -> B:p      -> 212
              B:ny(212) -> 437   if r ~= 2   (else 201)
              B:mW(437) -> 283   if Y ~= 0   (else 389)
              B:Jy(283) -> 314
              B:ay(314) -> 121   if Y >= 128  (else 84)
              B:Z(121)  -> 42
              B:T(42)   -> 48  -> third interpreter level
```

Three of the nine steps are conditional, so this is the *plausible* path rather
than the observed one. The `121 -> 42 -> 48` leg is unconditional and directly
contradicts the earlier `121 -> 9 -> 438` reading.

## Note on `tools/make_A_probe.py`

That generator's `A438` anchor targets an earlier sample and does not exist in
this build:

```text
repo  : local c,X,y=k+(Y+2097152*(c-c%128))+J+Z,4+I,P[1];return 79,P[2],y,X,j,r,z;
actual: local j,X,y=(J-128)*128+(r-128+k*16384),c+3,v[1];return 365,v[2],y,Y,X,I,j;
```

Different register names, a different limb formula (128x / 16384x instead of
2097152x), and it returns 365 directly instead of routing through 79.
`tools/make_A_probe_local.py` carries the corrected anchors and is fail-closed
(every anchor must match exactly once, or nothing is written).