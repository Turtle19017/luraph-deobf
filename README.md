# luraph-deobf

Research notes and reproducible tooling for analyzing a Roblox/Luau script protected with **Luraph Obfuscator v15.0**.

The repository tracks only analysis artifacts, deterministic extractors, probes, and receipts. The original protected script and reconstructed binary payloads are intentionally excluded.

## Current status

- Recovered the outer `Y9` payload transform: `LPH%` magic removal, `gsub(j9, M9)`, then a custom radix-85 decoder.
- Confirmed the nonstandard 5→4 radix-85 permutation independently from both forward and inverse VM handlers.
- Reconstructed `stage1.bin` byte-for-byte with SHA-256:
  `108da67ce0920931a4896896927fa127816bb9980d9fec2518bcad8ed472b2ec`.
- Replayed the outer `J9` loader sufficiently to hand off into `B:A`.
- Runtime tracing shows **11 A-layer LCG-XOR blocks**, totaling **37,590 decoded bytes**.
- Block #1 remains independently reproducible:
  `20,936 bytes`, SHA-256
  `ecdc76fa288993cd2093564fe9a8b3f50f361dbe8f3282aa977c019e9954857e`.
- The old `121 → 9 → 438 → 365` static path is superseded. Direct source mapping gives
  `121 → 42 → 48`.
- The current source-supported candidate continuation after each `A321 → 145` is:
  `145 → 212 → 437 → 283 → 314 → 121 → 42 → 48`.
  Conditional branches are being confirmed by the corrected successor trace.
- The verified outer J9 `z[7]` buffer is exactly
  `stage1[1274:1274+79999]`, SHA-256
  `158c17bfdd79cb23c036639223a730d9c8d2c4940cb07cbfb31aa97551b64891`.
- Runtime/source cross-checking proves that this outer `z[7]` is the source for
  block #1, but **not** a universal source buffer for all eleven A99 decodes.
  The other ten blocks still require separate source-buffer provenance.

## Layout

```text
  docs/001-stage1-base85.md
  docs/002-j9-loader.md
  docs/003-A-replay-layer1.md
  docs/004-runtime-probe.md
  docs/005-A-static-chain-correction.md
  docs/005-multiblock-lcg.md
  docs/006-runtime-harness.md              runtime harness (Luau CLI), probe gotchas, scoped offset-base claim
  docs/007-level3-state-graph.md           exact state→handler map + conservative successor graph
  docs/008-level3-runtime-trace.md         bounded first-invocation level-3 trace
  tools/build_and_run_probe.py             assemble a harness and run it under a Luau CLI
  tools/derive_lcg_manifest.py
  tools/extract_lcg_blocks.py
  tools/luatok.py                          minimal Lua slicer used to isolate handlers
  tools/luraph15_A_layer1.py
  tools/luraph15_static_stage1.py
  tools/make_A_probe.py
  tools/make_A_trace_probe.py
  tools/make_level3_trace_probe.py         bounded first level-3 runtime trace
  tools/map_level3.py                      exploratory mapper for the third interpreter level
  tools/roblox_shim.luau                   minimal Roblox globals for out-of-Roblox execution
  tools/run_luau_capture.py                runner that keeps output across timeouts
  tools/verify_block1_offset_base.py       locate block 1 by digest; derives (not asserts) its offset base
  receipts/luraph_A_entry164_layer1.receipt.json
  receipts/luraph_A_lcg_blocks.trace.json
  receipts/luraph_stage1.receipt.json
```

## Reproduce stage 1

```bash
python tools/luraph15_static_stage1.py script.txt \
  -o luraph_stage1.bin \
  --receipt luraph_stage1.receipt.json
```

Expected decoded SHA-256:

```text
108da67ce0920931a4896896927fa127816bb9980d9fec2518bcad8ed472b2ec
```

## Recover the verified outer J9 z[7] and block #1

```bash
python tools/recover_j9_z7_slice.py \
  luraph_stage1.bin \
  -o luraph_j9_z_7.bin

python tools/audit_a99_source_buffers.py \
  luraph_j9_z_7.bin \
  --json luraph_A99_z7_audit.json
```

The audit is intentionally fail-closed for the known sample: only block #1 is
allowed to match the runtime observation `[A321] first=1` when all eleven
runtime `srcoff` values are tested against this one outer buffer.

The remaining ten blocks are **not** decoded from this buffer. Their runtime
source-buffer provenance is still open.

## Build corrected A-layer probes

```bash
python tools/make_A_probe.py script.txt -o script_A_probe.luau
python tools/make_A_trace_probe.py script.txt -o script_A_trace.luau
```

The generated instrumented targets remain local and are excluded from version control.

## Run a probe outside Roblox

The target can be executed under a stock `luau` CLI; no Roblox Studio and no
`syn` are required. `tools/roblox_shim.luau` supplies the four globals it binds
at construction time (`Vector2.new`, `Vector3.new`, `setfenv`, `getfenv`) plus
the Roblox namespace objects it resolves dynamically. See
`docs/006-runtime-harness.md` for the full list of runtime gotchas.

## Verify the block-1 offset base

```bash
python tools/verify_block1_offset_base.py luraph_stage1.bin
```

This searches `stage1.bin` for the offset whose decryption reproduces the block-1
digest, then reports the base that offset implies (`1274` for this sample). It does
not assert that constant: it is fitted from **block 1 alone** and is not established
for the other ten blocks, whose decode source buffer may differ. Exits non-zero when
no offset reproduces the digest.

Using `srcoff` with no correction at all produces output whose entropy still sits at
~7.99 -- a plausible-looking result that is entirely wrong.

## Trace the first level-3 invocation

After the source-only state graph is built, generate a bounded runtime trace:

```bash
python tools/make_level3_trace_probe.py \
  script.txt \
  -o script_level3_trace.luau \
  --budget 2048
```

The generated target remains local. See `docs/008-level3-runtime-trace.md` for
the marker format and trust boundary.

## Scope

This is a reverse-engineering research repository. It does not include the protected source payload itself and does not claim a complete deobfuscator yet. Findings are recorded with hashes/receipts, and superseded interpretations are preserved explicitly rather than silently rewritten.
