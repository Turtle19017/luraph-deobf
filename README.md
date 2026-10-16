# luraph-deobf

Research notes and reproducible tooling for analyzing a Roblox/Luau script protected with **Luraph Obfuscator v15.0**.

The repository tracks only analysis artifacts, deterministic extractors, probes, and receipts. The original protected script and reconstructed binary payloads are intentionally excluded.

## Current status

- Recovered the outer `Y9` payload transform: `LPH%` magic removal, `gsub(j9, M9)`, then a custom radix-85 decoder.
- Confirmed the nonstandard 5→4 digit permutation independently from both forward and inverse VM handlers.
- Reconstructed `stage1.bin` byte-for-byte with SHA-256:
  `108da67ce0920931a4896896927fa127816bb9980d9fec2518bcad8ed472b2ec`.
- Reimplemented/replayed the outer `J9` loader sufficiently to hand off into `B:A`.
- Reached an inner 20,936-byte LCG-XOR-decoded layer for entry `164`, SHA-256:
  `ecdc76fa288993cd2093564fe9a8b3f50f361dbe8f3282aa977c019e9954857e`.
- Current blocker is a runtime/static divergence near state `438 → 365`; a fail-closed local probe generator is included.

## Layout

```text
docs/
  001-stage1-base85.md
  002-j9-loader.md
  003-A-replay-layer1.md
  004-runtime-probe.md
tools/
  luraph15_static_stage1.py
  luraph15_A_layer1.py
  make_A_probe.py
receipts/
  luraph_stage1.receipt.json
  luraph_A_entry164_layer1.receipt.json
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

## Scope

This is a reverse-engineering research repository. It does not include the protected source payload itself and does not claim a complete deobfuscator yet. Findings are recorded with hashes/receipts so each promoted claim can be checked independently.
