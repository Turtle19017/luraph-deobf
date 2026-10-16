# Report 005 — Eleven LCG-XOR blocks and corrected B:A path

## Result

Runtime probing shows that the A-layer LCG-XOR decoder runs **11 times**, not once.

The earlier analysis promoted the first 20,936-byte block as though it were the only inner layer. That interpretation is superseded by this trace.

| # | seed_in | seed0 = (seed_in + 240) % 256 | size |
|---:|---:|---:|---:|
| 1 | 164 | 148 | 20,936 |
| 2 | 325 | 53 | 186 |
| 3 | 229 | 213 | 462 |
| 4 | 129 | 113 | 7,397 |
| 5 | 305 | 33 | 2,479 |
| 6 | 339 | 67 | 231 |
| 7 | 347 | 75 | 640 |
| 8 | 281 | 9 | 578 |
| 9 | 187 | 171 | 738 |
| 10 | 283 | 11 | 250 |
| 11 | 211 | 195 | 3,693 |
| | | **total** | **37,590** |

All blocks use the same transform:

```text
key[0]   = (seed_in + 240) % 256
key[n+1] = (155 + key[n] * 93) % 256
plain[n] = cipher[n] XOR key[n+1] XOR 240
```

After every block the runtime probe observes:

```text
[A321] first=1 next=145
```

Therefore state 145 is a common continuation point for all eleven decoded buffers.

## Correction to the previous reachable path

The previous model incorrectly continued:

```text
... → 121 → 9 → 438 → 365
```

and then interpreted bytes 8..10 as an offset 43,238 into a 20,936-byte buffer.

Static source mapping shows that this path is not valid for this build.

The relevant source transitions are:

```text
321 → 145
145 → 212
212 → 437 or 201
437 → 283 or 389
283 → 314
314 → 121 or 84
121 → 42
42 → 48
```

The last two steps are unconditional once state 121 is reached:

- `B:Z` at state 121 returns state 42 directly.
- `B:T` at state 42 takes its `J > 38` branch, builds the `c[B.ep]` closure and returns state 48.

Thus the old `438 → 365` bounds contradiction is an **artifact of an incorrect static successor chain**, not evidence of an out-of-bounds runtime path.

The conditional steps `212`, `437`, and `314` still require the corrected successor trace to determine which branch is actually observed. Until that trace is recorded, the sequence through `145 → 212 → 437 → 283 → 314 → 121 → 42 → 48` is a source-supported candidate path, not a runtime-proven complete path.

## Environment gate

A partial Roblox shim previously died on a dynamically resolved `.cancel` access. Adding `task.cancel` together with the required Roblox-like globals/services allowed the target to continue indefinitely.

This establishes an environment-survival gate, but no evidence currently shows that the gate changes the A-layer opcode successor sequence. It determines whether execution survives long enough to continue.

## Interpreter hierarchy

The current model contains three distinct dispatcher layers:

| layer | entry | role |
|---|---|---|
| 1 | `J9` | outer loader, states 0..39 |
| 2 | `B:A` | A-layer deserializer/interpreter, hundreds of states |
| 3 | `c[B.ep]` closure built in `B:T` | inner interpreter entered through state 48 |

The level-3 closure contains the large family of micro-handlers such as `Ap`, `wp`, `vp`, `sp`, `op`, ... `z9`.

## Offline extraction requirement

The seed and size of all eleven blocks are now known. To extract them fully offline, one more value is required per block: the A-layer source base offset `q`.

In the `B:Q` state-99 call, A register `q` is passed as parameter `J`. The updated probe therefore logs:

```text
[A99] seed_in <n> seed0 <n> size <n> src <q>
```

Once the eleven `src` values are captured, `tools/extract_lcg_blocks.py` can reconstruct all eleven buffers without executing the target again.
