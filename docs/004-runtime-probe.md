# Report 004 — Runtime probe for the `438 → 365` divergence

## Purpose

The static replay reaches a bounds contradiction after decoding the 20,936-byte inner layer. The minimal probe instruments only the relevant states without replacing the target decoder or changing its control flow.

Probe generator:

```text
tools/make_A_probe.py
```

It takes the analyst-owned local `script.txt` and creates `script_A_probe.luau`; the protected target itself is not committed.

## Expected trace under the current static model

The useful lines begin with these markers:

```text
[A99]
[A228]
[A321]
[A438]
[A365]
```

Current expected values are approximately:

```text
[A99]  size 20936 seed_in 164 seed0 148
[A228] seed 148 inc 155 mult 93 xor 240 src 35915 key 95 cipher 174
[A321] len 20936 first 1 next 145
[A438] J 209 r 230 k 2 decoded 43238 cursor 8
[A365] buflen 20936 offset 43238 ...
```

## Decision rule

- If one of these values differs at runtime, the first differing line identifies the earliest incorrect register mapping in the Python replay.
- If every line agrees and Luau then raises an out-of-bounds error, the model has reproduced the real path and the next task is to identify the runtime condition that makes the original protected program avoid or transform that path.

No speculative correction should be promoted before this probe is checked.
