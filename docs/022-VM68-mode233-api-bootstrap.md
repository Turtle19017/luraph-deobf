# 022 — Mode233 API bootstrap and lazy constant repair

## Why some level-3 proto offsets looked impossible

Several companion lookups in the reachable mode233 path initially appeared to
reference impossible offsets such as:

```text
proto44 -> 263942668
proto46 -> 263891360
proto48 -> 263891762
```

Those are not final cursors.

The reusable mode233 trampoline at pc49..58 uses opcode34. Its source semantics
are:

1. select a proto/index entry,
2. XOR the stored cursor value with `263872163`,
3. write the repaired cursor back,
4. read the encoded payload length at that cursor,
5. XOR the payload bytes with the instruction's `w` lane,
6. rewrite the current VM slot.

Thus the large values are lazy-protected index entries, not invalid data.

## Reachable pc49..58 repair hub

The deterministic selector-102 bootstrap reaches pc49..58 before the first
payload-level assignment.

The ten repairs are:

```text
pc49  proto81   xor 1    -> "traceback"
pc50  proto101  xor 30   -> "IsClient"
pc51  proto113  xor 140  -> "Random"
pc52  proto44   xor 211  -> "spawn"
pc53  proto119  xor 62   -> "GetChildren"
pc54  proto46   xor 29   -> "wait"
pc55  proto111  xor 55   -> "GetPositionOnCurveArcLength"
pc56  proto39   xor 238  -> "RequestAsync"
pc57  proto48   xor 109  -> "defer"
pc58  proto126  xor 230  -> ">I4"
```

After this first visit the rewritten hub slots are inert for later passes, while
pc59 acts as the central indirect trampoline through `R37`.

## Level-3 string codec

For direct or repaired string proto records:

```text
tag       0x2d
length    serialized 1/2/3/4-byte integer
seed0     (61 + proto) mod 256

for each ciphertext byte:
    seed = (155 + 93*seed) mod 256
    plain = cipher XOR seed XOR 61
```

This reproduces:

```text
proto159 -> "d"
proto318 -> 2311-byte ASCII-art string
proto218 -> "task"
proto85  -> "cancel"
proto103 -> "delay"
proto98  -> "Instance"
proto193 -> "Vector3"
proto157 -> "identifyexecutor"
proto345 -> "islclosure"
```

and the repaired proto44/46/48 strings above.

## pc1924..1931 now reads like source

After pc1923 installs the first decoded payload constant, execution continues
sequentially:

```lua
R34  = getfenv()["task"]
R35  = R34["cancel"]
R36  = R34["spawn"]
R38  = R34["defer"]
R40  = R34["delay"]
R49  = R34["wait"]

R42  = getfenv()["Instance"]
R102 = getfenv()["Vector3"]
```

So the root VM is no longer only manipulating opaque integers: it is explicitly
collecting Roblox/Luau runtime APIs.

## Continuation at pc2122

pc1932 sets:

```text
R37 = 2121
```

and pc1933 re-enters the reusable pc49..59 trampoline, selecting pc2122.

Two additional opcode34 records repair more lazy string protos:

```text
pc2122 proto338 xor 68  -> "Vector2"
pc2124 proto223 xor 169 -> "CFrame"
```

The following globals are then installed:

```lua
R103 = getfenv()["Vector2"]
R22  = getfenv()["CFrame"]
R104 = getfenv()["Random"]
R77  = getfenv()["identifyexecutor"]
R78  = getfenv()["islclosure"]
```

pc2129 is a reachable mode233 opcode82 bulk-XOR pass:

```text
start  = 3964
length = 17
end    = 3980
seed   = 124
```

pc2130 then sets `R37=3963` and pc2131 returns through the central trampoline,
entering the newly decoded block at pc3964.

That block seeds a new selector value:

```text
R88 = 135
```

and returns to the mode233 decision tree. Analysis of that selector is kept
separate until a source-level side effect or call boundary is reached.
