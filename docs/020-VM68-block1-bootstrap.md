# 020 — Block-1 VM68 bootstrap and first body XOR layer

## Finalized-lane correction

The finalized-lane probe v2 originally appeared to show one mutation:

```text
pc4470 lane w
serialized expected 10
finalized          37
```

That was a validator bug, not a runtime mutation.

The verified block-1 plaintext contains:

```text
pc4468  57 hex -> 87
pc4469  0b hex -> 11
pc4470  25 hex -> 37
pc4471  0a hex -> 10
```

The expected value for pc4470 had been copied from pc4471.

After correction:

```text
sampled bootstrap main lanes unchanged = 19 / 19
pc11 main lanes unchanged              = true
sampled aux lanes                      = nil
B[3] at outer handoff                  = nil
```

Thus the positive-index main lanes sampled around the bootstrap can be lifted
directly from the runtime-verified plaintext.

## Mode-215 bootstrap

The block-1 executor begins with:

```text
dispatch_id = 68
mode        = 215
entry_pc    = 4453
stack_size  = 130
```

The deterministic bootstrap proceeds:

```text
4453..4471
  initialize/copy register frame
  pc4470: R37 = 19
  pc4471: jump base 10 -> pc11

pc11
  opcode23 self-rewrites:
    (S=46,w=12326,op=23,H=74)
      ->
    (S=0,w=0,op=1,H=37)

  rewritten opcode1 jumps through R37
  R37=19 -> next pc20

pc20..26
  lazy self-rewrites
  pc25: R37 = 4441
  pc26 -> pc11
  pc11 -> next pc4442

pc4442..4452
  register remap
  pc4451: R37 = 59
  pc4452 -> pc11
  pc11 -> next pc60

pc60..75
  register remap / lazy decode
  pc66: R37 = 67
  pc67 -> pc11
  pc11 -> pc68

pc75
  self-rewrites to opcode48:
    mode = 24
    pc   = 42
```

## Mode-24 trampoline

Mode 24 uses the serialized `w` lane as its opcode selector.

Several raw `w=44` instructions self-rewrite into small semantic opcodes.

The trampoline makes three passes through pc76:

```text
pc47  -> opcode16 -> R37 = 3
pc48  -> opcode22 -> pc76
pc76  -> opcode54 -> indirect through R37 -> pc4

pc9   -> opcode16 -> R37 = 12
pc10  -> opcode22 -> pc76
pc76  -> opcode54 -> indirect through R37 -> pc13

pc18  -> opcode16 -> R37 = 35
pc19  -> opcode22 -> pc76
pc76  -> opcode54 -> indirect through R37 -> pc36
```

At pc41, the self-rewrite produces:

```text
S = 26
w = 0
s = 54
H = 0
```

Mode-24 opcode 0 switches interpreter mode:

```text
mode = s[41] = 54
pc   = S[41] + 1 = 27
```

## Mode-54 setup and bulk lane decryption

Mode54 uses the `H` lane as its opcode selector.

After three short two-slot move groups at pc27/29/31, pc33 is:

```text
pc33
S = 44
w = 4357
s = 84
H = 84
```

Mode54 opcode 84 is a bulk XOR lane transform:

```text
start  = s[33] + 1 = 85
length = w[33]     = 4357
end    = 4441

for i = 1..4357:
    mask = (S[33] XOR i) & 0x7f

    S[84+i] ^= mask
    w[84+i] ^= mask
    s[84+i] ^= mask
    H[84+i] ^= mask
```

This decrypts the four main lanes for the entire body region:

```text
85 .. 4441
```

while leaving the outer bootstrap at `4442..4474` untouched.

The source operation also sets the current opcode slot to 87 after applying the
range transform.

## Lane fingerprints

For slots 85..4441, u32-le SHA-256 values are:

```text
before
S 01083987c972a00eeb94f5f3dfb6f0fbc3d80417d957ca7922470cb2181674f4
w 24e56ec1ef8daed66bafb9c5f01b290fab2f78e49a310327383e92922c0e065b
s 18030a26c115d0afd5372390401778dbedef8f621299de2e48866b82341f8474
H 9d2fa48f94c2ba84ba5bf4b975a138702b188525dcc06532d6af4b4c0b19e0a0

after
S b90ec9082dc69a72d5621308ebfdb89a4a26e877f562992f0f394d58db08fe9a
w fb47d0d925c0e14a9761973d52628e9193700ef0ec2b33dc19e398a690627ffb
s 01a897697dc9182fd073d550bb6d138dd649afc4003f9ba00ebc0ce0af9410c7
H ad6c1f91a4556f73220e03a215aceab82ee44d69ea86d817b2d7daa636ca70e0
```

The first decoded body tuples are recorded in:

```text
receipts/luraph_VM68_block1_bootstrap_lift.summary.json
```

## Correct continuation after pc35

A previous revision assigned opcode-72 semantics from the wrong VM mode and
incorrectly described pc35 as a nil-call.

The authoritative `cR == 54` source branch says:

```text
mode54 opcode72:
    l = s[l]
```

Therefore:

```text
pc35
  rewritten tuple = (S=0, w=0, s=11, H=72)
  l = 11
  common increment -> pc12
```

pc12 is another mode54 lazy-rewrite slot:

```text
raw       (S=2574, w=1, s=60, H=20)
rewritten (S=0,    w=37, s=0, H=80)
```

Mode54 opcode80 is an indirect jump through the register frame:

```text
l = R[w]
```

At this point pc34 has already set `R37=84`, hence:

```text
pc12 -> l=R37=84
common increment -> pc85
```

So the first bulk XOR pass at pc33 decrypts slots `85..4441` and the bootstrap
then enters that decrypted body at pc85.

## Reachable second XOR layer

The first decoded body instructions are deterministic:

```text
pc85  opcode26  paired register move
pc87  opcode26  paired register move
pc89  lazy rewrite -> opcode39
pc90  opcode84
```

pc90 is therefore reachable. Its second bulk lane transform is:

```text
seed   = S[90] = 11
start  = s[90] + 1 = 93
length = w[90] = 4349
end    = 4441

for i = 1..4349:
    mask = (11 XOR i) & 0x7f
    XOR mask into S/w/s/H at slot 92+i
```

After this pass:

```text
pc91 -> lazy rewrite -> opcode45 -> R37 = 3947
pc92 -> lazy rewrite -> opcode72 -> base=11
pc12 -> opcode80 -> indirect through R37
next executed pc = 3948
```

This closes two nested XOR layers over the VM body.

## J9 handoff semantics

The outer J9 state12 handler does:

```text
object  = B:A(...)
closure = B[object[object[1]]](B, nil, B.y, object)
next J9 state = 4
```

J9 state4 is handled by `ZW`, whose selected branch returns control code 2.
The J9 dispatcher responds by returning the carried closure.

Thus J9 itself does not invoke the VM closure.

The source chunk ends as:

```text
...:J9()(...)
```

so the closure returned by J9 is then invoked by the top-level call with the
chunk varargs.

## Reachable mode-233 transition

The deterministic mode54 path continues through register-bank setup and reaches:

```text
pc1138
  mode54 opcode25
  mode = w[1138] = 233
  pc   = s[1138] + 1 = 2409
```

Mode233 then dispatches through a decision tree driven by the known bootstrap
constant:

```text
R88 = 102
```

A source-closed prefix is:

```text
pc2409  if R88 <= 71   -> false
pc2410  jump -> pc1573

pc1573  R37 = 1516
pc1574  central trampoline -> pc49

pc49..58
  opcode34 backing-buffer/lazy-rewrite records

pc59
  lazy rewrite -> opcode4
  indirect through R37
  -> pc1517

pc1517  if R88 <= 107  -> true  -> pc1555
pc1555  R7 = (R88 <= 89)  -> false
pc1556  branch on R7       -> pc3865
pc3865  branch on R7       -> pc3955
pc3955  R4 = (R88 <= 98)   -> false
pc3956  branch on R4       -> pc1173
pc1173  branch on R4       -> pc1315
pc1315  if R88 <= 102      -> true  -> pc4235
pc4235  R1 = (R88 <= 100)  -> false
pc4236  branch on R1       -> pc1547
pc1547  R2 = (R88 <= 101)  -> false
pc1548/1536 branch chain   -> pc1923
```

At pc1923 the first currently unresolved semantic dependency is reached:

```text
mode233 opcode76:
    B[K[1923]] = I[1923]
```

`K` and `I` are companion lanes. Their positive indices are not serialized
densely; they are finalized as metatable-backed auxiliary tables. The next
analysis target is therefore the companion-lane metatable/lazy-lookup semantics,
not another main-lane XOR layer.

The earlier statement that pc35 was a deterministic nil call is revoked.
