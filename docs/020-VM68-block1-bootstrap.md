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

## Current fail-closed boundary

After the bulk decrypt:

```text
pc34
  self-rewrites to mode54 opcode45
  R37 = 84

pc35
  self-rewrites to:
    S = 0
    w = 0
    s = 11
    H = 72
```

Mode54 opcode 72 has source semantics:

```text
R[w] = R[H](R[s])
```

so pc35 is:

```text
R0 = R72(R11)
```

The current static bootstrap proof does not yet establish the runtime values
or types of `R72` and `R11`.

Therefore reachable execution is stopped at pc35 rather than inventing a
function value or skipping the call.

A second opcode-84-shaped record is visible at pc90 after the first body XOR
pass and describes a suffix range `93..4441`. It is **not** yet promoted as a
reachable second decryption layer because doing so requires crossing the pc35
runtime-register boundary first.

## Offline lifter

`tools/lift_vm68_block1_bootstrap.py` reproduces the bootstrap transforms and
the first bulk XOR layer directly from the verified block-1 plaintext.

Run:

```bash
python tools/lift_vm68_block1_bootstrap.py \
  _probe/a321_plaintexts/block01_seed164.bin \
  --json _probe/vm68_block1_bootstrap.json
```

No target execution is required.
