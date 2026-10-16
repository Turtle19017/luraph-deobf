# 018 — A321 bytecode IR and block-1 VM entry

## From serializer fields to VM execution fields

The source-level handoff after `B:A` is:

```lua
Z = B:A(...)
B[Z[Z[1]]](B, nil, B.y, Z)
```

Phase-5 parsing established that the second late metadata integer is stored at
`q[q[1]]`. For block #1 that value is `68`.

Therefore block #1 dispatches into:

```text
B[68]
```

This is the first point where a previously anonymous serialized field has an
exact runtime meaning:

```text
dispatch_id = q[q[1]]
```

## B[68] object-field resolution

The `B[68]` executor first resolves its fields indirectly through the object
`q`.

The important source assignments are equivalent to:

```text
aux_I     = q[q[11]]
entry_pc  = q[q[6]]
aux_v     = q[q[15]]

aux_V     = q[q[16]]
aux_K     = q[q[14]]
lane_S    = q[q[12]]
vm_mode   = q[q[7]]
opcode    = q[q[10]]
stack_sz  = q[q[9]]
lane_w    = q[q[13]]
lane_H    = q[q[8]]
```

The executor allocates its register frame with:

```text
registers = table.create(stack_sz)
```

and initializes its instruction pointer from `entry_pc`.

For block #1:

```text
dispatch_id = 68
vm_mode     = 215
entry_pc    = 4453
stack_size  = 130
slot_count  = 4474
```

The fact that `entry_pc=4453` lies inside the common 4474-element parallel
arrays is consistent with `count` being the virtual instruction-slot count.

## Serializer field meanings now established

Several formerly anonymous fields can now be renamed.

### VM mode

The invariant serialized integer `215` is stored through the key in `q[7]`:

```text
q[q[7]] = 215
```

`B[68]` reads this as the execution mode. Its body contains distinct
interpreter branches, including the observed `mode == 215` branch.

Thus:

```text
tag215 -> vm_mode
```

### Entry PC

The serialized integer immediately after `meta16/meta5` is stored through
`q[6]`:

```text
q[q[6]] = secondary_integer
```

`B[68]` reads that field as the initial instruction pointer.

Thus:

```text
secondary_integer -> entry_pc
```

For block #1:

```text
entry_pc = 4453
```

### Stack size

The first phase-5 metadata integer is stored at the dynamic key already held in
`q[9]`:

```text
q[q[9]] = phase5_integer_A
```

`B[68]` uses the value as the argument to `table.create` for the VM register
frame.

Thus:

```text
phase5_integer_A -> stack_size
```

For block #1:

```text
stack_size = 130
```

### Dispatch ID

The second phase-5 metadata integer is stored through `q[1]`:

```text
q[q[1]] = phase5_integer_B
```

The outer handoff uses exactly this field as the numeric method selector.

Thus:

```text
phase5_integer_B -> dispatch_id
```

For block #1:

```text
dispatch_id = 68
```

### Late field-key descriptors

The byte previously called `meta16` is stored directly as `q[16]`; it is
later used as the indirect key for `aux_V`.

The byte previously called `meta5` is stored as `q[5]`; state55 later
creates the phase-4 range/RLE result table at `q[q[5]]`.

The first post-second-table scalar is stored as `q[9]`; it becomes the
indirect key for `stack_size`.

The second post-second-table scalar is stored as `q[1]`; it becomes the
indirect key for `dispatch_id`.

The third late phase-5 integer is stored directly as `q[8]`; it becomes the
indirect key used to install table4.

These fields are therefore primarily **field-key descriptors**, not program
payload values.

## Eight parallel instruction lanes

The four serialized count-sized tables bind directly to the VM:

```text
table1 -> lane_S -> q[q[12]]
table2 -> lane_w -> q[q[13]]
table3 -> opcode -> q[q[10]]
table4 -> lane_H -> q[q[8]]
```

Four companion arrays are allocated alongside them:

```text
aux_v -> q[q[15]]   companion of table1
aux_I -> q[q[11]]   companion of table2
aux_V -> q[q[16]]   companion of table3
aux_K -> q[q[14]]   companion of table4
```

The `mode == 215` interpreter indexes these arrays by the same program counter.
For example:

```lua
local opcode = s[pc]
```

where runtime local `s` is `q[q[10]]`, i.e. serialized table3.

This establishes:

```text
table3 = opcode lane
```

and table1/table2/table4 are operand lanes used as `S[pc]`, `w[pc]`, and
`H[pc]`.

The companion arrays are auxiliary per-slot lanes used by selected opcodes and
runtime rewriting. Their complete population semantics are not promoted yet.

## Block-1 entry trampoline

The block-1 lane tuples around `entry_pc=4453` are:

```text
pc    S    w      opcode H
4453  12   1      52    0
4454  15   77     39    0
4455  88   78     24    0
4456  43   79     24    0
4457  72   58     24    0
4458  87   48     39    0
4459  19   50     24    0
4460  25   80     24    0
4461  61   10     24    0
4462 114   81     39    0
4463  23   82     24    0
4464  20   83     24    0
4465  47   84     24    0
4466  96   85     39    0
4467  22   86     24    0
4468  97   87     24    0
4469   8   11     24    0
4470   0   10     32   19
4471   0   10     15    0
```

Source semantics for the executed slots are:

```text
4453 opcode 52
  R[12] = current object

4454 opcode 39
  bulk move four register pairs
  consumes slots 4454..4457

4458 opcode 39
  consumes slots 4458..4461

4462 opcode 39
  consumes slots 4462..4465

4466 opcode 39
  consumes slots 4466..4469

4470 opcode 32
  R[10] = 19

4471 opcode 15
  sets pc base to lane_w[4471] = 10
  normal loop increment makes next executed pc = 11
```

The four bulk-move groups are:

```text
15 -> 77    88 -> 78    43 -> 79    72 -> 58
87 -> 48    19 -> 50    25 -> 80    61 -> 10
114 -> 81   23 -> 82    20 -> 83    47 -> 84
96 -> 85    22 -> 86    97 -> 87     8 -> 11
```

At pc 11:

```text
S=46
w=12326
opcode=23
H=74
```

Opcode 23 is source-derived as a self-rewrite/decode operation. It rewrites the
current instruction-lane entries and decrements the program counter so that the
same slot is executed again after the normal loop increment.

This explains why raw serialized lanes can contain values that are not valid
final runtime opcodes or operands: some instruction slots are transformed
in-place before their semantic operation executes.

## Consequence

The project has crossed from binary-format recovery into virtual-bytecode
lifting.

The next useful abstraction is no longer:

```text
table1 / table2 / table3 / table4
```

but:

```text
VMObject {
    dispatch_id
    vm_mode
    entry_pc
    stack_size

    opcode[slot]
    S[slot]
    w[slot]
    H[slot]

    aux_v[slot]
    aux_I[slot]
    aux_V[slot]
    aux_K[slot]

    phase4_range_table
}
```

The next semantic task is to lift reachable `mode=215` opcodes, beginning with
the block-1 bootstrap and its self-rewriting pc 11.
