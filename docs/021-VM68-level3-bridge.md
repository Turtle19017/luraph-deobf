# 021 — VM68 to level-3 lazy companion bridge

## Reachable root-VM boundary

The block-1 root object reaches mode233 pc1923 through the source-closed
selector-102 path. The instruction at that slot is:

```text
B[K[1923]] = I[1923]
```

The main lanes at the same slot identify the backing prototype indices:

```text
H[1923] = 159
w[1923] = 318
```

## Companion lanes are lazy, not missing

The companion tables are finalized with metatables whose metamethod key is:

```text
B.ep = "__index"
```

and whose handler is the level-3 interpreter closure built by B:A.

Their index-0 entries point back to the associated main lanes:

```text
K[0] = H
I[0] = w
V[0] = s
v[0] = S
```

Therefore a miss such as `K[1923]` invokes the level-3 VM using the backing
main lane and requested slot. State8 begins by resolving:

```text
proto = input_table[0][key]
```

which yields:

```text
K[1923] -> proto 159
I[1923] -> proto 318
```

## Proto159 closes the old runtime trace

The previously captured first level-3 invocation:

```text
8 -> 204 -> 12 -> 94 -> 207 -> 16 -> 72 -> 68
  -> 117 -> 142 -> 117 -> 147 -> 153 -> 83
```

is now provenance-bound to the reachable root instruction:

```text
K[1923]
```

The trace's proto id is exactly 159.

The level-3 decode produces the single byte:

```text
64 hex = "d"
```

State153 caches that value into the companion table and state83 returns it.

Thus:

```text
K[1923] = "d"
```

## Proto318

The corresponding `I[1923]` lookup selects proto318.

Its decoded result is:

```text
type   string
size   2311 bytes
SHA256 d13f98e9039e98c1bb8cb2bbc9ea855cfc60f1169b86194cbe72e9d2c0c9670a
class  printable ASCII-art/text
```

The full text is intentionally not committed; only the deterministic receipt is
kept in the repository.

## First payload-level side effect

pc1923 therefore becomes:

```lua
B["d"] = <2311-byte string>
```

This is the first reached VM instruction whose effect is no longer just
bootstrap, register remapping, lane decryption, or control dispatch.

It also connects the three previously separate analysis layers into one
reachable chain:

```text
A321 serialized object
  -> VM68 root executor
  -> mode215 bootstrap
  -> mode24
  -> mode54
  -> two bulk XOR lane passes
  -> mode233 selector tree
  -> companion-lane __index miss
  -> level-3 proto VM
  -> decoded program constant
```

The next useful step is to continue mode233 from pc1924 using the now-resolved
side effect and to resolve the next companion miss only when it is actually
reached.
