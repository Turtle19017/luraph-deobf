# 023 — Reachable native-builtin registration chain

## Lazy helper object

Selector 121 reaches:

```text
pc1226  opcode34 repair proto268, XOR 144
pc1227  opcode70 construct child -> R85
```

Proto268 decrypts to a new 2271-byte A321 object:

```text
SHA256 78cf8d146a4ae5ea6ee213bf183ec0fbd586b5bf89d298de1f527ce08c035ad9

count       474
vm_mode     215
entry_pc    9
stack_size  36
dispatch_id 68
```

This object was not part of the original eleven runtime-dumped plaintexts. It
is lazily reached by the running root VM.

Immediately after construction, R85 is repeatedly called with pairs of the
form:

```text
(native builtin, exact decoded name)
```

The function/name agreement is independently established from two sides:

1. the static B-table assignment in the protected source, and
2. the level-3 string decoded through the reconstructed J9 z4/z7 maps.

That is strong enough to describe R85 as a native-builtin registration/bootstrap
helper, while leaving its internal implementation for a later child-VM lift.

## Selector 121 — core Lua/Luau builtins

The reachable pairs include:

```text
getmetatable  "getmetatable"
setmetatable  "setmetatable"
tonumber      "tonumber"
tostring      "tostring"
rawset        "rawset"
rawget        "rawget"
select        "select"
xpcall        "xpcall"
assert        "assert"
```

Selector 121 then sets R88 to 39.

## Selector 39 — environment and string helpers

```text
error         "error"
pcall         "pcall"
type          "type"
next          "next"
getfenv       "getfenv"
setfenv       "setfenv"
typeof        "typeof"
string.gmatch "gmatch"
string.format "format"
string.match  "match"
```

The path also aliases:

```text
R47 = string.find
```

and transitions to selector 57.

## Selector 57 — string/table helpers

```text
string.char    "char"
string.byte    "byte"
string.gsub    "gsub"
string.sub     "sub"
string.rep     "rep"
string.unpack  "unpack"
string.pack    "pack"
table.concat   "concat"
table.insert   "insert"
table.pack     "pack"
```

Then:

```text
R47 = table.clear
R88 = 112
```

## Selector 112 — table + bit32

```text
table.clear    "clear"
table.create   "create"
table.move     "move"

bit32.bor      "bor"
bit32.bnot     "bnot"
bit32.bxor     "bxor"
bit32.band     "band"
bit32.lshift   "lshift"
bit32.rshift   "rshift"
bit32.rrotate  "rrotate"
bit32.lrotate  "lrotate"
```

The next selector is 28.

## Selector 28 — buffer bootstrap

A large reachable XOR pass opens slots 2758..3828, after which R85 registers:

```text
bit32.countlz      "countlz"
bit32.countrz      "countrz"

buffer.len         "len"
buffer.fill        "fill"
buffer.copy        "copy"
buffer.create      "create"
buffer.tostring    "tostring"
buffer.fromstring  "fromstring"
buffer.readstring  "readstring"
buffer.writestring "writestring"
```

The path then sets selector 107.

The selector-107 prefix continues with:

```text
buffer.readu8   "readu8"
buffer.readi16  "readi16"
```

and opens another encoded block. That later buffer-API sequence remains the
current reachable frontier.

## Object-corpus scope correction

The original statement that the eleven captured A321 plaintexts have complete
framing remains correct **for those eleven captured objects**.

It is not a claim that the reachable object graph contains only eleven objects.

Selector 121 proves that proto268 is another A321 object materialized lazily
during VM execution. Future reachable proto-80 records may add more objects.
