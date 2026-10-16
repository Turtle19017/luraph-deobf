#!/usr/bin/env python3
"""Static stage-1 extractor for this Luraph v15 Luau layout.

Pipeline recovered from the outer J9 state machine:
  Y9 long string -> strip 4-byte magic -> gsub(j9, M9) -> custom 85-radix 5->4 decoder

The 5 input digits d0..d4 are ASCII(code)-35 and are combined as:
  V = d3*85^0 + d0*85^1 + d1*85^2 + d4*85^3 + d2*85^4
Then V is written as little-endian uint32, matching buffer.writeu32.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def lua_unescape(s: str) -> str:
    """Decode the small subset of Lua quoted-string escapes needed here."""
    out = []
    i = 0
    simple = {
        'a': '\a', 'b': '\b', 'f': '\f', 'n': '\n', 'r': '\r',
        't': '\t', 'v': '\v', '\\': '\\', '"': '"', "'": "'",
    }
    while i < len(s):
        ch = s[i]
        if ch != '\\':
            out.append(ch)
            i += 1
            continue
        i += 1
        if i >= len(s):
            out.append('\\')
            break
        ch = s[i]
        if ch in simple:
            out.append(simple[ch])
            i += 1
        elif ch.isdigit():
            j = i
            while j < len(s) and j < i + 3 and s[j].isdigit():
                j += 1
            out.append(chr(int(s[i:j], 10) & 0xff))
            i = j
        elif ch == 'x' and i + 2 < len(s):
            out.append(chr(int(s[i + 1:i + 3], 16)))
            i += 3
        elif ch == 'z':
            # Lua \z skips following whitespace.
            i += 1
            while i < len(s) and s[i].isspace():
                i += 1
        else:
            # Keep an unknown escape conservatively as its escaped char.
            out.append(ch)
            i += 1
    return ''.join(out)


def extract_long_string(src: str, name: str) -> str:
    # Handles [=[...]=], [==[...]==], etc.
    rx = re.compile(rf'{re.escape(name)}=\[(=*)\[(.*?)\]\1\]', re.S)
    m = rx.search(src)
    if not m:
        raise ValueError(f'cannot find long-string assignment for {name}')
    return m.group(2)


def extract_m9(src: str) -> dict[str, str]:
    m = re.search(r'M9=\{(.*?)\},[A-Za-z_][A-Za-z0-9_]*=function', src, re.S)
    if not m:
        raise ValueError('cannot find M9 table')
    body = m.group(1)

    token = re.compile(
        r'(?:([A-Za-z_][A-Za-z0-9_]*)|\["((?:\\.|[^"\\])*)"\])'
        r'="((?:\\.|[^"\\])*)"'
    )
    mapping: dict[str, str] = {}
    for mm in token.finditer(body):
        bare_key, quoted_key, raw_value = mm.groups()
        key = bare_key if bare_key is not None else lua_unescape(quoted_key)
        value = lua_unescape(raw_value)
        mapping[key] = value

    if not mapping:
        raise ValueError('M9 parsed as empty table')
    return mapping


def extract_j9(src: str) -> str:
    m = re.search(r'j9="((?:\\.|[^"\\])*)"', src)
    if not m:
        raise ValueError('cannot find j9 pattern')
    return lua_unescape(m.group(1))


def expected_match_chars_from_j9(pattern: str) -> set[str]:
    # This sample uses the exact Lua pattern class: [ -"x-~]
    if pattern != '[ -"x-~]':
        raise ValueError(f'unexpected j9 pattern {pattern!r}; refusing to guess')
    return {chr(i) for i in range(32, 35)} | {chr(i) for i in range(120, 127)}


def apply_antitransform(text: str, mapping: dict[str, str], match_chars: set[str]) -> tuple[str, int]:
    missing = sorted(ch for ch in match_chars if ch not in mapping)
    if missing:
        raise ValueError(f'M9 missing replacements for: {missing!r}')
    n = sum(ch in match_chars for ch in text)
    return ''.join(mapping[ch] if ch in match_chars else ch for ch in text), n


def decode_custom85(text: str) -> bytes:
    if len(text) % 5:
        raise ValueError(f'base85 text length {len(text)} is not divisible by 5')

    alphabet = set(text)
    bad = sorted(ch for ch in alphabet if not (35 <= ord(ch) <= 119))
    if bad:
        raise ValueError(f'characters outside ASCII 35..119 after anti-transform: {bad!r}')

    out = bytearray(len(text) // 5 * 4)
    w = 0
    for i in range(0, len(text), 5):
        d0, d1, d2, d3, d4 = (ord(c) - 35 for c in text[i:i + 5])
        v = d3 + d0 * 85 + d1 * (85 ** 2) + d4 * (85 ** 3) + d2 * (85 ** 4)
        if not 0 <= v <= 0xFFFFFFFF:
            raise ValueError(f'group at {i // 5} decodes outside uint32: {v}')
        out[w:w + 4] = v.to_bytes(4, 'little')
        w += 4
    return bytes(out)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument('script', type=Path)
    ap.add_argument('-o', '--out', type=Path, default=Path('luraph_stage1.bin'))
    ap.add_argument('--receipt', type=Path, default=None)
    args = ap.parse_args()

    raw = args.script.read_bytes()
    src = raw.decode('utf-8')

    payload = extract_long_string(src, 'Y9')
    if len(payload) < 4:
        raise ValueError('Y9 is too short')
    magic = payload[:4]
    encoded = payload[4:]

    j9 = extract_j9(src)
    m9 = extract_m9(src)
    match_chars = expected_match_chars_from_j9(j9)
    transformed, replacements = apply_antitransform(encoded, m9, match_chars)

    alphabet = ''.join(sorted(set(transformed)))
    expected_alphabet = ''.join(chr(i) for i in range(35, 120))
    if alphabet != expected_alphabet:
        raise ValueError(
            'post-gsub alphabet is not exactly contiguous ASCII 35..119; '
            f'got {len(alphabet)} symbols'
        )

    decoded = decode_custom85(transformed)
    args.out.write_bytes(decoded)

    receipt = {
        'input': str(args.script),
        'input_size': len(raw),
        'input_sha256': sha256_bytes(raw),
        'y9_length': len(payload),
        'magic': magic,
        'encoded_length_after_magic': len(encoded),
        'j9': j9,
        'm9': m9,
        'gsub_replacement_count': replacements,
        'post_gsub_length': len(transformed),
        'post_gsub_sha256': sha256_bytes(transformed.encode('utf-8')),
        'alphabet_size': len(alphabet),
        'alphabet_ord_min': min(map(ord, alphabet)),
        'alphabet_ord_max': max(map(ord, alphabet)),
        'groups_5_to_4': len(transformed) // 5,
        'decoder_weights_by_input_index': [85, 85**2, 85**4, 1, 85**3],
        'decoded_size': len(decoded),
        'decoded_sha256': sha256_bytes(decoded),
        'decoded_head_hex': decoded[:64].hex(),
    }

    receipt_path = args.receipt or args.out.with_suffix(args.out.suffix + '.json')
    receipt_path.write_text(json.dumps(receipt, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')

    print(json.dumps(receipt, indent=2, ensure_ascii=False))


if __name__ == '__main__':
    main()
