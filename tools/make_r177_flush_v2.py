#!/usr/bin/env python3
"""R177 stdout flush diagnostic — patch only an already-built local harness.

Creates a throwaway stdout-pipe smoke script and an R177 v2 harness.
Does NOT execute the Luau CLI, change script.txt, or touch the previous capture.
This is a diagnostic adaptation; it is not evidence of R177 execution.
"""

import argparse
import hashlib
from pathlib import Path

FLUSH = 'print((" "):rep(131072))'
MARKERS = {
    'runner': 'print("[runner] === probe start ===")',
    'r177_pre': "'argpack_n',rawget(n,J));end;",
    'r177_post': "print((' '):rep(4096));error('__R177_DONE__');",
}


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f'FAIL {label}: expected one anchor, got {count}')
    return text.replace(old, new, 1)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('built_harness', type=Path,
                   help='The run_R177_probe.luau built at HEAD d0df8b2')
    p.add_argument('-o', '--output', type=Path,
                   default=Path('run_R177_flush_v2.luau'))
    p.add_argument('--smoke-output', type=Path,
                   default=Path('r177_stdout_pipe_smoke.luau'))
    args = p.parse_args()
    if args.output.resolve() == args.built_harness.resolve():
        raise SystemExit('FAIL: refusing to overwrite the original built harness')
    if args.smoke_output.resolve() == args.built_harness.resolve() or args.smoke_output.resolve() == args.output.resolve():
        raise SystemExit('FAIL: output paths must be distinct')

    raw = args.built_harness.read_bytes()
    src = raw.decode('utf-8-sig')
    if src.count('[R177PRE]') != 1 or src.count('[R177POST]') != 1:
        raise SystemExit('FAIL: original PRE/POST marker count is not exactly one each')
    if '__R177_DONE__' not in src:
        raise SystemExit('FAIL: R177 terminal marker is missing')

    patched = replace_once(src, MARKERS['runner'],
                           MARKERS['runner'] + '\n' + FLUSH, 'runner')
    patched = replace_once(patched, MARKERS['r177_pre'],
                           "'argpack_n',rawget(n,J));" + FLUSH + ';end;', 'r177_pre')
    patched = replace_once(patched, MARKERS['r177_post'],
                           FLUSH + ";error('__R177_DONE__');", 'r177_post')

    args.output.write_text(patched, encoding='utf-8', newline='\n')
    # Smoke deliberately does not exit, to reproduce stdout buffering on forced termination.
    args.smoke_output.write_text(
        'print("[PIPE_SMOKE] before forced timeout")\n'
        + FLUSH + '\n'
        'while true do end\n', encoding='utf-8', newline='\n')

    sha = hashlib.sha256(raw).hexdigest()
    print(f'input harness sha256: {sha}')
    print('anchors patched: runner=1, R177PRE=1, R177POST=1')
    print(f'wrote v2 harness: {args.output}')
    print(f'wrote independent pipe smoke: {args.smoke_output}')
    print('NO Luau execution performed')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
