#!/usr/bin/env python3
"""Reachable-path checkpoint for Luraph v15 B:A entry 164.

Consumes the J9 handoff artifacts produced by luraph15_j9_replay.py and
reconstructs the first LCG-XOR buffer created by A states 245->...->99->323/228.
Fails closed on every sample-specific register/value used in the derivation.
"""
from __future__ import annotations
import argparse, collections, hashlib, json, math
from pathlib import Path

EXPECTED_Z4_164 = 35911
EXPECTED_SRC_OFF = 35915
EXPECTED_SIZE = 20936
EXPECTED_SEED_IN = 164
EXPECTED_SEED0 = 148
EXPECTED_MULT = 93
EXPECTED_INC = 155
EXPECTED_XOR = 240
EXPECTED_SHA256 = "ecdc76fa288993cd2093564fe9a8b3f50f361dbe8f3282aa977c019e9954857e"
EXPECTED_HEAD = bytes.fromhex(
    "011a160018171b1ed1e6021c1113122041e90e8c0e0e4243324c016f2e940e0f"
    "1f181c1a016f3c022e0a042e2e0000000000002ce90e8c0e090a0d0b113e0700"
)

def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def entropy(b: bytes) -> float:
    n=len(b); c=collections.Counter(b)
    return -sum((v/n)*math.log2(v/n) for v in c.values())

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--handoff', type=Path, default=Path('/mnt/data/luraph_j9_handoff.json'))
    ap.add_argument('--z7', type=Path, default=Path('/mnt/data/luraph_j9_z_7.bin'))
    ap.add_argument('-o','--out', type=Path, default=Path('/mnt/data/luraph_A_entry164_layer1.bin'))
    ap.add_argument('--receipt', type=Path, default=Path('/mnt/data/luraph_A_entry164_layer1.receipt.json'))
    a=ap.parse_args()

    h=json.loads(a.handoff.read_text())
    z4={int(k):v for k,v in h['z_summary']['4'].items()}
    z7=a.z7.read_bytes()
    assert h['A_c']==164, h['A_c']
    assert z4[164]==EXPECTED_Z4_164, z4[164]

    # Literal reachable path before the loop:
    # Gy(245): q = 1 + z4[164]; t=readu8(z7,q)
    q=1+z4[164]
    assert q==35912
    b0,b1,b2=z7[q],z7[q+1],z7[q+2]
    assert (b0,b1,b2)==(0xA3,0xC8,0x01),(b0,b1,b2)

    # Ry(300): length = (b0-128)*128 + (b1-128) + 16384*b2
    size=(b0-128)*128 + (b1-128) + 16384*b2
    src_off=q+3
    assert size==EXPECTED_SIZE,size
    assert src_off==EXPECTED_SRC_OFF,src_off

    # Q(99): seed0=(A_c+240)%256, then Sy(228):
    # key=(155 + seed*93)%256; plain=cipher XOR key XOR 240.
    seed=(EXPECTED_SEED_IN+240)%256
    assert seed==EXPECTED_SEED0
    out=bytearray(size)
    for i in range(size):
        seed=(EXPECTED_INC + seed*EXPECTED_MULT)%256
        out[i]=z7[src_off+i] ^ seed ^ EXPECTED_XOR

    digest=sha256(out)
    assert digest==EXPECTED_SHA256,digest
    assert bytes(out[:64])==EXPECTED_HEAD,bytes(out[:64]).hex()
    a.out.write_bytes(out)

    # Continue only far enough to expose the first impossible bounds invariant
    # under the current static register model.
    f=out
    # Reachable byte reads on the observed path:
    reads={i:f[i] for i in (0,1,2,3,4,5,8,9,10)}
    # mW(438) decodes f[8],f[9],f[10] into the next offset.
    decoded_off=(f[8]-128)*128 + (f[9]-128) + f[10]*16384
    rec={
        'A_entry':164,
        'z4_entry':z4[164],
        'source_offset':src_off,
        'decoded_size':size,
        'lcg':{'seed0':EXPECTED_SEED0,'mult':EXPECTED_MULT,'inc':EXPECTED_INC,'xor':EXPECTED_XOR},
        'sha256':digest,
        'entropy_bits_per_byte':entropy(out),
        'head64_hex':bytes(out[:64]).hex(),
        'reachable_prefix_states':[245,405,439,300,99,323,228,321,145,212,437,283,277,44,355,114,176,336,288,149,157,434,348,317,121,9,438,365],
        'selected_bytes':{str(k):v for k,v in reads.items()},
        'state438_decoded_offset':decoded_off,
        'state365_buffer_len':len(out),
        'state365_in_bounds':0 <= decoded_off < len(out),
        'status':'RUNTIME_PROBE_REQUIRED_AT_A365' if not (0<=decoded_off<len(out)) else 'CONTINUE_STATIC',
    }
    a.receipt.write_text(json.dumps(rec,indent=2)+'\n')
    print(json.dumps(rec,indent=2))

if __name__=='__main__':
    main()
