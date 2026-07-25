#!/usr/bin/env python3
"""tok_diff.py — decode + diff two BCF canonical-goal byte streams.

The single most decisive instrument of the 2026-07-12 session: it closed
0x003e1542d2fdd1d6 (children_unsafe marking gap, alivio fix 7d77c68) and
0xb809d31ada13b036 (csum_diff orphan bound-pair, alivio fix 1bb382b) by
showing the EXACT conjunct-level delta between the kernel-queried goal
and alivio's nearest emission.

Accepts either source format for each input:
  * kernel dmesg chunks:  lines containing `hash=0x<H> off=<N> bytes: ..`
    (grep them from dmesg/serial capture into a file; chunks are
    reassembled by offset)
  * alivio census line:    a single line `.. bytes: ..` or a bare
    whitespace-separated hex byte stream
    (e.g. `grep -m1 'hash=0x<H> bytes:' census.log | sed 's/.*bytes: //'`)

Usage:
  tok_diff.py A.txt B.txt          # unified diff of decoded token streams
  tok_diff.py A.txt                # render one goal as readable conjuncts

Token encoding (observed, stable since probe era):
  01 18 00 WW 00 ID ID 00 00                      VAR   (WW: 0x20=32b 0x40=64b)
  02 08 01 20 00 V V V V                          CONST32
  02 08 02 40 00 V V V V V V V V                  CONST64
  03 OP 02 00 00                                  BINOP over 2 stack operands
  03 01 AR 00 00                                  terminating AND, arity AR
Ops: 11 '==' | 51 '!=' | b1 'u<=' | d1 's<=' | 31 's<' | 50 '&' |
     60 '<<' | 70 '>>' | 71 'u>' | 00 'op00(zext/sext?)'
Unary (arity byte 1, params in bytes 3-4):
  03 58 01 TO FROM   ZEXT  (e.g. 03 58 01 40 20 = zext64 of a 32-bit expr)
  03 38 01 HI LO     EXTRACT (e.g. 03 38 01 00 1f = extract bits 31..0)
A conjunct fails to decode -> printed raw; extend the table, don't guess.

Reading the diff (the divergence taxonomy, one line each):
  * extra conjunct = orphaned BOUND-PAIR on a var only one side has
      -> return-range narrowing divergence (see alivio_narrower_than_kernel
         pre-cache list, transfer/call/transfer.rs; fix 1bb382b pattern)
  * same slot, (vN op K) vs (K' op K) folded
      -> value collapsed on one side (replay-base placement or state
         divergence; check base/rung and where the value was narrowed)
  * same count, one 64-bit anchor vs 32-bit folded pair
      -> different demanded edge (route/lineage question; check
         children_unsafe marking and [ZK refine] base data first —
         fix 7d77c68 pattern)
  * whole blocks differ mid-stream
      -> different route arm (dispatch fork); census the lineages (rung=)
Widths NEVER lie: a 64-bit conjunct cannot come from a 32-bit insn (JNE32
etc.). Check widths before any route theory.
"""
import re
import sys
import difflib

OPS = {0x11: '==', 0x51: '!=', 0xb1: 'u<=', 0xd1: 's<=', 0x31: 's<',
       0x50: '&', 0x60: '<<', 0x70: '>>', 0x71: 'u>', 0x00: 'op00'}
UNARY = {0x58: 'zext', 0x38: 'extract'}


def load_bytes(path):
    text = open(path).read()
    chunks = {}
    for ln in text.splitlines():
        m = re.search(r'off=(\d+) bytes: (.*)', ln)
        if m:
            chunks[int(m.group(1))] = m.group(2).split()
    if chunks:
        out = []
        for off in sorted(chunks):
            out.extend(chunks[off])
        return [int(x, 16) for x in out]
    # single-line / raw stream
    for ln in text.splitlines():
        m = re.search(r'bytes: (.*)', ln)
        if m:
            return [int(x, 16) for x in m.group(1).split()]
    return [int(x, 16) for x in text.split()]


def tokens(a):
    out, i = [], 0
    while i < len(a):
        c = a[i]
        if c == 1:
            n = 9
        elif c == 2:
            n = 13 if a[i + 2] == 2 else 9
        elif c == 3:
            n = 5
        else:
            out.append('?? at byte %d: ' % i +
                       ' '.join(f'{x:02x}' for x in a[i:i + 12]))
            break
        out.append(' '.join(f'{x:02x}' for x in a[i:i + n]))
        i += n
    return out


def render(toks):
    stack, lines = [], []
    for tok in toks:
        p = [int(x, 16) for x in tok.split()]
        if p[0] == 1:
            w = p[3]
            vid = p[5] | p[6] << 8
            stack.append(f'v{vid:x}.{w}')
        elif p[0] == 2:
            if p[2] == 2:
                val = 0
                for k, b in enumerate(p[5:13]):
                    val |= b << (8 * k)
                stack.append(hex(val) + '.64')
            else:
                val = 0
                for k, b in enumerate(p[5:9]):
                    val |= b << (8 * k)
                stack.append(hex(val))
        elif p[0] == 3:
            op, ar = p[1], p[2]
            if op == 0x01:
                lines.append(f'--- AND arity {ar} ({len(stack)} exprs)')
                continue
            if ar == 1:
                a2 = stack.pop() if stack else '?'
                nm = UNARY.get(op, hex(op))
                stack.append(f'{nm}[{p[3]:02x},{p[4]:02x}]({a2})')
                continue
            b = stack.pop() if stack else '?'
            a2 = stack.pop() if stack else '?'
            stack.append(f'({a2} {OPS.get(op, hex(op))} {b})')
        else:
            lines.append(tok)
    for i, s in enumerate(stack):
        lines.append(f'[{i:2}] {s}')
    return lines


def main():
    if len(sys.argv) == 2:
        t = tokens(load_bytes(sys.argv[1]))
        print(f'{len(t)} tokens')
        print('\n'.join(render(t)))
        return
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    ta = tokens(load_bytes(sys.argv[1]))
    tb = tokens(load_bytes(sys.argv[2]))
    print(f'{sys.argv[1]}: {len(ta)} tokens | {sys.argv[2]}: {len(tb)} tokens')
    same = True
    for line in difflib.unified_diff(ta, tb, lineterm='', n=1,
                                     fromfile=sys.argv[1], tofile=sys.argv[2]):
        print(line)
        same = False
    if same:
        print('BYTE-IDENTICAL')
    print('\n== rendered A =='); print('\n'.join(render(ta)))
    print('\n== rendered B =='); print('\n'.join(render(tb)))


if __name__ == '__main__':
    main()
