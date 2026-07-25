import re,collections,sys
import render_alivio as rz
# Usage: closest.py <target_kernel_chunked_file> <alivio_hashbytes_log> [signature_hex]
#   target = chunked `bcf_canonical_hash off=N bytes:` lines for ONE missed hash.
#   log    = ALIVIO_BCF_DUMP_HASH_BYTES=1 stderr (one `[alivio] bcf_canonical_hash` line per emitted goal).
#   signature = optional byte filter to restrict the candidate family (default "00 00 00 21",
#               the proto-mark 0x21000000 const). Use "" to compare against ALL emitted entries.
# Ranks emitted entries by conjunct-multiset symmetric difference to the target (var-renamed to V),
# so you can see exactly which prefix/anchor/fold conjuncts the kernel wants that alivio didn't emit.
TGT=sys.argv[1] if len(sys.argv)>1 else '/tmp/miss_2f57.txt'
LOG=sys.argv[2] if len(sys.argv)>2 else '/tmp/hashbytes.log'
SIG=sys.argv[3] if len(sys.argv)>3 else '00 00 00 21'
def load(fn):
    chunks={}
    for line in open(fn):
        m=re.search(r'off=(\d+) bytes:\s*([0-9a-f ]+)',line)
        if m: chunks[int(m.group(1))]=bytes(int(x,16) for x in m.group(2).split())
    return b''.join(chunks[o] for o in sorted(chunks))
def norm(cs): return sorted(re.sub(r'v\d+','V',c) for c in cs)
data=load(TGT)
root=rz.parse(data)
tgt=norm([rz.render(k) for k in root[1]])
print('TARGET n=%d'%len(tgt))
for c in tgt: print('   ',c)
seen={}
for line in open(LOG):
    if 'bcf_canonical_hash' not in line or (SIG and SIG not in line): continue
    h=re.search(r'hash=0x([0-9a-f]+)',line).group(1)
    if h not in seen: seen[h]=norm(rz.conjuncts(line))
print('\nunique proto-mark emitted hashes:',len(seen))
def diff(a,b):
    ca=collections.Counter(a); cb=collections.Counter(b); return sum((ca-cb).values())+sum((cb-ca).values())
ranked=sorted(seen.items(), key=lambda kv: diff(tgt,kv[1]))
print('\nclosest 6 emitted to 2f57:')
for h,cs in ranked[:6]:
    ca=collections.Counter(tgt); cb=collections.Counter(cs)
    print(' hash=%s n=%d symdiff=%d'%(h,len(cs),diff(tgt,cs)))
    print('   only_in_2f57 :',list((ca-cb).elements()))
    print('   only_in_emit :',list((cb-ca).elements()))
