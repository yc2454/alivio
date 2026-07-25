import re,collections,sys
import render_alivio as rz
def norm(cs): return sorted(re.sub(r'v\d+','V',c) for c in cs)
def diff(a,b):
    ca=collections.Counter(a); cb=collections.Counter(b); return sum((ca-cb).values())+sum((cb-ca).values())
# 1) parse alivio emitted log ONCE -> {hash: norm multiset} for proto-mark entries
emit={}
for line in open('/tmp/fs5.log'):
    if 'bcf_canonical_hash' not in line or '00 00 00 21' not in line: continue
    h=re.search(r'hash=0x([0-9a-f]+)',line).group(1)
    if h not in emit:
        try: emit[h]=norm(rz.conjuncts(line))
        except Exception: pass
print("emitted proto entries parsed:",len(emit))
# 2) load 27 kernel targets from all_buffers.txt grouped by hash
buf=collections.defaultdict(dict)
for line in open('/tmp/all_buffers.txt'):
    m=re.search(r'hash=0x([0-9a-f]+) off=(\d+) bytes:\s*([0-9a-f ]+)',line)
    if m:
        h=m.group(1); off=int(m.group(2)); buf[h][off]=bytes(int(x,16) for x in m.group(3).split())
targets=[l.strip() for l in open('/tmp/unmatched27.txt') if l.strip()]
emit_list=list(emit.items())
out=[]
for h in targets:
    if h not in buf: out.append((h,None,99,[],[])); continue
    data=b''.join(buf[h][o] for o in sorted(buf[h]))
    root=rz.parse(data)
    tgt=norm([rz.render(k) for k in root[1]]) if isinstance(root,tuple) and root[0]=='AND' else norm([rz.render(root)])
    best=min(emit_list, key=lambda kv: diff(tgt,kv[1]))
    ca=collections.Counter(tgt); cb=collections.Counter(best[1])
    out.append((h,best[0],diff(tgt,best[1]),list((ca-cb).elements()),list((cb-ca).elements())))
out.sort(key=lambda r:r[2])
from collections import Counter
print("symdiff distribution:",dict(Counter(r[2] for r in out)))
for h,bh,sd,only_t,only_e in out:
    print(f"\n[{h}] symdiff={sd} closest_emit={bh}")
    print("  only_in_KERNEL:",only_t)
    print("  only_in_alivio :",only_e)
