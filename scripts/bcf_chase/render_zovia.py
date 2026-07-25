import re,sys
# decode a alivio single-line "[alivio] bcf_canonical_hash: buf.len=N hash=0x.. bytes: XX XX..."
def u16(b,o): return b[o]|(b[o+1]<<8)
def u32(b,o): return b[o]|(b[o+1]<<8)|(b[o+2]<<16)|(b[o+3]<<24)
OPS={0x10:'==',0x50:'!=',0x20:'u>',0x30:'u>=',0x60:'s>',0x70:'s>=',0xa0:'u<',0xb0:'u<=',
     0xc0:'s<',0xd0:'s<=',0x40:'&jset',0x00:'+',0x0c:'-',0x5c:'&',0x4c:'|',0x74:'>>',0x64:'<<'}
def opn(c): return OPS.get(c & 0xfe, OPS.get(c,'op0x%02x'%c))
def render(node): return node[0] if isinstance(node,tuple) else str(node)
def parse(data):
    i=0; st=[]
    while i<len(data):
        tag=data[i]; code=data[i+1]; vlen=data[i+2]; w=u16(data,i+3); i+=5
        if tag==1:
            idx=u32(data,i); i+=4+4*vlen; st.append(('v%d'%idx,w))
        elif tag==2:
            args=[u32(data,i+4*k) for k in range(vlen)]; i+=4*vlen
            val=args[0]|(args[1]<<32) if vlen>=2 else (args[0] if args else 0)
            st.append((hex(val),w))
        else:
            kids=[st.pop() for _ in range(vlen)][::-1]
            if vlen>2: st.append(('AND',kids))
            else: st.append(('(%s %s %s)'%(render(kids[0]),opn(code),render(kids[1]) if len(kids)>1 else ''),w))
    return st[-1]
def conjuncts(line):
    m=re.search(r'bytes:\s*([0-9a-f ]+)',line)
    data=bytes(int(x,16) for x in m.group(1).split())
    root=parse(data)
    if isinstance(root,tuple) and root[0]=='AND':
        return [render(k) for k in root[1]]
    return [render(root)]
if __name__=='__main__':
    # arg1=logfile, arg2=hash(optional). prints conjuncts (sorted) for first matching line
    log=sys.argv[1]; want=sys.argv[2] if len(sys.argv)>2 else None
    for line in open(log):
        if 'bcf_canonical_hash' not in line: continue
        h=re.search(r'hash=0x([0-9a-f]+)',line).group(1)
        if want and h!=want: continue
        cs=conjuncts(line)
        print('hash=%s n=%d'%(h,len(cs)))
        for c in cs: print('   ',c)
        break
