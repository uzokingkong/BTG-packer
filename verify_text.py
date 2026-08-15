import struct, sys

def parse_pe(path):
    with open(path, 'rb') as f:
        data = f.read()
    e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
    assert data[e_lfanew:e_lfanew+4] == b'PE\0\0', "not PE"
    nsec = struct.unpack_from('<H', data, e_lfanew+6)[0]
    opt_size = struct.unpack_from('<H', data, e_lfanew+20)[0]
    sec_off = e_lfanew + 24 + opt_size
    sections = []
    for i in range(nsec):
        off = sec_off + i*40
        name = data[off:off+8].rstrip(b'\0').decode('latin1')
        vsize, vaddr, rsize, roff = struct.unpack_from('<IIII', data, off+8)
        sections.append((name, vaddr, vsize, roff, rsize))
    return data, sections

def section_bytes(data, roff, rsize):
    return data[roff:roff+rsize]

if __name__ == '__main__':
    orig = sys.argv[1]
    packed = sys.argv[2]
    od, osects = parse_pe(orig)
    pd, psects = parse_pe(packed)

    print("=== ORIG sections ===")
    for s in osects: print(s)
    print("=== PACKED sections ===")
    for s in psects: print(s)

    def get_text(sects):
        for n,va,vs,ro,rs in sects:
            if n == '.text':
                return (ro, rs)
        return None

    o = get_text(osects)
    p = get_text(psects)
    if o and p:
        ob = section_bytes(od, o[0], o[1])
        pb = section_bytes(pd, p[0], p[1])
        n = min(len(ob), len(pb))
        same = ob[:n] == pb[:n]
        print(f"\n=== .text comparison: orig {o} len={len(ob)}, packed {p} len={len(pb)} ===")
        print("first %d bytes identical: %s" % (n, same))
        # count differing bytes
        if not same:
            diff = sum(1 for a,b in zip(ob,pb) if a!=b)
            print("diff bytes in first %d: %d (%.2f%%)" % (n, diff, 100.0*diff/n))
            # print a few sample bytes
            print("orig first 64:", ob[:64].hex())
            print("pack first 64:", pb[:64].hex())
        else:
            # check if packed .text is same full length region
            print("orig first 64:", ob[:64].hex())
            print("pack first 64:", pb[:64].hex())
    else:
        print("one of them missing .text", o, p)

    # entropy of each section in packed
    import math
    print("\n=== PACKED section entropy ===")
    for n,va,vs,ro,rs in psects:
        sb = section_bytes(pd, ro, rs)
        if len(sb)==0: 
            print(n, "0 bytes"); continue
        from collections import Counter
        c = Counter(sb)
        L = len(sb)
        ent = -sum((x/L)*math.log2(x/L) for x in c.values())
        print(f"{n}: size={L} entropy={ent:.3f}")
