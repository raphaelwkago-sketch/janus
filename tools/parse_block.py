# Parse an Alpenglow block's data stream into components (entry batches / markers), Agave wire format.
import struct
def cu16(b, o):                       # Solana compact-u16 (short_vec length)
    v = 0; s = 0
    for k in range(3):
        x = b[o + k]; v |= (x & 0x7F) << s; s += 7
        if not x & 0x80: return v, o + k + 1
    raise ValueError("cu16")
def skip_tx(b, o):
    n, o = cu16(b, o); o += 64 * n
    v0 = b[o] & 0x80
    o += 1 if v0 else 0
    o += 3
    n, o = cu16(b, o); o += 32 * n; o += 32
    n, o = cu16(b, o)
    for _ in range(n):
        o += 1; k, o = cu16(b, o); o += k; k, o = cu16(b, o); o += k
    if v0:
        n, o = cu16(b, o)
        for _ in range(n):
            o += 32; k, o = cu16(b, o); o += k; k, o = cu16(b, o); o += k
    return o
def components(b):
    o = 0; out = []
    while o < len(b):
        st = o; cnt, = struct.unpack_from("<Q", b, o); o += 8
        if cnt == 0:
            ver, = struct.unpack_from("<H", b, o); var = b[o + 2]; ln, = struct.unpack_from("<H", b, o + 3)
            o += 5 + ln; out.append(("marker", st, o, ver, var, b[st + 13: o]))
        else:
            ntx = 0
            for _ in range(cnt):
                o += 8 + 32; n, = struct.unpack_from("<Q", b, o); o += 8
                for _ in range(n): o = skip_tx(b, o); ntx += 1
            out.append(("entries", st, o, cnt, ntx, None))
    assert o == len(b), (o, len(b))
    return out
