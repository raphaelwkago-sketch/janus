# Check the testnet finalization certificate for slot $1 with BLS against the recorder's epoch set (rank order).
import json, struct, sys
sys.path.insert(0, "/mnt/c/Users/rapha/moonlink/tools")
from set_commit import rank_of
from py_ecc.bls import G2ProofOfPossession as bls
G = int(sys.argv[1]); SV = 4457
F = [json.loads(l) for l in open("/root/tn/footers.jsonl")]
certs = {f["final_cert"]["slot"]: f["final_cert"] for f in F if f.get("final_cert")}
print(f"{len(F)} footers, certs for {len(certs)} slots; slot {G} has a finalization cert: {G in certs}")
c = certs[G]
rm = rank_of(bytes.fromhex([json.loads(l) for l in open("/root/tn/sets.jsonl")][-1]["data"]))
tot = sum(s for _, s in rm)
def parse_agg(h):
    b = bytes.fromhex(h); sig = b[:96]; n, = struct.unpack("<H", b[96:98]); bm = b[98:98 + n]
    nb, = struct.unpack("<H", bm[1:3]); raw = bm[3:]
    return sig, [i for i in range(nb) if raw[i // 8] >> (i % 8) & 1], bm[0], nb
bid = bytes.fromhex(c["block_id"])
notar = bytes([1]) + struct.pack("<Q", G) + bid + struct.pack("<H", SV)
final = bytes([2]) + struct.pack("<Q", G) + struct.pack("<H", SV)
aggs = [("notar", c["notar"], notar), ("final", c["final"], final)] if c.get("notar") else [("fast", c["final"], notar)]
for k, h, m in aggs:
    sig, r, enc, nb = parse_agg(h)
    fr = sum(rm[i][1] for i in r) / tot
    print(f"{k}: bitmap enc {enc}, {nb} bits (rank set {len(rm)}), {len(r)} signers, {fr:.1%} stake, BLS verifies: {bls.FastAggregateVerify([rm[i][0] for i in r], m, sig)}")
