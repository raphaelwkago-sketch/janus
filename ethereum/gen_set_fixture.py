# Foundry fixture for the validator-set handoff (real data from the 4-validator cluster):
#   old set  = epoch E-1 set as recorded on-chain by the recorder (sets.jsonl), Alpenglow rank rules applied
#   new set  = epoch E set from the ZK set-mode input (rank order the SP1 program uses)
#   cert     = finalization cert of the record block (signed by the new set)
#   cert2    = another real cert from epoch E, to show the installed set verifies later blocks
#   setProof = SP1 Groth16 proof (set mode) of the recorder account
# gen_set_fixture.py <record slot> <zkset .set.json> <groth16 json> <out.json>
import json, struct, sys
from py_ecc.bls.g2_primitives import pubkey_to_G1, signature_to_G2
from py_ecc.optimized_bls12_381 import normalize

M = "/root/mc2"; SPE = 200
slot, setj, g16, out = int(sys.argv[1]), json.load(open(sys.argv[2])), json.load(open(sys.argv[3])), sys.argv[4]
E = setj["epoch"]
fpb = lambda x: (x.n if hasattr(x, "n") else x).to_bytes(64, "big")
def g1raw(k): x, y = normalize(pubkey_to_G1(k)); return fpb(x) + fpb(y)
def g2raw(P): x, y = normalize(P); return fpb(x.coeffs[0]) + fpb(x.coeffs[1]) + fpb(y.coeffs[0]) + fpb(y.coeffs[1])
def bits(idx, n):
    w = [0] * ((n + 255) // 256)
    for i in idx: w[i >> 8] |= 1 << (i & 255)
    return [str(x) for x in w]
def rank_of(d):
    n = int.from_bytes(d[8:12], "little"); cand = []
    for i in range(n):
        e = d[61 + 121 * i: 61 + 121 * (i + 1)]; st = int.from_bytes(e[113:121], "little")
        if st and e[64] == 1: cand.append((e[65:113], e[32:64], st))
    cnt = lambda k, j: sum(1 for c in cand if c[j] == k)
    return sorted([(c[0], c[2]) for c in cand if cnt(c[0], 0) == 1 and cnt(c[1], 1) == 1], key=lambda c: (-c[1], c[0]))

rec = {}
for l in open(f"{M}/sets.jsonl"):
    j = json.loads(l); rec[j["epoch"]] = bytes.fromhex(j["data"])
old = rank_of(rec[E - 1])
new = [(bytes.fromhex(r["bls"]), r["stake"]) for r in setj["rank"]]
assert new == rank_of(rec[E]), "ZK set differs from the recorded set"

p = json.load(open(f"{M}/proof_{slot}.json"))
assert [v["pk"] for v in p["validators"]] == [g1raw(k).hex() for k, _ in new], "cert rank order != new set order"
oldkeys = [k for k, _ in old]
fx = {"slot": slot, "blockId": "0x" + p["block_id"], "sv": p["shred_version"], "epochOld": E - 1, "epochNew": E,
      "pksOld": "0x" + "".join(g1raw(k).hex() for k, _ in old), "stakesOld": [str(s) for _, s in old],
      "pksNew": "0x" + "".join(g1raw(k).hex() for k, _ in new), "stakesNew": [str(s) for _, s in new],
      "oldIndexOfNewRank": [str(oldkeys.index(k) + 1 if k in oldkeys else 0) for k, _ in new],
      "nAgg": len(p["cert"]), "setPublicValues": g16["publicValues"], "setProof": g16["proof"], "vkey": g16["vkey"]}
for i, c in enumerate(p["cert"]):
    fx[f"sig{i}"] = "0x" + c["sig"]; fx[f"bits{i}"] = bits(c["signers"], len(new))

# a second real certificate from epoch E (a later block), verified only through the newly installed set
def parse_agg(h):
    b = bytes.fromhex(h); sig = b[:96]; n, = struct.unpack("<H", b[96:98]); bm = b[98:98 + n]
    nb, = struct.unpack("<H", bm[1:3]); raw = bm[3:]
    return sig, [i for i in range(nb) if raw[i // 8] >> (i % 8) & 1]
for l in open(f"{M}/footers.jsonl"):
    f = json.loads(l); c = f.get("final_cert")
    if c and E * SPE <= c["slot"] < (E + 1) * SPE and c["slot"] > slot + 20 and not c["notar"]:
        sig, ranks = parse_agg(c["final"])
        fx.update(slot2=c["slot"], blockId2="0x" + c["block_id"], sig2="0x" + g2raw(signature_to_G2(sig)).hex(), bits2=bits(ranks, len(new)))
        break
json.dump(fx, open(out, "w"))
print(f"old epoch {E-1}: stakes {[s for _, s in old]}\nnew epoch {E}: stakes {[s for _, s in new]}\noldIndexOfNewRank {fx['oldIndexOfNewRank']}\ncert2 slot {fx.get('slot2')}")
