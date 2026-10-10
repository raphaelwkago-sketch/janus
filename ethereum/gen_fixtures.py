# Write Foundry fixtures: the real slot-1076 certificate, and a simulated mainnet-size (680 validator) certificate.
import json, random, struct, os
from py_ecc.bls import G2ProofOfPossession as bls
from py_ecc.bls.hash_to_curve import hash_to_G2
from py_ecc.optimized_bls12_381 import G1, multiply, normalize, curve_order
from py_ecc.bls.g2_primitives import signature_to_G2

OUT = "/root/moonlink-eth/test/fixtures"; os.makedirs(OUT, exist_ok=True)
def fpb(x): return (x.n if hasattr(x, "n") else x).to_bytes(64, "big")
def g1raw(P): x, y = normalize(P); return fpb(x) + fpb(y)
def g2raw(P): x, y = normalize(P); return fpb(x.coeffs[0]) + fpb(x.coeffs[1]) + fpb(y.coeffs[0]) + fpb(y.coeffs[1])
def bits(idx, n):
    w = [0] * ((n + 255) // 256)
    for i in idx: w[i >> 8] |= 1 << (i & 255)
    return [str(x) for x in w]

p = json.load(open("/root/mc2/proof_1076.json"))
fx = {"slot": p["slot"], "blockId": "0x" + p["block_id"], "sv": p["shred_version"], "spe": 200, "epoch": p["slot"] // 200,
      "pks": "0x" + "".join(v["pk"] for v in p["validators"]), "stakes": [str(v["stake"]) for v in p["validators"]],
      "nAgg": len(p["cert"])}
for i, c in enumerate(p["cert"]):
    fx[f"sig{i}"] = "0x" + c["sig"]; fx[f"bits{i}"] = bits(c["signers"], len(p["validators"]))
    fx[f"msg{i}"] = "0x" + c["msg"]; fx[f"hm{i}"] = "0x" + c["hm"]
json.dump(fx, open(f"{OUT}/cert_1076.json", "w"))

# simulated mainnet: 680 validators, power-law stake, signers hold ~88% (typical), fast path needs 80%
random.seed(1); N = 680; SV = 50093; SLOT = 400_000_123; BID = bytes(random.getrandbits(8) for _ in range(32))
sks = [random.randrange(1, 2**250) for _ in range(N)]
stakes = sorted([int(1e9 * 1000 * (1 / (i + 1)) ** 0.9) + 10**12 for i in range(N)], reverse=True)
pks = [multiply(G1, sk) for sk in sks]
total = sum(stakes); order = list(range(N)); random.shuffle(order)
signers = set(order); off = 0
for i in order:                                      # take validators offline until ~88% remains
    if (off + stakes[i]) / total > 0.12: continue
    signers.discard(i); off += stakes[i]
msg = bytes([1]) + struct.pack("<Q", SLOT) + BID + struct.pack("<H", SV)
H = hash_to_G2(msg, bls.DST, bls.xmd_hash_function)
agg_sk = sum(sks[i] for i in signers) % curve_order
sig = multiply(H, agg_sk)                            # = sum of each signer's signature (BLS is linear)
json.dump({"slot": SLOT, "blockId": "0x" + BID.hex(), "sv": SV, "spe": 432000, "epoch": SLOT // 432000,
           "pks": "0x" + b"".join(g1raw(P) for P in pks).hex(), "stakes": [str(s) for s in stakes], "nAgg": 1,
           "sig0": "0x" + g2raw(sig).hex(), "bits0": bits(sorted(signers), N), "msg0": "0x" + msg.hex(), "hm0": "0x" + g2raw(H).hex(),
           "nSigners": len(signers)}, open(f"{OUT}/cert_sim680.json", "w"))
print("fixtures written; sim signers", len(signers), "of", N, f"stake {(total-off)/total:.1%}")
