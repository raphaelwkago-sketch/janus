# Foundry/cast fixture for one real certificate: python3 gen_cert.py /root/mc2/proof_<slot>.json out.json
import json, sys
def bits(idx, n):
    w = [0] * ((n + 255) // 256)
    for i in idx: w[i >> 8] |= 1 << (i & 255)
    return [str(x) for x in w]
p = json.load(open(sys.argv[1]))
fx = {"slot": p["slot"], "blockId": "0x" + p["block_id"], "sv": p["shred_version"], "spe": 200, "epoch": p["slot"] // 200,
      "pks": "0x" + "".join(v["pk"] for v in p["validators"]), "stakes": [str(v["stake"]) for v in p["validators"]],
      "nAgg": len(p["cert"])}
for i, c in enumerate(p["cert"]):
    fx[f"sig{i}"] = "0x" + c["sig"]; fx[f"bits{i}"] = bits(c["signers"], len(p["validators"]))
json.dump(fx, open(sys.argv[2], "w"))
print("wrote", sys.argv[2], "slot", fx["slot"], "epoch", fx["epoch"], "aggs", fx["nAgg"])
