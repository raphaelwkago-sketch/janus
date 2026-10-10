# Set-mode ZK input: block input (zkin.py) + y-coordinates of the new set's BLS keys in Alpenglow rank order.
# zkin_set.py /root/mc2/proof_<slot>.json out.bin
import json, sys, subprocess, struct
from py_ecc.bls.g2_primitives import pubkey_to_G1
from py_ecc.optimized_bls12_381 import normalize
p = json.load(open(sys.argv[1])); out = sys.argv[2]
subprocess.run([sys.executable, "-I", "/mnt/c/Users/rapha/AppData/Local/Temp/claude/C--Users-rapha--claude/da43f16f-c5f7-43ef-8669-5c9de77829d4/scratchpad/zk/zkin.py", sys.argv[1], out], check=True)
prog = p["program"]
sets = [d["new"] for d in p["delta"] if d["new"]["owner"] == prog and len(d["new"]["data"]) // 2 >= 61 and bytes.fromhex(d["new"]["data"])[12] == 1]
assert len(sets) == 1, len(sets)
d = bytes.fromhex(sets[0]["data"]); n = int.from_bytes(d[8:12], "little")
cand = []
for i in range(n):
    e = d[61 + 121 * i: 61 + 121 * (i + 1)]; stake = int.from_bytes(e[113:121], "little")
    if stake and e[64] == 1: cand.append((e[65:113], e[32:64], stake))
cnt = lambda k, j: sum(1 for c in cand if c[j] == k)
rank = sorted([c for c in cand if cnt(c[0], 0) == 1 and cnt(c[1], 1) == 1], key=lambda c: (-c[2], c[0]))
ys = b""
for key, _, stake in rank:
    x, y = normalize(pubkey_to_G1(key)); ys += (y.n if hasattr(y, "n") else y).to_bytes(48, "big")
open(out, "ab").write(struct.pack("<I", len(rank)) + ys)
print(f"set epoch {int.from_bytes(d[0:8], 'little')}: {len(rank)} validators in rank order, stakes {[c[2] for c in rank]}")
json.dump({"epoch": int.from_bytes(d[0:8], "little"), "rank": [{"bls": c[0].hex(), "stake": c[2]} for c in rank]}, open(out + ".set.json", "w"))
