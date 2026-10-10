# Cost benchmark only: grow the real slot-1076 block to mainnet size by adding synthetic changed accounts,
# then re-derive LtHash_after, the bank hash and the footer so the zk program accepts it.
# (block_id changes, so no real certificate exists for it -- it measures proving cost, nothing else)
# usage: synth.py proof.json out.json n_small small_bytes n_big big_bytes
import json, struct, sys, hashlib, os
import numpy as np
from blake3 import blake3
N = 1024
p = json.load(open(sys.argv[1])); out = sys.argv[2]
ns, ss, nb, sb = map(int, sys.argv[3:7])
H = bytes.fromhex

def lt(pk, a):
    if a["lamports"] == 0: return np.zeros(N, np.uint16)
    m = struct.pack("<Q", a["lamports"]) + H(a["data"]) + bytes([int(a["executable"])]) + H(a["owner"]) + pk
    return np.frombuffer(blake3(m).digest(length=2 * N), dtype="<u2").astype(np.uint16)

acc = np.frombuffer(H(p["bank"]["lt_after"]), dtype="<u2").astype(np.uint16)
owner = "11" * 32
for i, size in enumerate([ss] * ns + [sb] * nb):
    pk = hashlib.sha256(b"synthetic" + struct.pack("<I", i)).digest()
    old = {"pubkey": pk.hex(), "lamports": 2_000_000, "data": os.urandom(size).hex(), "executable": False, "owner": owner}
    new = dict(old, lamports=1_999_000, data=os.urandom(size).hex())
    acc = (acc - lt(pk, old) + lt(pk, new)).astype(np.uint16)
    p["delta"].append({"old": old, "new": new})
p["bank"]["lt_after"] = acc.astype("<u2").tobytes().hex()
bk = p["bank"]
bh = hashlib.sha256(hashlib.sha256(H(bk["parent_bank_hash"]) + struct.pack("<Q", bk["sig_count"]) + H(bk["last_blockhash"])).digest() + H(bk["lt_after"])).digest()
s = bytearray(H(p["block"]["shreds"][64]["body"]))
assert s[24:32] == bytes(8) and s[34] == 0 and s[37] == 1, "footer not where expected"
s[38:70] = bh
p["block"]["shreds"][64]["body"] = s.hex()
json.dump(p, open(out, "w"))
data = sum(len(d["old"]["data"]) + len(d["new"]["data"]) for d in p["delta"]) // 2
print(f"{out}: {len(p['delta'])} changed accounts, {data / 1e6:.1f} MB account data (old+new)")
