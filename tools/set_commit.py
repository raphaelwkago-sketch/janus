# Validator set in Alpenglow rank order from a recorder account (sets.jsonl line), as Ethereum sees it:
# 128-byte uncompressed G1 keys (EIP-2537), stakes, and the commitment keccak256(abi.encode(pks, stakes)).
#   set_commit.py <sets.jsonl> <epoch> <out.json>
import json, sys
from eth_hash.auto import keccak
from py_ecc.bls.g2_primitives import pubkey_to_G1
from py_ecc.optimized_bls12_381 import normalize

fpb = lambda x: (x.n if hasattr(x, "n") else x).to_bytes(64, "big")
def g1raw(k): x, y = normalize(pubkey_to_G1(k)); return fpb(x) + fpb(y)

def rank_of(d):   # same rules as the ZK set program / gen_set_fixture.py
    n = int.from_bytes(d[8:12], "little"); cand = []
    for i in range(n):
        e = d[61 + 121 * i: 61 + 121 * (i + 1)]; st = int.from_bytes(e[113:121], "little")
        if st and e[64] == 1: cand.append((e[65:113], e[32:64], st))
    cnt = lambda k, j: sum(1 for c in cand if c[j] == k)
    return sorted([(c[0], c[2]) for c in cand if cnt(c[0], 0) == 1 and cnt(c[1], 1) == 1], key=lambda c: (-c[1], c[0]))

def abi_bytes_uints(b, xs):
    w = lambda v: v.to_bytes(32, "big")
    pad = b + b"\x00" * (-len(b) % 32)
    return w(64) + w(64 + 32 + len(pad)) + w(len(b)) + pad + w(len(xs)) + b"".join(w(x) for x in xs)

if __name__ == "__main__":
    src, epoch, out = sys.argv[1], int(sys.argv[2]), sys.argv[3]
    rec = [json.loads(l) for l in open(src) if json.loads(l)["epoch"] == epoch][-1]
    d = bytes.fromhex(rec["data"]); assert d[12] == 1, "set account not complete"
    rank = rank_of(d)
    pks = b"".join(g1raw(k) for k, _ in rank); stakes = [s for _, s in rank]
    fx = {"epoch": epoch, "n": len(rank), "pks": "0x" + pks.hex(), "stakes": [str(s) for s in stakes],
          "blsCompressed": [k.hex() for k, _ in rank], "total": str(sum(stakes)),
          "setHash": "0x" + keccak(abi_bytes_uints(pks, stakes)).hex()}
    json.dump(fx, open(out, "w"))
    print(f"epoch {epoch}: {len(rank)} validators in rank set (of {int.from_bytes(d[8:12], 'little')} recorded), total stake {sum(stakes)/1e9:.3f} SOL, setHash {fx['setHash']}")
