# Rank set exactly as Alpenglow uses it: the replay's frozen epoch-stakes rank map (slots.json "rank_map",
# "vote node stake" per rank) with each vote account's BLS key taken from the recorder's on-chain data.
# Usage: frozen_set.py <slots.json> <sets.jsonl> <slot> <out.json>
import sys, json, base64, urllib.request
RPC = __import__("os").environ.get("RPC", "https://api.testnet.solana.com")
sys.path.insert(0, __import__("os").path.dirname(__file__))
from set_commit import abi_bytes_uints, g1raw, keccak

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
def b58(b):
    n = int.from_bytes(b, "big"); s = ""
    while n: n, r = divmod(n, 58); s = B58[r] + s
    return "1" * (len(b) - len(b.lstrip(b"\0"))) + s

def bls_by_vote(sets_path):
    m = {}
    for l in open(sets_path):
        d = bytes.fromhex(json.loads(l)["data"]); n = int.from_bytes(d[8:12], "little")
        for i in range(n):
            e = d[61 + 121 * i: 61 + 121 * (i + 1)]
            if e[64] == 1: m[b58(e[:32])] = e[65:113]
    return m

def frozen_rank(slots_path, sets_path, slot):
    det = {d["slot"]: d for d in json.load(open(slots_path))["bank_hash_details"]}[slot]
    keys = bls_by_vote(sets_path); out = []
    for row in det["rank_map"]:
        vote, node, stake = row.split()
        if vote not in keys:   # not in the recorder's data (live vs frozen set): read the key from the vote account
            q = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "getAccountInfo", "params": [vote, {"encoding": "base64"}]}).encode()
            a = json.load(urllib.request.urlopen(urllib.request.Request(RPC, q, {"Content-Type": "application/json"})))["result"]["value"]
            d = base64.b64decode(a["data"][0]); assert d[144] == 1, f"vote account {vote} has no BLS key"
            keys[vote] = d[145:193]; print(f"  {vote}: BLS key read from chain (not in recorder data)")
        out.append((keys[vote], int(stake)))
    return out

if __name__ == "__main__":
    slots, sets, slot, out = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
    rank = frozen_rank(slots, sets, slot)
    pks = b"".join(g1raw(k) for k, _ in rank); stakes = [s for _, s in rank]
    epoch = 14 + (slot - 524256) // 432000   # testnet warmup schedule (getEpochSchedule)
    fx = {"slot": slot, "epoch": epoch, "n": len(rank), "pks": "0x" + pks.hex(), "stakes": [str(s) for s in stakes],
          "blsCompressed": [k.hex() for k, _ in rank], "total": str(sum(stakes)),
          "setHash": "0x" + keccak(abi_bytes_uints(pks, stakes)).hex()}
    json.dump(fx, open(out, "w"))
    print(f"slot {slot}: {len(rank)} validators (frozen rank map), total stake {sum(stakes)/1e9:.3f} SOL, setHash {fx['setHash']}")
