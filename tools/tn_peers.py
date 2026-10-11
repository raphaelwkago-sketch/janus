# Repair peers on Solana testnet (staked validators first) and the block slots in a range, from public RPC.
#   tn_peers.py <peers out> [<slots out> <first slot> <last slot>]
import json, sys, urllib.request
RPC = "https://api.testnet.solana.com"
def rpc(m, p=None):
    r = urllib.request.Request(RPC, json.dumps({"jsonrpc": "2.0", "id": 1, "method": m, "params": p or []}).encode(), {"Content-Type": "application/json"})
    return json.load(urllib.request.urlopen(r, timeout=60))["result"]
staked = {v["nodePubkey"] for v in rpc("getVoteAccounts")["current"]}
nodes = [n for n in rpc("getClusterNodes") if n.get("serveRepair") and n.get("shredVersion") == 4457]
nodes.sort(key=lambda n: n["pubkey"] not in staked)
open(sys.argv[1], "w").write("".join(f"{n['pubkey']} {n['serveRepair']}\n" for n in nodes if n["pubkey"] in staked))
print(len([n for n in nodes if n["pubkey"] in staked]), "staked repair peers")
if len(sys.argv) > 2:
    a, b = int(sys.argv[3]), int(sys.argv[4]); out = []
    while a <= b:
        out += rpc("getBlocks", [a, min(b, a + 499999)]); a += 500000
    open(sys.argv[2], "w").write("".join(f"{s}\n" for s in out)); print(len(out), "blocks in range")
