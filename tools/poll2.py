# Record the validator set (vote account, node, current-epoch stake, BLS key) every few seconds.
import json, time, base64, urllib.request
RPC = "http://127.0.0.1:8899"
def rpc(m, p=None):
    r = urllib.request.Request(RPC, json.dumps({"jsonrpc": "2.0", "id": 1, "method": m, "params": p or []}).encode(),
                               {"Content-Type": "application/json"})
    return json.load(urllib.request.urlopen(r, timeout=10))["result"]
out = open("/root/mc2/epochs.jsonl", "a")
while True:
    try:
        ei = rpc("getEpochInfo")
        va = rpc("getVoteAccounts")
        rows = []
        for v in va["current"] + va["delinquent"]:
            d = base64.b64decode(rpc("getAccountInfo", [v["votePubkey"], {"encoding": "base64"}])["value"]["data"][0])
            bls = d[145:193].hex() if int.from_bytes(d[:4], "little") == 3 and d[144] == 1 else None
            rows.append({"vote": v["votePubkey"], "node": v["nodePubkey"], "stake": v["activatedStake"], "bls": bls})
        out.write(json.dumps({"slot": ei["absoluteSlot"], "epoch": ei["epoch"], "set": rows}) + "\n"); out.flush()
    except Exception as e:
        print("poll err", e, flush=True)
    time.sleep(4)
