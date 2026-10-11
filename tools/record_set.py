# Relayer: record the current epoch's validator set into the Moonlink recorder program (all staked vote accounts).
import json, os, sys, time, base64, urllib.request
from solders.keypair import Keypair
from solders.pubkey import Pubkey
from solders.instruction import Instruction, AccountMeta
from solders.message import Message
from solders.transaction import Transaction
from solders.hash import Hash
# env: RPC, RECORDER_KEY (program keypair), PAYER, SETS_OUT (defaults = local cluster)
RPC = os.environ.get("RPC", "http://127.0.0.1:8899")
def rpc(m, p=None):
    r = urllib.request.Request(RPC, json.dumps({"jsonrpc": "2.0", "id": 1, "method": m, "params": p or []}).encode(), {"Content-Type": "application/json"})
    j = json.load(urllib.request.urlopen(r, timeout=20))
    if "error" in j: raise Exception(j["error"])
    return j["result"]
load = lambda p: Keypair.from_bytes(bytes(json.load(open(p))))
PID = load(os.environ.get("RECORDER_KEY", "/root/recorder-sol/target/deploy/moonlink_recorder-keypair.json")).pubkey()
payer = load(os.environ.get("PAYER", "/root/mc2/user.json"))
CB = Pubkey.from_string("ComputeBudget111111111111111111111111111111")
SYS = Pubkey.from_string("11111111111111111111111111111111")
ei = rpc("getEpochInfo"); epoch = ei["epoch"]
SET, _ = Pubkey.find_program_address([b"set", epoch.to_bytes(8, "little"), bytes(payer.pubkey())], PID)
va = rpc("getVoteAccounts"); votes = sorted({Pubkey.from_string(v["votePubkey"]) for v in va["current"] + va["delinquent"]}, key=bytes)
print(f"epoch {epoch} (slot {ei['absoluteSlot']}, slotIndex {ei['slotIndex']}), {len(votes)} vote accounts, set account {SET}")
last = None
for i in range(0, len(votes), 10):
    batch = votes[i:i + 10]
    ix = Instruction(PID, epoch.to_bytes(8, "little"), [AccountMeta(payer.pubkey(), True, True), AccountMeta(SET, False, True), AccountMeta(SYS, False, False)] + [AccountMeta(v, False, False) for v in batch])
    bh = Hash.from_string(rpc("getLatestBlockhash")["value"]["blockhash"])
    sig = rpc("sendTransaction", [base64.b64encode(bytes(Transaction([payer], Message([Instruction(CB, bytes([3]) + (20000).to_bytes(8, "little"), []), ix], payer.pubkey()), bh))).decode(), {"encoding": "base64", "skipPreflight": True}])
    for _ in range(120):
        time.sleep(0.5)
        t = rpc("getSignatureStatuses", [[sig]])["value"][0]
        if t and t.get("confirmationStatus") in ("confirmed", "finalized"): break
    else: sys.exit(f"batch {i // 10} did not land: {sig}")
    print(f"  batch {i // 10}: slot {t['slot']} err {t['err']}"); last = t
d = base64.b64decode(rpc("getAccountInfo", [str(SET), {"encoding": "base64"}])["value"]["data"][0])
count = int.from_bytes(d[8:12], "little"); sum_ = int.from_bytes(d[13:21], "little"); tot = int.from_bytes(d[21:29], "little")
print(f"  set epoch {int.from_bytes(d[0:8], 'little')}: {count} entries, complete={d[12]}, sum={sum_/1e9:.3f} SOL, total={tot/1e9:.3f} SOL")
for k in range(min(count, 8)):
    e = d[61 + 121 * k: 61 + 121 * (k + 1)]
    print(f"    vote {Pubkey(e[0:32])} node {str(Pubkey(e[32:64]))[:6]} bls={e[64]} {e[65:73].hex()}.. stake {int.from_bytes(e[113:121], 'little')/1e9:.3f}")
rec = {"epoch": epoch, "slot": last["slot"], "set_account": str(SET), "program": str(PID), "data": d.hex()}
open(os.environ.get("SETS_OUT", "/root/mc2/sets.jsonl"), "a").write(json.dumps(rec) + "\n")
