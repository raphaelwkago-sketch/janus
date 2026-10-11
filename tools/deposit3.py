# Send real Moonlink deposits to the local cluster; record slots.
import json, os, sys, time, base64, urllib.request
from solders.keypair import Keypair
from solders.pubkey import Pubkey
from solders.instruction import Instruction, AccountMeta
from solders.message import Message
from solders.transaction import Transaction
from solders.hash import Hash
# env: RPC, PROGRAM, USER (keypair), OUT_DIR (defaults = local cluster)
RPC = os.environ.get("RPC", "http://127.0.0.1:8899")
def rpc(m, p=None):
    r = urllib.request.Request(RPC, json.dumps({"jsonrpc": "2.0", "id": 1, "method": m, "params": p or []}).encode(), {"Content-Type": "application/json"})
    j = json.load(urllib.request.urlopen(r, timeout=20)); 
    if "error" in j: raise Exception(j["error"])
    return j["result"]
load = lambda p: Keypair.from_bytes(bytes(json.load(open(p))))
PID = Pubkey.from_string(os.environ.get("PROGRAM", "FUj7xs87KbwFQxnW5PHhNw17X37QxZMdr5NHT1SHgyWt"))
user = load(os.environ.get("USER_KEY", "/root/mc2/user.json"))
CB = Pubkey.from_string("ComputeBudget111111111111111111111111111111")
SYS = Pubkey.from_string("11111111111111111111111111111111")
vault, _ = Pubkey.find_program_address([b"vault"], PID)
def deposit(amount, eth, nonce):
    receipt, _ = Pubkey.find_program_address([b"receipt", nonce.to_bytes(8, "little")], PID)
    ix = Instruction(PID, amount.to_bytes(8, "little") + eth + nonce.to_bytes(8, "little"),
                     [AccountMeta(user.pubkey(), True, True), AccountMeta(vault, False, True), AccountMeta(receipt, False, True), AccountMeta(SYS, False, False)])
    bh = Hash.from_string(rpc("getLatestBlockhash")["value"]["blockhash"])
    tx = Transaction([user], Message([Instruction(CB, bytes([3]) + (20000).to_bytes(8, "little"), []), ix], user.pubkey()), bh)
    sig = rpc("sendTransaction", [base64.b64encode(bytes(tx)).decode(), {"encoding": "base64", "skipPreflight": True}])
    for _ in range(60):
        time.sleep(1)
        t = rpc("getSignatureStatuses", [[sig]])["value"][0]
        if t and t.get("confirmationStatus") in ("confirmed", "finalized"): return sig, t["slot"], t["err"], str(receipt)
    return sig, None, "timeout", str(receipt)
ETH = bytes.fromhex(sys.argv[1][2:] if sys.argv[1].startswith("0x") else sys.argv[1])
amount, nonce = int(float(sys.argv[2]) * 10**9), int(sys.argv[3])
out = {"program": str(PID), "vault": str(vault), "user": str(user.pubkey())}
out["deposit"] = deposit(amount, ETH, nonce)
print(json.dumps(out, indent=1)); json.dump(out, open(os.path.join(os.environ.get("OUT_DIR", "/root/mc2"), "deposit_%d.json" % nonce), "w"))
print("vault balance", rpc("getBalance", [str(vault)])["value"] / 1e9)
