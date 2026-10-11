# Drive Moonlink's ETH -> SOL side with real SP1 Helios proofs (local cluster by default; env RPC, PROGRAM, PAYER for testnet).
#   soleth.py init   <lc.json> <eth_contract>      (upgrade authority = faucet.json)
#   soleth.py update <lc.json>
#   soleth.py unlock <st.json> <head> <amount> <nonce> <recipient_pubkey>
#   soleth.py tamper-unlock <st.json> <head> <amount> <nonce> <recipient_pubkey>   (amount+1: must fail)
import json, os, sys, time, base64, struct, urllib.request
from solders.keypair import Keypair
from solders.pubkey import Pubkey
from solders.instruction import Instruction, AccountMeta
from solders.message import Message
from solders.transaction import Transaction
from solders.hash import Hash

RPC = os.environ.get("RPC", "http://127.0.0.1:8899")
def rpc(m, p=None):
    r = urllib.request.Request(RPC, json.dumps({"jsonrpc": "2.0", "id": 1, "method": m, "params": p or []}).encode(), {"Content-Type": "application/json"})
    j = json.load(urllib.request.urlopen(r, timeout=30))
    if "error" in j: raise Exception(j["error"])
    return j["result"]
load = lambda p: Keypair.from_bytes(bytes(json.load(open(p))))
PID = Pubkey.from_string(os.environ.get("PROGRAM", "FUj7xs87KbwFQxnW5PHhNw17X37QxZMdr5NHT1SHgyWt"))
LOADER = Pubkey.from_string("BPFLoaderUpgradeab1e11111111111111111111111")
SYS = Pubkey.from_string("11111111111111111111111111111111")
CB = Pubkey.from_string("ComputeBudget111111111111111111111111111111")
SPP = 8192  # Ethereum slots per sync-committee period
payer = load(os.environ.get("PAYER", "/root/mc2/faucet.json"))
pda = lambda *s: Pubkey.find_program_address(list(s), PID)[0]
le = lambda x: struct.pack("<Q", x)
hx = lambda s: bytes.fromhex(s[2:] if s.startswith("0x") else s)
W = lambda b, i: b[32 * i:32 * (i + 1)]
u = lambda w: int.from_bytes(w, "big")

def send(data, metas):
    cu = Instruction(CB, bytes([2]) + struct.pack("<I", 1_400_000), [])
    ix = Instruction(PID, data, metas)
    pr = Instruction(CB, bytes([3]) + struct.pack("<Q", 20000), [])   # priority fee (public clusters)
    bh = Hash.from_string(rpc("getLatestBlockhash")["value"]["blockhash"])
    tx = Transaction([payer], Message([cu, pr, ix], payer.pubkey()), bh)
    raw = bytes(tx); print(f"  tx {len(raw)} bytes")
    sim = rpc("simulateTransaction", [base64.b64encode(raw).decode(), {"encoding": "base64", "sigVerify": False}])["value"]
    print("  simulate: err", sim["err"], "| CU", sim.get("unitsConsumed"))
    for l in (sim.get("logs") or [])[-3:]: print("   ", l)
    sig = rpc("sendTransaction", [base64.b64encode(raw).decode(), {"encoding": "base64", "skipPreflight": True}])
    for _ in range(60):
        time.sleep(1)
        t = rpc("getSignatureStatuses", [[sig]])["value"][0]
        if t and t.get("confirmationStatus") in ("confirmed", "finalized"):
            print("  landed in slot", t["slot"], "err", t["err"], "sig", sig[:20] + "...")
            return t["err"] is None
    print("  timeout"); return False

def lc_fields(lc):
    pv = hx(lc["publicValues"]); f = lambda i: W(pv, 1 + i)
    return dict(prevHeader=f(0), prevHead=u(f(1)), prevSc=f(2), newHead=u(f(3)), newHeader=f(4), root=f(5), sc=f(7), nextSc=f(8))

cmd = sys.argv[1]
if cmd == "init":
    lc = json.load(open(sys.argv[2])); f = lc_fields(lc)
    # storage vkey comes from st.json next to lc.json
    st = json.load(open(sys.argv[2].replace("lc.json", "st.json")))
    data = bytes([1]) + hx(sys.argv[3]) + hx(lc["vkey"]) + hx(st["vkey"]) + le(SPP) + le(f["prevHead"]) + f["prevHeader"] + f["prevSc"]
    pdata = Pubkey.find_program_address([bytes(PID)], LOADER)[0]
    print("init: trusted checkpoint head", f["prevHead"])
    ok = send(data, [AccountMeta(payer.pubkey(), True, True), AccountMeta(pda(b"lc"), False, True),
                     AccountMeta(pda(b"sc", le(f["prevHead"] // SPP)), False, True), AccountMeta(pdata, False, False), AccountMeta(SYS, False, False)])
elif cmd == "update":
    lc = json.load(open(sys.argv[2])); f = lc_fields(lc); proof = hx(lc["proof"])
    data = bytes([2]) + struct.pack("<H", len(proof)) + proof + hx(lc["publicValues"])
    np_ = f["newHead"] // SPP
    print(f"update: head {f['prevHead']} -> {f['newHead']}")
    ok = send(data, [AccountMeta(payer.pubkey(), True, True), AccountMeta(pda(b"lc"), False, True),
                     AccountMeta(pda(b"sc", le(f["prevHead"] // SPP)), False, False), AccountMeta(pda(b"sc", le(np_)), False, True),
                     AccountMeta(pda(b"sc", le(np_ + 1)), False, True), AccountMeta(pda(b"root", le(f["newHead"])), False, True), AccountMeta(SYS, False, False)])
elif cmd in ("unlock", "tamper-unlock", "unlock-other-recipient", "unlock-unknown-head", "unlock-bad-pv", "unlock-new-nonce"):
    st = json.load(open(sys.argv[2])); head, amount, nonce = int(sys.argv[3]), int(sys.argv[4]), int(sys.argv[5])
    rcpt = Pubkey.from_string(sys.argv[6]); proof = hx(st["proof"])
    if cmd == "tamper-unlock": amount += 1
    if cmd == "unlock-other-recipient": rcpt = Keypair().pubkey()          # someone else claims the burn
    if cmd == "unlock-unknown-head": head += 32                            # a head Solana never verified
    if cmd == "unlock-new-nonce": nonce = 1                                # same proof, unused nonce
    pvb = bytearray(hx(st["publicValues"]))
    if cmd == "unlock-bad-pv": pvb[-1] ^= 1; st["publicValues"] = "0x" + pvb.hex()   # edit the proven slot data
    vault = pda(b"vault")
    before = rpc("getBalance", [str(rcpt)])["value"]; vb = rpc("getBalance", [str(vault)])["value"]
    data = bytes([3]) + struct.pack("<H", len(proof)) + proof + le(head) + le(amount) + le(nonce) + hx(st["publicValues"])
    if cmd == "unlock-unknown-head" and len(sys.argv) > 7: pass
    print(f"{cmd}: {amount} lamports to {rcpt}, burn nonce {nonce}, against head {head}")
    ok = send(data, [AccountMeta(payer.pubkey(), True, True), AccountMeta(pda(b"lc"), False, False),
                     AccountMeta(pda(b"root", le(head)), False, False), AccountMeta(rcpt, False, True), AccountMeta(vault, False, True),
                     AccountMeta(pda(b"unlocked", le(nonce)), False, True), AccountMeta(SYS, False, False)])
    print(f"  recipient {before/1e9} -> {rpc('getBalance', [str(rcpt)])['value']/1e9} SOL; vault {vb/1e9} -> {rpc('getBalance', [str(vault)])['value']/1e9} SOL")
print("RESULT", "OK" if ok else "FAILED")
