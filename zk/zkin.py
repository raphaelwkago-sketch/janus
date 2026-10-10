# Encode a proof package (from prove2.py) as the zk program's binary input. Optional tamper modes for negative tests.
import json, struct, sys
p = json.load(open(sys.argv[1])); out = sys.argv[2]; mode = sys.argv[3] if len(sys.argv) > 3 else "honest"
H = bytes.fromhex
import copy
p = copy.deepcopy(p)
if mode == "wrong_program": p["program"] = "%064x" % (int(p["program"], 16) ^ 1)   # claim receipts of another program
if mode == "old_lie":            # pretend an account held less before the block
    d = next(d for d in p["delta"] if d["old"]["lamports"] > 10**9); d["old"]["lamports"] -= 10**9
if mode == "omit_account":       # hide one changed account (a sysvar)
    p["delta"] = [d for d in p["delta"] if len(d["new"]["data"]) // 2 != 6008]
if mode == "parent_lie": p["parent_bank"]["sig_count"] += 1
if mode == "cancel_dup":         # receipt created, deleted, created again -> net change = one receipt, but listed twice
    r = next(d for d in p["delta"] if d["new"]["pubkey"] == p["receipt"])
    p["delta"] = p["delta"] + [{"old": r["new"], "new": r["old"]}, copy.deepcopy(r)]
sh = p["block"]["shreds"]
if mode == "swap_shreds": sh[3], sh[4] = sh[4], sh[3]
if mode == "drop_fec": sh = sh[:32] + sh[64:]   # remove a whole 32-shred FEC set (block_id changes -> no cert)
if mode == "drop_fec":
    p["block"]["coding_sib"] = p["block"]["coding_sib"][:1] + p["block"]["coding_sib"][2:]
b = bytearray()
b += struct.pack("<QQ", p["slot"], p["block"]["parent_slot"]) + H(p["block"]["parent_block_id"]) + H(p["program"])
b += struct.pack("<I", len(sh))
for i, s in enumerate(sh):
    body = bytearray(H(s["body"]))
    if mode == "flip_footer" and i == 64: body[24 + 14] ^= 1          # flip a bit of the footer's bank hash
    b += struct.pack("<I", len(body)) + body + H(s["chained"])
    if i % 32 == 31: b += H(p["block"]["coding_sib"][i // 32])
bk, pb = p["bank"], p["parent_bank"]
b += H(bk["parent_bank_hash"]) + struct.pack("<Q", bk["sig_count"]) + H(bk["last_blockhash"]) + H(bk["lt_after"])
b += H(pb["parent_bank_hash"]) + struct.pack("<Q", pb["sig_count"]) + H(pb["last_blockhash"]) + H(pb["lt_before"])
delta = p["delta"]
if mode == "inflate":
    for d in delta:
        if d["new"]["pubkey"] == p["receipt"]:
            nd = bytearray(H(d["new"]["data"])); nd[24:32] = struct.pack("<Q", 500 * 10**9); d["new"]["data"] = nd.hex()
if mode == "fake_receipt":
    delta = delta + [{"old": {"pubkey": "ab" * 32, "lamports": 0, "data": "", "executable": False, "owner": "00" * 32},
                      "new": {"pubkey": "ab" * 32, "lamports": 1426080, "data": (b"MLNK" + b"\x66" * 20 + struct.pack("<QQ", 500 * 10**9, 8)).hex(), "executable": False, "owner": p["program"]}}]
b += struct.pack("<I", len(delta))
for d in delta:
    b += H(d["old"]["pubkey"])
    for a in (d["old"], d["new"]):
        b += struct.pack("<QB", a["lamports"], int(a["executable"])) + H(a["owner"]) + struct.pack("<I", len(a["data"]) // 2) + H(a["data"])
open(out, "wb").write(b); print(f"{mode}: {len(b)} bytes -> {out}")
