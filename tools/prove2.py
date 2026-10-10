# Moonlink reference prover + verifier on a real 4-validator Alpenglow ledger (/root/mc2).
# Chain: BLS finalization cert -> block_id -> shred Merkle proofs -> block footer -> bank hash
#        -> LtHash block-delta -> Moonlink receipt account (eth recipient, amount, nonce).
# Also writes the proof package that the Ethereum contract consumes (/root/mc2/proof_<slot>.json).
import json, struct, hashlib, base64, sys
import numpy as np, base58
from blake3 import blake3
from py_ecc.bls import G2ProofOfPossession as bls
from py_ecc.bls.g2_primitives import pubkey_to_G1, signature_to_G2
from py_ecc.bls.hash_to_curve import hash_to_G2
from py_ecc.optimized_bls12_381 import normalize

M = "/root/mc2"; SV = 18915; SPE = 200; LAG = 1
SETMODE = len(sys.argv) > 1 and sys.argv[1] == "--set"
if SETMODE:             # prove2.py --set <slot> <recorder program id>: export the block where a validator-set record completed
    GOOD = int(sys.argv[2]); PROGRAM = sys.argv[3]; BAD = None; RECEIPT = "11111111111111111111111111111111"; dep = {"vault": None}
elif len(sys.argv) > 1:   # prove2.py /root/mc2/deposit_<nonce>.json <eth hex> <lamports> <nonce>
    dep = json.load(open(sys.argv[1])); PROGRAM = dep["program"]; GOOD = dep["deposit"][1]; BAD = None; RECEIPT = dep["deposit"][3]
    EXP = (RECEIPT, sys.argv[2].lower(), int(sys.argv[3]), int(sys.argv[4]))
else:
    dep = json.load(open(f"{M}/deposits.json"))
    PROGRAM = dep["program"]; GOOD = dep["good"][1]; BAD = dep["dup"][1]; RECEIPT = dep["good"][3]
    EXP = (RECEIPT, "0x" + "11" * 20, 3 * 10**9, 7)
ok_all = True
def ok(n, c):
    global ok_all; ok_all &= bool(c); print(f"  [{'PASS' if c else 'FAIL'}] {n}"); return c
sha = lambda *p: hashlib.sha256(b"".join(p)).digest()

# ---------------- LtHash replay (same port that matched Agave 330/330 + 274/274 before) ----------------
N = 1024; ID = np.zeros(N, dtype=np.uint16)
def lt_with(b): return np.frombuffer(blake3(b).digest(length=2 * N), dtype="<u2").astype(np.uint16)
def acct_bytes(pk, a): return a["lamports"].to_bytes(8, "little") + a["data"] + bytes([a["executable"]]) + base58.b58decode(a["owner"]) + base58.b58decode(pk)
def acct_lt(pk, a): return ID.copy() if a["lamports"] == 0 else lt_with(acct_bytes(pk, a))
add = lambda x, y: (x + y).astype(np.uint16); sub = lambda x, y: (x - y).astype(np.uint16)
def bank_hash(parent, sigs, lbh, lt):
    return sha(sha(parent + sigs.to_bytes(8, "little") + lbh) + lt.astype("<u2").tobytes())
EMPTY = {"lamports": 0, "data": b"", "owner": "11111111111111111111111111111111", "executable": False}

state = {}
for e in json.load(open(f"{M}/accounts0.json"))["accounts"]:
    a = e["account"]; state[e["pubkey"]] = {"lamports": a["lamports"], "data": base64.b64decode(a["data"][0]), "owner": a["owner"], "executable": a["executable"]}
lt = ID.copy()
for pk, a in state.items(): lt = add(lt, acct_lt(pk, a))
slots = sorted(json.load(open(f"{M}/slots.json"))["bank_hash_details"], key=lambda x: x["slot"])
LT, CH, META = {}, {}, {}; prev_slot = 0; LT[0] = lt; mbh = 0
for b in slots:
    s = b["slot"]; ch = []
    for a in b["accounts"]:
        new = {"lamports": a["lamports"], "data": base64.b64decode(a["data"]), "owner": a["owner"], "executable": a["executable"]}
        old = state.get(a["pubkey"], EMPTY); ch.append((a["pubkey"], old, new))
        lt = add(sub(lt, acct_lt(a["pubkey"], old)), acct_lt(a["pubkey"], new)); state[a["pubkey"]] = new
    LT[s], CH[s], META[s] = lt, ch, b
    mbh += bank_hash(base58.b58decode(b["parent_bank_hash"]), b["signature_count"], base58.b58decode(b["last_blockhash"]), lt) == base58.b58decode(b["bank_hash"])
print(f"T1  LtHash replay of {len(slots)} real slots (4-validator cluster)")
ok(f"recomputed bank hash == Agave's in {mbh}/{len(slots)} slots", mbh == len(slots))
parent_of = {}
for i, b in enumerate(slots):
    if i: parent_of[b["slot"]] = slots[i - 1]["slot"]

# ---------------- shreds -> FEC roots -> block_id (double Merkle root) ----------------
LEAF = b"\x00SOLANA_MERKLE_SHREDS_LEAF"; NODE = b"\x01SOLANA_MERKLE_SHREDS_NODE"
join = lambda a, b: sha(NODE, a[:20], b[:20])
def shred_info(p):
    v = p[64]; kind = v & 0xF0; proof = v & 0x0F
    assert kind in (0x90, 0xB0), hex(v)                          # merkle data, chained (0xB0 = chained+resigned)
    resigned = kind == 0xB0
    idx, = struct.unpack_from("<I", p, 73); fec, = struct.unpack_from("<I", p, 79)
    flags = p[85]; size, = struct.unpack_from("<H", p, 86)
    off = 1203 - proof * 20 - (64 if resigned else 0)
    return dict(idx=idx, fec=fec, flags=flags, size=size, proof=[p[off + 20 * k: off + 20 * k + 20] for k in range(proof)], off=off)
def shred_root(p):
    si = shred_info(p); node = sha(LEAF, p[64:si["off"]]); i = si["idx"] - si["fec"]
    for o in si["proof"]:
        node = join(node, o) if i % 2 == 0 else join(o, node); i >>= 1
    return node
def tree(leaves):                                               # Agave shred MerkleTree::try_new_with_len
    nodes = list(leaves); size = len(leaves); levels = [list(leaves)]
    while size > 1:
        lvl = levels[-1]; nxt = [join(lvl[i], lvl[min(i + 1, size - 1)]) for i in range(0, size, 2)]
        levels.append(nxt); size = len(nxt)
    return levels
def tree_proof(levels, i):
    out = []
    for lvl in levels[:-1]:
        out.append(lvl[min(i ^ 1, len(lvl) - 1)][:20]); i >>= 1
    return out
def root_from(leaf, i, proof):
    node = leaf
    for o in proof: node = join(node, o) if i % 2 == 0 else join(o, node); i >>= 1
    return node

SH = {j["slot"]: j for j in map(json.loads, open(f"{M}/shreds.jsonl"))}
FOOT = {j["slot"]: j for j in map(json.loads, open(f"{M}/footers.jsonl"))}
CERT = {}
for f in FOOT.values():
    if f["final_cert"]: CERT[f["final_cert"]["slot"]] = f["final_cert"]

def block_parts(slot):
    j = SH[slot]; shreds = [bytes.fromhex(x["hex"]) for x in j["shreds"]]
    roots_agave = {x["fec"]: bytes.fromhex(x["root"]) for x in j["shreds"]}
    fecs = sorted(roots_agave); roots = {}
    for p in shreds:
        r = shred_root(p); f = shred_info(p)["fec"]; roots.setdefault(f, r); assert roots[f] == r
    pinfo = sha(struct.pack("<Q", j["parent"]), bytes.fromhex(j["parent_block_id"]), struct.pack("<I", len(fecs)))
    levels = tree([roots[f] for f in fecs] + [pinfo])
    return j, shreds, fecs, roots, roots_agave, pinfo, levels

import sys as _s; _s.path.insert(0, "/mnt/c/Users/rapha/AppData/Local/Temp/claude/C--Users-rapha--claude/da43f16f-c5f7-43ef-8669-5c9de77829d4/scratchpad")
from parse_block import components
FOOTER_VARIANT = 0
def block_check(slot, shreds):
    """Everything Ethereum must check to read the footer: all data shreds 0..last, consecutive, 32 per FEC set,
    LAST_IN_SLOT only on the final one; rebuild block_id; parse the WHOLE stream; exactly one footer marker."""
    infos = [shred_info(p) for p in shreds]
    if [x["idx"] for x in infos] != list(range(len(shreds))): return None, "indices"
    if any(x["fec"] != x["idx"] // 32 * 32 for x in infos) or len(shreds) % 32: return None, "fec layout"
    if any(struct.unpack_from("<Q", p, 65)[0] != slot for p in shreds): return None, "slot"
    if any((x["flags"] & 0xC0) == 0xC0 for x in infos[:-1]) or (infos[-1]["flags"] & 0xC0) != 0xC0: return None, "last flag"
    fecs = list(range(0, len(shreds), 32)); roots = {}
    for k, p in enumerate(shreds):
        r = shred_root(p); roots.setdefault(infos[k]["fec"], r)
        if roots[infos[k]["fec"]] != r: return None, "fec root mismatch"
    stream = b"".join(p[88:infos[k]["size"]] for k, p in enumerate(shreds))
    try: comps = components(stream)
    except Exception as ex: return None, f"parse {ex}"
    foot = [c for c in comps if c[0] == "marker" and c[4] == FOOTER_VARIANT]
    if len(foot) != 1 or foot[0][5][0] != 1: return None, "footer count"
    return dict(roots=[roots[f] for f in fecs], bank_hash=foot[0][5][1:33], comps=comps, stream=stream), "ok"
def block_id_from(roots, parent_slot, parent_bid):
    pinfo = sha(struct.pack("<Q", parent_slot), parent_bid, struct.pack("<I", len(roots)))
    return tree(roots + [pinfo])[-1][0]

print(f"\nT2  Footer of the deposit block (slot {GOOD}) is inside the block the validators signed")
j = SH[GOOD]; shreds = [bytes.fromhex(x["hex"]) for x in j["shreds"]]
bc, why = block_check(GOOD, shreds)
ok(f"all {len(shreds)} data shreds consistent, stream parses fully ({why})", bc is not None)
ok("our FEC roots == Agave's", all(bc["roots"][i] == bytes.fromhex(x["root"]) for i, x in enumerate(j["shreds"][::32])))
ok("block_id rebuilt from shreds + parent info == Agave's block_id", block_id_from(bc["roots"], j["parent"], bytes.fromhex(j["parent_block_id"])) == bytes.fromhex(j["block_id"]))
print("      components:", [(c[0], c[2] - c[1]) for c in bc["comps"]])
fbh = bc["bank_hash"]
ok("footer bank hash == our replayed bank hash", fbh == bank_hash(base58.b58decode(META[GOOD]["parent_bank_hash"]), META[GOOD]["signature_count"], base58.b58decode(META[GOOD]["last_blockhash"]), LT[GOOD]))
ok("footer bank hash == dump_footers (Agave parser)", fbh.hex() == FOOT[GOOD]["bank_hash"])
# attacks on the block layer
bad = list(shreds); del bad[40]
ok("attacker drops a shred -> rejected", block_check(GOOD, bad)[0] is None)
t = bytearray(shreds[64]); t[88 + 14] ^= 1; bad = list(shreds); bad[64] = bytes(t)
r = block_check(GOOD, bad)
ok("attacker flips a bit of the footer's bank hash -> block_id changes (rejected)", r[0] is None or block_id_from(r[0]["roots"], j["parent"], bytes.fromhex(j["parent_block_id"])) != bytes.fromhex(j["block_id"]))
fp = dict(j=j, shreds=shreds, bc=bc)

# ---------------- certificate ----------------
sets = {}
for l in open(f"{M}/epochs.jsonl"):
    s = json.loads(l); sets[s["epoch"]] = s["set"]
def rank_map(epoch):
    e = max(0, epoch - LAG)
    if e not in sets:   # cluster was offline during that epoch: use the closest recorded one (stakes unchanged here)
        e = max([k for k in sets if k <= e] or [min(sets)]); print(f"      (rank map: epoch {epoch - LAG} not recorded, using epoch {e})")
    rows = [r for r in sets[e] if r["stake"] > 0 and r["bls"]]
    rows.sort(key=lambda r: (-r["stake"], bytes.fromhex(r["bls"])))
    return [(bytes.fromhex(r["bls"]), r["stake"]) for r in rows]
def p_notar(slot, bid): return bytes([1]) + struct.pack("<Q", slot) + bid + struct.pack("<H", SV)
def p_final(slot): return bytes([2]) + struct.pack("<Q", slot) + struct.pack("<H", SV)
def parse_agg(h):
    b = bytes.fromhex(h); sig = b[:96]; n, = struct.unpack("<H", b[96:98]); bm = b[98:98 + n]
    assert bm[0] == 0; nb, = struct.unpack("<H", bm[1:3]); raw = bm[3:]
    return sig, [i for i in range(nb) if raw[i // 8] >> (i % 8) & 1]
print(f"\nT3  Finalization certificate for slot {GOOD}")
c = CERT[GOOD]; rm = rank_map(GOOD // SPE); bid = bytes.fromhex(c["block_id"])
ok("cert block_id == block_id rebuilt from shreds", bid == block_id_from(bc["roots"], j["parent"], bytes.fromhex(j["parent_block_id"])))
aggs = [("notar", c["notar"], p_notar(GOOD, bid)), ("final", c["final"], p_final(GOOD))] if c["notar"] else [("fast", c["final"], p_notar(GOOD, bid))]
tot = sum(x[1] for x in rm); cert_out = []
for kind, h, msg in aggs:
    sig, ranks = parse_agg(h); pks = [rm[r][0] for r in ranks]; frac = sum(rm[r][1] for r in ranks) / tot
    ok(f"{kind} aggregate: {len(ranks)}/{len(rm)} signers, {frac:.0%} stake, BLS verifies", bls.FastAggregateVerify(pks, msg, sig) and frac >= (0.8 if kind == "fast" else 0.6))
    cert_out.append((kind, sig, ranks, msg))

# ---------------- delta proof + receipt ----------------
def verify_delta(slot, entries, before, after):
    m = META[slot]
    if bank_hash(base58.b58decode(m["parent_bank_hash"]), m["signature_count"], base58.b58decode(m["last_blockhash"]), after) != base58.b58decode(m["bank_hash"]): return False
    pm = META[parent_of[slot]]
    if bank_hash(base58.b58decode(pm["parent_bank_hash"]), pm["signature_count"], base58.b58decode(pm["last_blockhash"]), before) != base58.b58decode(m["parent_bank_hash"]): return False
    if len({e[0] for e in entries}) != len(entries): return False
    t = before
    for pk, o, n in entries: t = add(sub(t, acct_lt(pk, o)), acct_lt(pk, n))
    return np.array_equal(t, after)
def receipts(entries):
    out = []
    for pk, o, n in entries:
        if n["owner"] == PROGRAM and o["lamports"] == 0 and n["lamports"] > 0 and len(n["data"]) == 40 and n["data"][:4] == b"MLNK":
            out.append((pk, "0x" + n["data"][4:24].hex(), int.from_bytes(n["data"][24:32], "little"), int.from_bytes(n["data"][32:40], "little")))
    return out
print(f"\nT4  Block-delta proof for slot {GOOD} (parent {parent_of[GOOD]})")
e = CH[GOOD]
ok(f"delta verifies against parent+child bank hashes ({len(e)} accounts changed)", verify_delta(GOOD, e, LT[parent_of[GOOD]], LT[GOOD]))
if not SETMODE:
    rc = receipts(e); print(f"      receipts created in block: {rc}")
    ok(f"exactly one Moonlink receipt: {EXP[2]} lamports -> {EXP[1]}, nonce {EXP[3]}", [(a, b.lower(), c, d) for a, b, c, d in rc] == [EXP])
    vd = [(o["lamports"], n["lamports"]) for pk, o, n in e if pk == dep["vault"]]
    ok(f"vault PDA balance +{EXP[2]} lamports in same block {vd}", bool(vd) and vd[0][1] - vd[0][0] == EXP[2])
    forged = [(pk, o, dict(n, data=n["data"][:24] + (500 * 10**9).to_bytes(8, "little") + n["data"][32:]) if pk == RECEIPT else n) for pk, o, n in e]
    ok("attacker edits receipt amount to 500 SOL -> rejected", not verify_delta(GOOD, forged, LT[parent_of[GOOD]], LT[GOOD]))

if BAD is not None:
    print(f"\nT5  Failed duplicate-nonce deposit (slot {BAD}, 500 SOL to 0x6666...)")
    e2 = CH[BAD]
    ok(f"honest delta of slot {BAD} verifies ({len(e2)} accounts)", verify_delta(BAD, e2, LT[parent_of[BAD]], LT[BAD]))
    ok("no receipt created in that block -> nothing to claim", receipts(e2) == [])
    fk = e2 + [("Fake111111111111111111111111111111111111111", EMPTY, {"lamports": 1426080, "data": b"MLNK" + b"\x66" * 20 + (500 * 10**9).to_bytes(8, "little") + (8).to_bytes(8, "little"), "owner": PROGRAM, "executable": False})]
    ok("attacker inserts a fake receipt -> rejected", not verify_delta(BAD, fk, LT[parent_of[BAD]], LT[BAD]))

# ---------------- export proof package for the Ethereum contract ----------------
def fp_bytes(x): return (x.n if hasattr(x, "n") else x).to_bytes(64, "big")
def g1_raw(pk): x, y = normalize(pubkey_to_G1(pk)); return fp_bytes(x) + fp_bytes(y)
def g2_raw(P): x, y = normalize(P); return fp_bytes(x.coeffs[0]) + fp_bytes(x.coeffs[1]) + fp_bytes(y.coeffs[0]) + fp_bytes(y.coeffs[1])
def compact(p):
    si = shred_info(p); body = p[64:si["off"] - 32]
    return {"body": body.rstrip(bytes(1)).hex(), "chained": p[si["off"] - 32:si["off"]].hex()}
groups = [shreds[i:i + 32] for i in range(0, len(shreds), 32)]
coding_sib = []
for g, root in zip(groups, bc["roots"]):
    dl = [sha(LEAF, p[64:shred_info(p)["off"]]) for p in g]; lv = tree(dl)        # 32 data leaves -> data subtree root
    sib = shred_info(g[0])["proof"][5]                                              # sibling = coding-shred subtree
    assert join(lv[-1][0], sib) == root; coding_sib.append(sib.hex())
m = META[GOOD]; pm = META[parent_of[GOOD]]
def acct_json(pk, a): return {"pubkey": base58.b58decode(pk).hex(), "lamports": a["lamports"], "data": a["data"].hex(), "executable": a["executable"], "owner": base58.b58decode(a["owner"]).hex()}
pkg = {
    "slot": GOOD, "shred_version": SV, "block_id": bid.hex(),
    "validators": [{"pk": g1_raw(k).hex(), "stake": st} for k, st in rm],
    "cert": [{"kind": k, "sig": g2_raw(signature_to_G2(s)).hex(), "signers": r, "msg": msg.hex(),
              "hm": g2_raw(hash_to_G2(msg, bls.DST, bls.xmd_hash_function)).hex()} for k, s, r, msg in cert_out],
    "block": {"parent_slot": j["parent"], "parent_block_id": j["parent_block_id"], "shreds": [compact(p) for p in shreds], "coding_sib": coding_sib},
    "bank": {"parent_bank_hash": base58.b58decode(m["parent_bank_hash"]).hex(), "sig_count": m["signature_count"],
             "last_blockhash": base58.b58decode(m["last_blockhash"]).hex(), "lt_after": LT[GOOD].astype("<u2").tobytes().hex()},
    "parent_bank": {"parent_bank_hash": base58.b58decode(pm["parent_bank_hash"]).hex(), "sig_count": pm["signature_count"],
                    "last_blockhash": base58.b58decode(pm["last_blockhash"]).hex(), "lt_before": LT[parent_of[GOOD]].astype("<u2").tobytes().hex()},
    "delta": [{"old": acct_json(pk, o), "new": acct_json(pk, n)} for pk, o, n in e],
    "program": base58.b58decode(PROGRAM).hex(), "receipt": base58.b58decode(RECEIPT).hex(),
}
json.dump(pkg, open(f"{M}/proof_{GOOD}.json", "w"))
sz = sum(len(x["old"]["data"]) + len(x["new"]["data"]) for x in pkg["delta"]) // 2
print(f"\nexported {M}/proof_{GOOD}.json: {len(pkg['delta'])} delta accounts, ~{sz/1024:.0f} KB account data, block data {sum(len(x['body'])//2+32 for x in pkg['block']['shreds'])/1024:.1f} KB compact")
print("ALL PASS" if ok_all else "SOME FAILED")
