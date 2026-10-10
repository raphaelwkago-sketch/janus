//! Moonlink block verifier (runs inside SP1, and natively for testing).
//!
//! Proves, from raw Solana data only:
//!   data shreds -> FEC set roots -> block_id   (same Merkle construction as Agave)
//!   whole block stream parsed -> exactly one footer -> footer bank hash
//!   bank hash == sha256(sha256(parent_bank_hash | sig_count | last_blockhash) | LtHash_after)
//!   parent_bank_hash == same construction over LtHash_before
//!   LtHash_before - sum(old accounts) + sum(new accounts) == LtHash_after   (block-delta proof)
//!   -> Moonlink receipts created in this block (accounts newly owned by the program, "MLNK" data)
//! Public output: slot, block_id, program id, receipts. Ethereum separately checks the BLS
//! finalization certificate for (slot, block_id), so nothing here is trusted on its own.
use alloy_sol_types::sol;
use sha2::{Digest, Sha256};

sol! {
    struct Receipt { address eth; uint64 amount; uint64 nonce; }
    struct PublicValues { uint64 slot; bytes32 blockId; bytes32 program; Receipt[] receipts; }
}

const LEAF: &[u8] = b"\x00SOLANA_MERKLE_SHREDS_LEAF";
const NODE: &[u8] = b"\x01SOLANA_MERKLE_SHREDS_NODE";
const FOOTER_VARIANT: u8 = 0;
const N: usize = 1024; // LtHash lanes (u16)

fn sha(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts { h.update(p); }
    h.finalize().into()
}
fn join(a: &[u8], b: &[u8]) -> [u8; 32] { sha(&[NODE, &a[..20], &b[..20]]) }
/// Agave shred MerkleTree::try_new_with_len root (odd node paired with itself).
fn tree_root(mut lvl: Vec<[u8; 32]>) -> [u8; 32] {
    while lvl.len() > 1 {
        let n = lvl.len();
        lvl = (0..n).step_by(2).map(|i| join(&lvl[i], &lvl[(i + 1).min(n - 1)])).collect();
    }
    lvl[0]
}

struct R<'a> { b: &'a [u8], o: usize }
impl<'a> R<'a> {
    fn take(&mut self, n: usize) -> &'a [u8] { let s = &self.b[self.o..self.o + n]; self.o += n; s }
    fn u8(&mut self) -> u8 { self.take(1)[0] }
    fn u16(&mut self) -> u16 { u16::from_le_bytes(self.take(2).try_into().unwrap()) }
    fn u32(&mut self) -> u32 { u32::from_le_bytes(self.take(4).try_into().unwrap()) }
    fn u64(&mut self) -> u64 { u64::from_le_bytes(self.take(8).try_into().unwrap()) }
    fn h32(&mut self) -> [u8; 32] { self.take(32).try_into().unwrap() }
    fn cu16(&mut self) -> usize {
        let (mut v, mut s) = (0usize, 0);
        for _ in 0..3 { let x = self.u8(); v |= ((x & 0x7f) as usize) << s; s += 7; if x & 0x80 == 0 { return v; } }
        panic!("cu16")
    }
}

fn skip_tx(r: &mut R) {
    let n = r.cu16(); r.take(64 * n);
    let v0 = r.b[r.o] & 0x80 != 0;
    if v0 { r.take(1); }
    r.take(3);
    let n = r.cu16(); r.take(32 * n); r.take(32);
    let n = r.cu16();
    for _ in 0..n { r.take(1); let k = r.cu16(); r.take(k); let k = r.cu16(); r.take(k); }
    if v0 {
        let n = r.cu16();
        for _ in 0..n { r.take(32); let k = r.cu16(); r.take(k); let k = r.cu16(); r.take(k); }
    }
}

/// Parse the whole block stream; return the bank hash from its single footer.
fn footer_bank_hash(stream: &[u8]) -> [u8; 32] {
    let mut r = R { b: stream, o: 0 };
    let mut found: Option<[u8; 32]> = None;
    while r.o < stream.len() {
        let cnt = r.u64();
        if cnt == 0 {
            let _ver = r.u16(); let var = r.u8(); let len = r.u16() as usize;
            let body = r.take(len);
            if var == FOOTER_VARIANT {
                assert!(found.is_none(), "two footers");
                assert_eq!(body[0], 1, "footer version");
                found = Some(body[1..33].try_into().unwrap());
            }
        } else {
            for _ in 0..cnt {
                r.take(8 + 32);
                let ntx = r.u64();
                for _ in 0..ntx { skip_tx(&mut r); }
            }
        }
    }
    assert_eq!(r.o, stream.len(), "stream overrun");
    found.expect("no footer")
}

fn lt_of(pubkey: &[u8], lamports: u64, data: &[u8], exec: u8, owner: &[u8]) -> [u16; N] {
    let mut out = [0u16; N];
    if lamports == 0 { return out; }
    let mut h = blake3::Hasher::new();
    h.update(&lamports.to_le_bytes()); h.update(data); h.update(&[exec]); h.update(owner); h.update(pubkey);
    let mut buf = [0u8; 2 * N];
    h.finalize_xof().fill(&mut buf);
    for i in 0..N { out[i] = u16::from_le_bytes([buf[2 * i], buf[2 * i + 1]]); }
    out
}
fn lt_bytes(lt: &[u16; N]) -> Vec<u8> { lt.iter().flat_map(|x| x.to_le_bytes()).collect() }
fn read_lt(r: &mut R) -> [u16; N] {
    let b = r.take(2 * N); let mut o = [0u16; N];
    for i in 0..N { o[i] = u16::from_le_bytes([b[2 * i], b[2 * i + 1]]); }
    o
}

pub struct Acct { pub lamports: u64, pub exec: u8, pub owner: [u8; 32], pub data: Vec<u8> }

/// Verify block (shreds/footer/bank hashes/delta) and return (slot, block_id, program, changed accounts, reader offset).
fn verify_block(input: &[u8]) -> (u64, [u8; 32], [u8; 32], Vec<([u8; 32], Acct, Acct)>, usize) {
    let mut r = R { b: input, o: 0 };
    let slot = r.u64();
    let parent_slot = r.u64();
    let parent_block_id = r.h32();
    let program = r.h32();

    // ---- shreds -> FEC roots -> block_id; collect stream ----
    let n_shreds = r.u32() as usize;
    assert!(n_shreds > 0 && n_shreds % 32 == 0, "32 data shreds per FEC set");
    let n_fec = n_shreds / 32;
    let mut leaves: Vec<[u8; 32]> = Vec::with_capacity(32);
    let mut roots: Vec<[u8; 32]> = Vec::with_capacity(n_fec);
    let mut stream: Vec<u8> = Vec::new();
    for i in 0..n_shreds {
        let body_len = r.u32() as usize;
        let body = r.take(body_len);       // payload[64 .. off-32] with trailing zeros removed
        let chained = r.take(32);
        let variant = body[0];
        let kind = variant & 0xF0; let proof = (variant & 0x0F) as usize;
        assert!(kind == 0x90 || kind == 0xB0, "merkle chained data shred");
        assert_eq!(proof, 6, "32:32 erasure batch");
        let resigned = kind == 0xB0;
        let off = 1203 - proof * 20 - if resigned { 64 } else { 0 };
        let region = off - 32 - 64;
        assert!(body_len <= region);
        let mut full = vec![0u8; region];
        full[..body_len].copy_from_slice(body);
        let s = u64::from_le_bytes(full[1..9].try_into().unwrap());
        let idx = u32::from_le_bytes(full[9..13].try_into().unwrap()) as usize;
        let fec = u32::from_le_bytes(full[15..19].try_into().unwrap()) as usize;
        let flags = full[21];
        let size = u16::from_le_bytes(full[22..24].try_into().unwrap()) as usize;
        assert_eq!(s, slot, "shred slot");
        assert_eq!(idx, i, "consecutive indices");
        assert_eq!(fec, i / 32 * 32, "fec layout");
        let last = flags & 0xC0 == 0xC0;
        assert_eq!(last, i == n_shreds - 1, "LAST_IN_SLOT only on final shred");
        assert!(size >= 88 && size - 64 <= region, "size");
        stream.extend_from_slice(&full[88 - 64..size - 64]);
        leaves.push(sha(&[LEAF, &full, chained]));
        if leaves.len() == 32 {
            let sib = r.take(20);           // coding-shred half of the 64-leaf FEC tree
            roots.push(join(&tree_root(std::mem::take(&mut leaves)), sib));
        }
    }
    let pinfo = sha(&[&parent_slot.to_le_bytes(), &parent_block_id, &(n_fec as u32).to_le_bytes()]);
    roots.push(pinfo);
    let block_id = tree_root(roots);

    // ---- footer -> bank hash -> LtHash after / before ----
    let footer_bh = footer_bank_hash(&stream);
    let pbh = r.h32(); let sigs = r.u64(); let lbh = r.h32(); let lt_after = read_lt(&mut r);
    assert_eq!(sha(&[&sha(&[&pbh, &sigs.to_le_bytes(), &lbh]), &lt_bytes(&lt_after)]), footer_bh, "bank hash");
    let ppbh = r.h32(); let psigs = r.u64(); let plbh = r.h32(); let lt_before = read_lt(&mut r);
    assert_eq!(sha(&[&sha(&[&ppbh, &psigs.to_le_bytes(), &plbh]), &lt_bytes(&lt_before)]), pbh, "parent bank hash");

    // ---- block delta ----
    let n_delta = r.u32() as usize;
    let mut acc = lt_before;
    let mut out = Vec::with_capacity(n_delta);
    for _ in 0..n_delta {
        let pk = r.h32();
        let mut rd = |r: &mut R| { let l = r.u64(); let e = r.u8(); let o = r.h32(); let n = r.u32() as usize;
                                   Acct { lamports: l, exec: e, owner: o, data: r.take(n).to_vec() } };
        let old = rd(&mut r); let new = rd(&mut r);
        let a = lt_of(&pk, old.lamports, &old.data, old.exec, &old.owner);
        let b = lt_of(&pk, new.lamports, &new.data, new.exec, &new.owner);
        for i in 0..N { acc[i] = acc[i].wrapping_sub(a[i]).wrapping_add(b[i]); }
        out.push((pk, old, new));
    }
    let mut keys: Vec<[u8; 32]> = out.iter().map(|e| e.0).collect();
    keys.sort_unstable();
    assert!(keys.windows(2).all(|w| w[0] != w[1]), "duplicate account");
    assert!(acc == lt_after, "delta does not reproduce LtHash_after");
    (slot, block_id, program, out, r.o)
}

/// Deposit mode: receipts created in this block by the Moonlink program.
pub fn verify(input: &[u8]) -> PublicValues {
    let (slot, block_id, program, delta, used) = verify_block(input);
    assert_eq!(used, input.len(), "trailing input");
    let mut receipts = Vec::new();
    for (_, old, new) in &delta {
        let nd = &new.data;
        if new.owner == program && old.lamports == 0 && new.lamports > 0 && nd.len() == 40 && &nd[0..4] == b"MLNK" {
            receipts.push(Receipt {
                eth: alloy_sol_types::private::Address::from_slice(&nd[4..24]),
                amount: u64::from_le_bytes(nd[24..32].try_into().unwrap()),
                nonce: u64::from_le_bytes(nd[32..40].try_into().unwrap()),
            });
        }
    }
    PublicValues { slot, blockId: block_id.into(), program: program.into(), receipts }
}

// ---------------- validator-set mode ----------------
sol! {
    struct SetValues { uint64 slot; bytes32 blockId; bytes32 program; uint64 epoch; bytes32 setHash; uint256 totalStake; uint32 count; }
}
const SET_HEADER: usize = 61;
const SET_ENTRY: usize = 121;
// BLS12-381 base field modulus
const P_HEX: &str = "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab";

/// Set mode: the recorder's set account became complete in this block. Apply Agave's
/// BLSPubkeyToRankMap rules (stake > 0, has BLS key, unique BLS key, unique node pubkey;
/// sort by stake desc then compressed key asc), check the relayer's y-coordinates
/// (y^2 = x^3 + 4, sign flag matches), and output keccak256(abi.encode(pks, stakes)) in the
/// exact format the Ethereum light client stores.
pub fn verify_set(input: &[u8]) -> SetValues {
    use num_bigint::BigUint;
    use std::collections::HashMap;
    let (slot, block_id, program, delta, used) = verify_block(input);
    let set: Vec<&Acct> = delta.iter()
        .filter(|(_, o, n)| n.owner == program && n.data.len() >= SET_HEADER && n.data[12] == 1
                && (o.data.len() < SET_HEADER || o.data[12] == 0))
        .map(|(_, _, n)| n).collect();
    assert_eq!(set.len(), 1, "exactly one set completed in this block");
    let d = &set[0].data;
    let epoch = u64::from_le_bytes(d[0..8].try_into().unwrap());
    let count = u32::from_le_bytes(d[8..12].try_into().unwrap()) as usize;
    assert_eq!(d.len(), SET_HEADER + count * SET_ENTRY);
    let mut cand: Vec<([u8; 48], [u8; 32], u64)> = Vec::new();
    for i in 0..count {
        let e = &d[SET_HEADER + i * SET_ENTRY..SET_HEADER + (i + 1) * SET_ENTRY];
        let stake = u64::from_le_bytes(e[113..121].try_into().unwrap());
        if stake == 0 || e[64] != 1 { continue; }
        cand.push((e[65..113].try_into().unwrap(), e[32..64].try_into().unwrap(), stake));
    }
    let mut bc: HashMap<[u8; 48], u32> = HashMap::new(); let mut nc: HashMap<[u8; 32], u32> = HashMap::new();
    for c in &cand { *bc.entry(c.0).or_default() += 1; *nc.entry(c.1).or_default() += 1; }
    let mut set: Vec<([u8; 48], u64)> = cand.iter().filter(|c| bc[&c.0] == 1 && nc[&c.1] == 1).map(|c| (c.0, c.2)).collect();
    set.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));

    // y-coordinates (48 bytes each, rank order) supplied by the relayer; we only check them
    let mut r = R { b: input, o: used };
    let n = r.u32() as usize; assert_eq!(n, set.len());
    let p = BigUint::parse_bytes(P_HEX.as_bytes(), 16).unwrap();
    let half = (&p - 1u32) / 2u32;
    let mut pks: Vec<u8> = Vec::with_capacity(n * 128);
    let mut stakes: Vec<alloy_sol_types::private::U256> = Vec::with_capacity(n);
    let mut total = 0u128;
    for (key, stake) in &set {
        assert!(key[0] & 0x80 != 0 && key[0] & 0x40 == 0, "compressed, not infinity");
        let sign = key[0] & 0x20 != 0;
        let mut xb = *key; xb[0] &= 0x1f;
        let x = BigUint::from_bytes_be(&xb); let yb = r.take(48); let y = BigUint::from_bytes_be(yb);
        assert!(x < p && y < p);
        assert_eq!((&y * &y) % &p, (&x * &x * &x + 4u32) % &p, "point not on curve");
        assert_eq!(y > half, sign, "y sign flag");
        pks.extend_from_slice(&[0u8; 16]); pks.extend_from_slice(&xb);
        pks.extend_from_slice(&[0u8; 16]); pks.extend_from_slice(yb);
        stakes.push(alloy_sol_types::private::U256::from(*stake));
        total += *stake as u128;
    }
    assert_eq!(r.o, input.len(), "trailing input");
    use alloy_sol_types::SolValue;
    let enc = (alloy_sol_types::private::Bytes::from(pks), stakes).abi_encode_params();
    let mut k = tiny_keccak::Keccak::v256(); let mut h = [0u8; 32];
    use tiny_keccak::Hasher; k.update(&enc); k.finalize(&mut h);
    SetValues { slot, blockId: block_id.into(), program: program.into(), epoch, setHash: h.into(),
                totalStake: alloy_sol_types::private::U256::from(total), count: n as u32 }
}
