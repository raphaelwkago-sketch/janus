//! Moonlink, Solana side.
//!
//! SOL -> ETH. deposit(amount, eth_recipient, nonce):
//!   - moves `amount` lamports from the user into the vault PDA ["vault"] (no private key; nobody owns it)
//!   - creates a receipt PDA ["receipt", nonce] owned by this program holding
//!     "MLNK" | eth_recipient(20) | amount u64 LE | nonce u64 LE
//!   Both happen in one instruction, so a receipt existing on-chain means the SOL is in the vault.
//!   Ethereum later proves the receipt account was created (block-delta proof) and pays eth_recipient.
//!
//! ETH -> SOL. An Ethereum light client (SP1 Helios: sync-committee signatures checked inside an SP1
//! proof) runs in this program, and burns on Ethereum are proven with storage proofs:
//!   - init:   one time, by the program's upgrade authority: trusted starting checkpoint + Ethereum contract
//!   - update: SP1 Helios light-client proof -> new finalized head + its execution state root
//!   - unlock: SP1 Helios storage proof that Moonlink.burns[nonce] holds
//!             keccak256(sol_recipient | amount u64 BE | nonce u64 BE) under a known state root
//!             -> pay `amount` lamports from the vault, once per nonce
//! Every proof is a Groth16 proof checked here by a port of Succinct's v6.1.0 verifier (sp1v6.rs).
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    bpf_loader_upgradeable,
    entrypoint, entrypoint::ProgramResult,
    keccak::hashv as keccakv,
    program::{invoke, invoke_signed},
    program_error::ProgramError,
    pubkey::Pubkey,
    rent::Rent,
    system_instruction, system_program,
    sysvar::Sysvar,
};

mod g16v6_consts;
pub mod sp1v6;

pub const RECEIPT_LEN: usize = 40;
/// lc account: eth_contract 20 | lc_vkey 32 | storage_vkey 32 | slots_per_period u64 | head u64 | header 32
pub const LC_LEN: usize = 132;
/// Storage slot index of `mapping(uint64 => bytes32) burns` in Moonlink.sol (checked by a forge test).
pub const BURNS_SLOT: u8 = 6;
entrypoint!(process);

fn process(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    if data.len() == 36 { return deposit(program_id, accounts, data); }
    match data.first() {
        Some(1) => init(program_id, accounts, &data[1..]),
        Some(2) => update(program_id, accounts, &data[1..]),
        Some(3) => unlock(program_id, accounts, &data[1..]),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

fn deposit(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let amount = u64::from_le_bytes(data[0..8].try_into().unwrap());
    let eth: [u8; 20] = data[8..28].try_into().unwrap();
    let nonce = u64::from_le_bytes(data[28..36].try_into().unwrap());
    if amount == 0 { return Err(ProgramError::InvalidArgument); }

    let it = &mut accounts.iter();
    let user = next_account_info(it)?;
    let vault = next_account_info(it)?;
    let receipt = next_account_info(it)?;
    let sys = next_account_info(it)?;
    if !user.is_signer { return Err(ProgramError::MissingRequiredSignature); }
    if *sys.key != system_program::id() { return Err(ProgramError::IncorrectProgramId); }
    let (vault_key, _) = Pubkey::find_program_address(&[b"vault"], program_id);
    if *vault.key != vault_key { return Err(ProgramError::InvalidSeeds); }
    let nb = nonce.to_le_bytes();
    let (receipt_key, bump) = Pubkey::find_program_address(&[b"receipt", &nb], program_id);
    if *receipt.key != receipt_key { return Err(ProgramError::InvalidSeeds); }

    // receipt PDA: fails if this nonce was already used (account exists)
    let lamports = Rent::get()?.minimum_balance(RECEIPT_LEN);
    invoke_signed(
        &system_instruction::create_account(user.key, receipt.key, lamports, RECEIPT_LEN as u64, program_id),
        &[user.clone(), receipt.clone(), sys.clone()],
        &[&[b"receipt", &nb, &[bump]]],
    )?;
    invoke(&system_instruction::transfer(user.key, vault.key, amount), &[user.clone(), vault.clone(), sys.clone()])?;

    let mut d = receipt.try_borrow_mut_data()?;
    d[0..4].copy_from_slice(b"MLNK");
    d[4..24].copy_from_slice(&eth);
    d[24..32].copy_from_slice(&amount.to_le_bytes());
    d[32..40].copy_from_slice(&nb);
    Ok(())
}

// ---------------- helpers ----------------

fn err(_: impl core::fmt::Debug) -> ProgramError { ProgramError::InvalidArgument }

/// Create PDA `acc` (seeds + bump found here) owned by this program with `data`. Fails if it already exists.
fn create_pda<'a>(program_id: &Pubkey, payer: &AccountInfo<'a>, acc: &AccountInfo<'a>, sys: &AccountInfo<'a>,
                  seeds: &[&[u8]], data: &[u8]) -> ProgramResult {
    let (key, bump) = Pubkey::find_program_address(seeds, program_id);
    if *acc.key != key { return Err(ProgramError::InvalidSeeds); }
    let mut s: Vec<&[u8]> = seeds.to_vec();
    let b = [bump];
    s.push(&b);
    invoke_signed(
        &system_instruction::create_account(payer.key, acc.key, Rent::get()?.minimum_balance(data.len()), data.len() as u64, program_id),
        &[payer.clone(), acc.clone(), sys.clone()],
        &[&s],
    )?;
    acc.try_borrow_mut_data()?.copy_from_slice(data);
    Ok(())
}

/// Read a PDA this program created; None if it does not exist yet.
fn read_pda(program_id: &Pubkey, acc: &AccountInfo, seeds: &[&[u8]]) -> Result<Option<Vec<u8>>, ProgramError> {
    if *acc.key != Pubkey::find_program_address(seeds, program_id).0 { return Err(ProgramError::InvalidSeeds); }
    if acc.lamports() == 0 { return Ok(None); }
    if acc.owner != program_id { return Err(ProgramError::IllegalOwner); }
    Ok(Some(acc.try_borrow_data()?.to_vec()))
}

fn word(b: &[u8], i: usize) -> Result<[u8; 32], ProgramError> {
    b.get(32 * i..32 * (i + 1)).map(|w| w.try_into().unwrap()).ok_or(ProgramError::InvalidInstructionData)
}
fn word_u64(w: &[u8; 32]) -> Result<u64, ProgramError> {
    if w[..24] != [0u8; 24] { return Err(ProgramError::InvalidInstructionData); }
    Ok(u64::from_be_bytes(w[24..].try_into().unwrap()))
}
fn u64_word(x: u64) -> [u8; 32] { let mut w = [0u8; 32]; w[24..].copy_from_slice(&x.to_be_bytes()); w }

/// Split `proof_len u16 LE | proof | rest`.
fn split_proof(d: &[u8]) -> Result<(&[u8], &[u8]), ProgramError> {
    let n = u16::from_le_bytes(d.get(0..2).ok_or(ProgramError::InvalidInstructionData)?.try_into().unwrap()) as usize;
    let proof = d.get(2..2 + n).ok_or(ProgramError::InvalidInstructionData)?;
    Ok((proof, &d[2 + n..]))
}

struct Lc { eth_contract: [u8; 20], lc_vkey: [u8; 32], storage_vkey: [u8; 32], slots_per_period: u64, head: u64, header: [u8; 32] }

fn load_lc(program_id: &Pubkey, acc: &AccountInfo) -> Result<Lc, ProgramError> {
    let d = read_pda(program_id, acc, &[b"lc"])?.ok_or(ProgramError::UninitializedAccount)?;
    Ok(Lc {
        eth_contract: d[0..20].try_into().unwrap(),
        lc_vkey: d[20..52].try_into().unwrap(),
        storage_vkey: d[52..84].try_into().unwrap(),
        slots_per_period: u64::from_le_bytes(d[84..92].try_into().unwrap()),
        head: u64::from_le_bytes(d[92..100].try_into().unwrap()),
        header: d[100..132].try_into().unwrap(),
    })
}

// ---------------- ETH -> SOL ----------------

/// init: eth_contract 20 | lc_vkey 32 | storage_vkey 32 | slots_per_period u64 | head u64 | header 32 | sync_committee_hash 32
/// accounts: payer (upgrade authority, signer), lc, sync committee PDA of head's period, program data, system
fn init<'a>(program_id: &Pubkey, accounts: &[AccountInfo<'a>], d: &[u8]) -> ProgramResult {
    if d.len() != 164 { return Err(ProgramError::InvalidInstructionData); }
    let [payer, lc, sc, pdata, sys] = accounts else { return Err(ProgramError::NotEnoughAccountKeys) };
    if !payer.is_signer { return Err(ProgramError::MissingRequiredSignature); }
    if *sys.key != system_program::id() { return Err(ProgramError::IncorrectProgramId); }
    // only the upgrade authority may pick the starting checkpoint (otherwise anyone could front-run init)
    let (pdata_key, _) = Pubkey::find_program_address(&[program_id.as_ref()], &bpf_loader_upgradeable::id());
    if *pdata.key != pdata_key { return Err(ProgramError::InvalidSeeds); }
    let pd = pdata.try_borrow_data()?;
    if pd.len() < 45 || pd[0..4] != [3, 0, 0, 0] || pd[12] != 1 || pd[13..45] != payer.key.to_bytes() {
        return Err(ProgramError::IncorrectAuthority);
    }
    drop(pd);
    let spp = u64::from_le_bytes(d[84..92].try_into().unwrap());
    let head = u64::from_le_bytes(d[92..100].try_into().unwrap());
    if spp == 0 { return Err(ProgramError::InvalidArgument); }
    create_pda(program_id, payer, lc, sys, &[b"lc"], &d[..LC_LEN])?;
    create_pda(program_id, payer, sc, sys, &[b"sc", &(head / spp).to_le_bytes()], &d[132..164])
}

/// update: proof_len u16 | proof | SP1 Helios ProofOutputs (abi-encoded public values)
/// accounts: payer, lc, sc(current period), sc(new period), sc(new period + 1), root(new head), system
fn update<'a>(program_id: &Pubkey, accounts: &[AccountInfo<'a>], d: &[u8]) -> ProgramResult {
    let [payer, lc_acc, sc_cur, sc_new, sc_next, root, sys] = accounts else { return Err(ProgramError::NotEnoughAccountKeys) };
    if !payer.is_signer { return Err(ProgramError::MissingRequiredSignature); }
    if *sys.key != system_program::id() { return Err(ProgramError::IncorrectProgramId); }
    let (proof, pv) = split_proof(d)?;
    let mut lc = load_lc(program_id, lc_acc)?;
    sp1v6::verify(&lc.lc_vkey, pv, proof).map_err(err)?;

    // ProofOutputs is a dynamic tuple: word 0 = offset 0x20, then the fields
    if word(pv, 0)? != u64_word(32) { return Err(ProgramError::InvalidInstructionData); }
    let f = |i: usize| word(pv, 1 + i);
    let (prev_header, prev_head, prev_sc) = (f(0)?, word_u64(&f(1)?)?, f(2)?);
    let (new_head, new_header, state_root) = (word_u64(&f(3)?)?, f(4)?, f(5)?);
    let (sc_hash, next_sc_hash) = (f(7)?, f(8)?);

    // the proof must start exactly from what we trust now
    if prev_head != lc.head || prev_header != lc.header { return Err(ProgramError::InvalidArgument); }
    let cur = read_pda(program_id, sc_cur, &[b"sc", &(lc.head / lc.slots_per_period).to_le_bytes()])?
        .ok_or(ProgramError::UninitializedAccount)?;
    if cur != prev_sc { return Err(ProgramError::InvalidArgument); }
    if new_head <= lc.head || new_head % 32 != 0 { return Err(ProgramError::InvalidArgument); }

    let np = new_head / lc.slots_per_period;
    set_committee(program_id, payer, sc_new, sys, np, sc_hash)?;
    if next_sc_hash != [0u8; 32] { set_committee(program_id, payer, sc_next, sys, np + 1, next_sc_hash)?; }
    create_pda(program_id, payer, root, sys, &[b"root", &new_head.to_le_bytes()], &state_root)?;

    lc.head = new_head;
    lc.header = new_header;
    let mut l = lc_acc.try_borrow_mut_data()?;
    l[92..100].copy_from_slice(&new_head.to_le_bytes());
    l[100..132].copy_from_slice(&new_header);
    Ok(())
}

/// Store the sync committee hash of `period`, or check it matches the one already stored.
fn set_committee<'a>(program_id: &Pubkey, payer: &AccountInfo<'a>, acc: &AccountInfo<'a>, sys: &AccountInfo<'a>,
                     period: u64, h: [u8; 32]) -> ProgramResult {
    let pb = period.to_le_bytes();
    match read_pda(program_id, acc, &[b"sc", &pb])? {
        None => create_pda(program_id, payer, acc, sys, &[b"sc", &pb], &h),
        Some(x) if x == h => Ok(()),
        Some(_) => Err(ProgramError::InvalidArgument),
    }
}

/// unlock: proof_len u16 | proof | head u64 | amount u64 | nonce u64 | SP1 Helios StorageProofOutputs
/// accounts: payer, lc, root(head), recipient, vault, unlocked(nonce), system
fn unlock<'a>(program_id: &Pubkey, accounts: &[AccountInfo<'a>], d: &[u8]) -> ProgramResult {
    let [payer, lc_acc, root, recipient, vault, unlocked, sys] = accounts else { return Err(ProgramError::NotEnoughAccountKeys) };
    if !payer.is_signer { return Err(ProgramError::MissingRequiredSignature); }
    if *sys.key != system_program::id() { return Err(ProgramError::IncorrectProgramId); }
    let (proof, rest) = split_proof(d)?;
    if rest.len() < 24 { return Err(ProgramError::InvalidInstructionData); }
    let head = u64::from_le_bytes(rest[0..8].try_into().unwrap());
    let amount = u64::from_le_bytes(rest[8..16].try_into().unwrap());
    let nonce = u64::from_le_bytes(rest[16..24].try_into().unwrap());
    let pv = &rest[24..];
    let lc = load_lc(program_id, lc_acc)?;
    sp1v6::verify(&lc.storage_vkey, pv, proof).map_err(err)?;

    // StorageProofOutputs { bytes32 stateRoot; StorageSlot[] slots } (dynamic tuple)
    if word(pv, 0)? != u64_word(32) || word(pv, 2)? != u64_word(64) { return Err(ProgramError::InvalidInstructionData); }
    let state_root = word(pv, 1)?;
    let known = read_pda(program_id, root, &[b"root", &head.to_le_bytes()])?.ok_or(ProgramError::UninitializedAccount)?;
    if known != state_root { return Err(ProgramError::InvalidArgument); }

    let key = keccakv(&[&u64_word(nonce), &u64_word(BURNS_SLOT as u64)]).to_bytes();
    let value = keccakv(&[recipient.key.as_ref(), &amount.to_be_bytes(), &nonce.to_be_bytes()]).to_bytes();
    let mut addr = [0u8; 32];
    addr[12..].copy_from_slice(&lc.eth_contract);
    let n = word_u64(&word(pv, 3)?)? as usize;
    let found = (0..n).any(|i| {
        let w = |j| word(pv, 4 + 3 * i + j).unwrap_or([0xff; 32]);
        w(0) == key && w(1) == value && w(2) == addr
    });
    if !found || amount == 0 { return Err(ProgramError::InvalidArgument); }

    // one payout per burn nonce: this PDA can only be created once
    create_pda(program_id, payer, unlocked, sys, &[b"unlocked", &nonce.to_le_bytes()], &[1])?;
    let (vault_key, vb) = Pubkey::find_program_address(&[b"vault"], program_id);
    if *vault.key != vault_key { return Err(ProgramError::InvalidSeeds); }
    invoke_signed(
        &system_instruction::transfer(vault.key, recipient.key, amount),
        &[vault.clone(), recipient.clone(), sys.clone()],
        &[&[b"vault", &[vb]]],
    )
}
