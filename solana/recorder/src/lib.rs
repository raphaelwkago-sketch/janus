//! Moonlink validator-set recorder.
//! record(epoch): for each vote account passed (strictly increasing pubkeys, so no duplicates), store
//!   vote pubkey | node pubkey | has_bls | BLS key (compressed) | stake
//! where stake comes from the runtime's own epoch stakes (sol_get_epoch_stake syscall, current epoch =
//! exactly the stakes Alpenglow uses for this epoch's certificates). The set account is marked complete
//! only when the recorded stake adds up to the runtime's total epoch stake, so nobody can leave validators out.
//! Ethereum later proves the completed account (block-delta proof) to learn the epoch's validator set.
//! Each payer gets its own set account ["set", epoch, payer]: a shared one could be jammed by anyone
//! recording the highest vote pubkey first. Every completed account holds the same, full set.
use solana_program::{
    account_info::AccountInfo, clock::Clock, entrypoint, entrypoint::ProgramResult,
    epoch_stake::{get_epoch_stake_for_vote_account, get_epoch_total_stake},
    program::{invoke, invoke_signed}, program_error::ProgramError, pubkey::Pubkey, rent::Rent,
    system_instruction, sysvar::Sysvar,
};

pub const HEADER: usize = 61; // epoch u64 | count u32 | complete u8 | sum u64 | total u64 | last_vote [32]
pub const ENTRY: usize = 121; // vote 32 | node 32 | has_bls 1 | bls 48 | stake u64
const VOTE_PROGRAM: Pubkey = solana_program::pubkey!("Vote111111111111111111111111111111111111111");
entrypoint!(process);

fn process(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    if data.len() != 8 { return Err(ProgramError::InvalidInstructionData); }
    let epoch = u64::from_le_bytes(data.try_into().unwrap());
    if Clock::get()?.epoch != epoch { return Err(ProgramError::InvalidArgument); }
    let [payer, set, sys, votes @ ..] = accounts else { return Err(ProgramError::NotEnoughAccountKeys) };
    if !payer.is_signer { return Err(ProgramError::MissingRequiredSignature); }
    let eb = epoch.to_le_bytes();
    let (key, bump) = Pubkey::find_program_address(&[b"set", &eb, payer.key.as_ref()], program_id);
    if *set.key != key { return Err(ProgramError::InvalidSeeds); }
    let rent = Rent::get()?;
    if set.lamports() == 0 {
        invoke_signed(
            &system_instruction::create_account(payer.key, set.key, rent.minimum_balance(HEADER), HEADER as u64, program_id),
            &[payer.clone(), set.clone(), sys.clone()], &[&[b"set", &eb, payer.key.as_ref(), &[bump]]])?;
        let mut d = set.try_borrow_mut_data()?;
        d[0..8].copy_from_slice(&eb);
        d[21..29].copy_from_slice(&get_epoch_total_stake().to_le_bytes());
    }
    let (mut count, complete, mut sum, total, mut last) = {
        let d = set.try_borrow_data()?;
        (u32::from_le_bytes(d[8..12].try_into().unwrap()), d[12], u64::from_le_bytes(d[13..21].try_into().unwrap()),
         u64::from_le_bytes(d[21..29].try_into().unwrap()), <[u8; 32]>::try_from(&d[29..61]).unwrap())
    };
    if complete == 1 { return Err(ProgramError::AccountAlreadyInitialized); }
    let mut entries: Vec<u8> = Vec::new();
    for v in votes {
        if *v.owner != VOTE_PROGRAM { return Err(ProgramError::IncorrectProgramId); }
        if v.key.to_bytes() <= last { return Err(ProgramError::InvalidArgument); } // strictly increasing
        last = v.key.to_bytes();
        let stake = get_epoch_stake_for_vote_account(v.key);
        if stake == 0 { continue; }
        let vd = v.try_borrow_data()?;
        let v4 = vd.len() >= 193 && u32::from_le_bytes(vd[0..4].try_into().unwrap()) == 3;
        entries.extend_from_slice(v.key.as_ref());
        entries.extend_from_slice(if v4 { &vd[4..36] } else { &[0u8; 32] });
        let has = v4 && vd[144] == 1;
        entries.push(has as u8);
        entries.extend_from_slice(if has { &vd[145..193] } else { &[0u8; 48] });
        entries.extend_from_slice(&stake.to_le_bytes());
        sum = sum.checked_add(stake).ok_or(ProgramError::ArithmeticOverflow)?;
        count += 1;
    }
    let old = set.data_len(); let new = old + entries.len();
    let need = rent.minimum_balance(new).saturating_sub(set.lamports());
    if need > 0 { invoke(&system_instruction::transfer(payer.key, set.key, need), &[payer.clone(), set.clone(), sys.clone()])?; }
    set.realloc(new, false)?;
    let mut d = set.try_borrow_mut_data()?;
    d[old..new].copy_from_slice(&entries);
    d[8..12].copy_from_slice(&count.to_le_bytes());
    d[12] = (sum == total) as u8;
    d[13..21].copy_from_slice(&sum.to_le_bytes());
    d[29..61].copy_from_slice(&last);
    Ok(())
}
