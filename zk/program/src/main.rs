//! SP1 guest. kind 0: Moonlink deposit receipts in a block. kind 1: a completed validator-set record.
#![no_main]
sp1_zkvm::entrypoint!(main);
use alloy_sol_types::SolType;
use moonlink_lib::{verify, verify_set, PublicValues, SetValues};

pub fn main() {
    let kind = sp1_zkvm::io::read::<u8>();
    let input = sp1_zkvm::io::read_vec();
    if kind == 0 {
        sp1_zkvm::io::commit_slice(&PublicValues::abi_encode(&verify(&input)));
    } else {
        sp1_zkvm::io::commit_slice(&SetValues::abi_encode(&verify_set(&input)));
    }
}
