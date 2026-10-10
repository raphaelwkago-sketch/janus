//! moonlink <input.bin> <native|execute|prove|groth16> [deposit|set]
use alloy_sol_types::SolType;
use moonlink_lib::{PublicValues, SetValues};
use sp1_sdk::{blocking::{ProveRequest, Prover, ProverClient}, include_elf, Elf, HashableKey, ProvingKey, SP1Stdin};
use std::time::Instant;

const ELF: Elf = include_elf!("moonlink-program");

fn show(kind: u8, out: &[u8]) {
    if kind == 0 {
        let pv = PublicValues::abi_decode(out).unwrap();
        println!("  slot {}  block_id {}  program {}", pv.slot, pv.blockId, pv.program);
        for r in &pv.receipts { println!("  receipt: {} lamports -> {} (nonce {})", r.amount, r.eth, r.nonce); }
    } else {
        let s = SetValues::abi_decode(out).unwrap();
        println!("  slot {}  block_id {}  epoch {}  validators {}  total stake {}  setHash {}", s.slot, s.blockId, s.epoch, s.count, s.totalStake, s.setHash);
    }
}

fn main() {
    sp1_sdk::utils::setup_logger();
    let a: Vec<String> = std::env::args().collect();
    let input = std::fs::read(&a[1]).expect("input");
    let mode = a.get(2).map(|s| s.as_str()).unwrap_or("execute");
    let kind: u8 = if a.get(3).map(|s| s.as_str()) == Some("set") { 1 } else { 0 };
    if mode == "native" {
        let t = Instant::now();
        let r = std::panic::catch_unwind(|| if kind == 0 { PublicValues::abi_encode(&moonlink_lib::verify(&input)) } else { SetValues::abi_encode(&moonlink_lib::verify_set(&input)) });
        match r { Ok(out) => { println!("native OK in {:?}", t.elapsed()); show(kind, &out) } Err(_) => println!("native REJECTED") }
        return;
    }
    let client = ProverClient::from_env();
    let mut stdin = SP1Stdin::new();
    stdin.write(&kind);
    stdin.write_vec(input);
    if mode == "execute" {
        let t = Instant::now();
        match client.execute(ELF, stdin).run() {
            Ok((out, report)) => {
                println!("zkVM execute OK in {:?}: {} RISC-V cycles", t.elapsed(), report.total_instruction_count());
                show(kind, out.as_slice());
            }
            Err(e) => println!("zkVM execute REJECTED: {e}"),
        }
        return;
    }
    let pk = client.setup(ELF).expect("setup");
    println!("program vkey: {}", pk.verifying_key().bytes32());
    let t = Instant::now();
    let proof = if mode == "groth16" { client.prove(&pk, stdin).groth16().run() } else { client.prove(&pk, stdin).compressed().run() }
        .expect("prove");
    println!("{mode} proof generated in {:?}", t.elapsed());
    client.verify(&proof, pk.verifying_key(), None).expect("verify");
    println!("proof verifies");
    show(kind, proof.public_values.as_slice());
    if mode == "groth16" {
        let out = serde_json::json!({
            "vkey": pk.verifying_key().bytes32(),
            "publicValues": format!("0x{}", hex::encode(proof.public_values.as_slice())),
            "proof": format!("0x{}", hex::encode(proof.bytes())),
        });
        std::fs::write(format!("{}.groth16.json", a[1]), out.to_string()).unwrap();
        println!("wrote {}.groth16.json ({} proof bytes)", a[1], proof.bytes().len());
    }
}
