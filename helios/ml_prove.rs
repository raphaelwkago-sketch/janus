//! Moonlink: Groth16 proofs for the Solana-side Ethereum light client, from one gen_fixture CBOR.
//!   lc.json : SP1 Helios light_client proof (bootstrap checkpoint -> newer finalized head + state root)
//!   st.json : SP1 Helios storage proof of the fixture's contract slots under that state root
//! ml_prove <proof_inputs.cbor> <out_dir> [execute]
use alloy::sol_types::SolType;
use alloy_primitives::hex;
use anyhow::{ensure, Context, Result};
use sp1_helios_primitives::types::{ProofInputs, ProofOutputs, StorageProofOutputs};
use sp1_sdk::{Elf, HashableKey, ProveRequest, Prover, ProverClient, ProvingKey, SP1Stdin};

async fn run<P: Prover>(client: &P, name: &str, elf: Elf, stdin: SP1Stdin, out: &str, execute_only: bool) -> Result<Vec<u8>> {
    let (pv, report) = client.execute(elf.clone(), stdin.clone()).await.context("execute")?;
    ensure!(report.exit_code == 0, "{name}: exit code {}", report.exit_code);
    println!("{name}: executed, {} cycles", report.total_instruction_count());
    let values = pv.to_vec();
    if execute_only { return Ok(values); }
    let pk = client.setup(elf).await.map_err(|e| anyhow::anyhow!("setup: {e}"))?;
    let t = std::time::Instant::now();
    let proof = client.prove(&pk, stdin).groth16().await.map_err(|e| anyhow::anyhow!("prove: {e}"))?;
    client.verify(&proof, pk.verifying_key(), None)?;
    ensure!(proof.public_values.to_vec() == values, "proof/executor mismatch");
    println!("{name}: groth16 proof in {:?}, vkey {}", t.elapsed(), pk.verifying_key().bytes32());
    let j = serde_json::json!({
        "vkey": pk.verifying_key().bytes32(),
        "publicValues": hex::encode_prefixed(&values),
        "proof": hex::encode_prefixed(proof.bytes()),
    });
    std::fs::write(format!("{out}/{name}.json"), j.to_string())?;
    Ok(values)
}

#[tokio::main]
async fn main() -> Result<()> {
    sp1_sdk::utils::setup_logger();
    let a: Vec<String> = std::env::args().collect();
    let cbor = std::fs::read(&a[1])?;
    let out = &a[2];
    let execute_only = a.get(3).map(|s| s == "execute").unwrap_or(false);
    let mut inputs: ProofInputs = serde_cbor::from_slice(&cbor)?;
    #[cfg(not(feature = "mlcpu"))]
    let client = ProverClient::builder().cuda().build().await;
    #[cfg(feature = "mlcpu")]   // no GPU: same proofs on CPU (slower)
    let client = ProverClient::builder().cpu().build().await;

    // light-client proof without storage slots (keeps the Solana transaction under 1232 bytes);
    // the slots are proven separately by the storage program against the same state root
    let storage = std::mem::take(&mut inputs.contract_storage);
    let mut s = SP1Stdin::new();
    s.write_slice(&serde_cbor::to_vec(&inputs)?);
    let lc = run(&client, "lc", Elf::Static(include_bytes!("../../elf/light_client")), s, out, execute_only).await?;
    let po = ProofOutputs::abi_decode(&lc)?;
    println!("lc: head {} -> {}, block {}, state root {}", po.prevHead, po.newHead, po.executionBlockNumber, po.executionStateRoot);
    println!("    prevHeader {} prevSyncCommitteeHash {}", po.prevHeader, po.prevSyncCommitteeHash);

    let mut s = SP1Stdin::new();
    s.write(&storage);
    s.write(&po.executionStateRoot);
    let st = run(&client, "st", Elf::Static(include_bytes!("../../elf/storage")), s, out, execute_only).await?;
    let so = StorageProofOutputs::abi_decode(&st)?;
    for x in &so.storageSlots { println!("st: {} [{}] = {}", x.contractAddress, x.key, x.value); }
    Ok(())
}
