# Moonlink

Trustless SOL ⇄ ETH bridge. No multisig, no guardians, no admin keys: each chain verifies the other chain's own validators, and SP1 zero-knowledge proofs show what happened inside a block.

## Layout

| Folder | What |
|---|---|
| `ethereum/` | Foundry project. `src/Moonlink.sol` (claim, burn, validator-set handoff), `src/MoonlinkLightClient.sol` + `src/AlpenglowBLS.sol` (Alpenglow BLS certificates via EIP-2537), `src/sp1/` (Succinct v6.1.0 verifier). `test/` = 29 tests, `script/RoundTrip.s.sol`. |
| `solana/moonlink/` | Solana program: deposit into the vault PDA; Ethereum light client (init / update) and unlock. `src/sp1v6.rs` = Succinct's v6.1.0 Groth16 verifier ported to Solana's alt_bn128 syscalls. |
| `solana/recorder/` | Records each epoch's validator set from the runtime's epoch stakes (per-relayer accounts). |
| `zk/` | SP1 program: shreds → block_id → footer → bank hash → LtHash block delta → receipts (deposit mode) or validator set (set mode). `zkin.py`, `zkin_set.py` build inputs; `synth.py` makes mainnet-size test blocks. |
| `helios/ml_prove.rs` | Proves SP1 Helios light-client + storage proofs (Groth16) for the Solana side. Drop into `sp1-helios/script/bin/`. |
| `tools/` | Reference prover/checker (`prove2.py`), relayer scripts (deposit, record set, Solana ETH-side driver `soleth.py`), Sepolia deploy (`sepcast.sh`), gnark build patch. |
| `fixtures/` | Real data used by the tests: certificates, Groth16 proofs (deposit slot 3348, set slot 6229), Sepolia Helios proofs. |

## Status (2026-10-10)

- Full round trip on real chains: local 4-validator Alpenglow cluster ⇄ Ethereum Sepolia (Moonlink at `0xe26716bf90769de2758097a6f4b1f58f75b7574c`).
- Mainnet-size block (3,013 accounts, 36 MB) proven Ethereum-ready in 5.8 min on one RTX 4090.
- Before real money: remove Solana program upgrade authority, audit, choose a relayer data feed.

Build notes: always build/run Agave and SP1 in WSL Ubuntu. SP1 Groth16 needs sp1-sdk feature `native-gnark` and `tools/patch_gnark.py` (an upstream Go dependency was deleted). Sepolia charges ~1,547 gas per byte of deployed code: deploy with node-side gas estimates (`tools/sepcast.sh`), not `forge script` simulation.
