# Janus

Trustless SOL ⇄ ETH bridge. No multisig, no guardians, no admin keys: each chain verifies the other chain's own validators, and SP1 zero-knowledge proofs show what happened inside a block.

(Working code name was **Moonlink**: contract and file names still use it, and the deployed Sepolia contract is named `Moonlink`.)

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

- Full round trip on real chains: local 4-validator Alpenglow cluster ⇄ Ethereum Sepolia (contract at `0xe26716bf90769de2758097a6f4b1f58f75b7574c`).
- Full round trip on PUBLIC testnets: Solana testnet (Alpenglow, 466 validators) ⇄ Ethereum Sepolia (`fixtures/testnet/`).
  - SOL→ETH: 1 SOL deposit in testnet slot 450906700, finalized by a fast certificate (322/466 signers, 80.3% stake). Sepolia Moonlink `0x5ad9be60031c564ce135f3e5596e357bea47e106`: cert `0xc321ef2f…819a`, claim `0x1730b182…b1`, burn `0x8ec4c018…8473`.
  - ETH→SOL: Solana testnet program `Ftazryb4STB7rV4xHsYE5E52VZrYtkfPFw2ZXEAfcuJv`: init `61Fc2VV1…iPaS`, light-client update `63S66wuC…pbtr`, unlock `t44cWtSK…H3zW` (vault 1 → 0 SOL, recipient +1 SOL).
  - Known limitation: the initial validator set is a trusted constructor input, and the recorder program's stakes differ from Alpenglow's frozen epoch stakes (404/466 validators), so epoch handoff on testnet is not yet sound. Testnet uses an epoch-warmup schedule (`warmup=true`).
- Mainnet-size block (3,013 accounts, 36 MB) proven Ethereum-ready in 5.8 min on one RTX 4090.
- Before real money: remove Solana program upgrade authority, audit, choose a relayer data feed.

Build notes: always build/run Agave and SP1 in WSL Ubuntu. SP1 Groth16 needs sp1-sdk feature `native-gnark` and `tools/patch_gnark.py` (an upstream Go dependency was deleted). Sepolia charges ~1,547 gas per byte of deployed code: deploy with node-side gas estimates (`tools/sepcast.sh`), not `forge script` simulation.
