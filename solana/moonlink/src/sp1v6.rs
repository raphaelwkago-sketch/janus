//! SP1 v6.1.0 Groth16 verifier for Solana: a line-by-line port of Succinct's SP1VerifierGroth16.sol
//! (sp1-contracts v6.1.0) using Solana's alt_bn128 syscalls (same EIP-196/197 encoding as Ethereum).
use crate::g16v6_consts::*;
use solana_bn254::prelude::{alt_bn128_addition, alt_bn128_multiplication, alt_bn128_pairing};
use solana_program::hash::hashv as sha256v;

/// First 4 bytes of the verifier hash; SP1 prefixes every v6.1.0 Groth16 proof with them.
pub const VERIFIER_SELECTOR: [u8; 4] = [0x43, 0x88, 0xa2, 0x1c];
pub const VK_ROOT: [u8; 32] = [
    0x00, 0x2f, 0x85, 0x0e, 0xe9, 0x98, 0x97, 0x4d, 0x6c, 0xc0, 0x0e, 0x50, 0xcd, 0x08, 0x14, 0xb0,
    0x98, 0xc0, 0x5b, 0xfa, 0xde, 0x46, 0x6d, 0x28, 0x57, 0x32, 0x40, 0xd0, 0x57, 0xf2, 0x53, 0x52,
];
/// BN254 scalar field modulus (big-endian).
const R: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
];

#[derive(Debug, PartialEq)]
pub enum Sp1Error { Length, Selector, ExitCode, VkRoot, NotInField, Curve, Invalid }

/// sha256(publicValues) with the top 3 bits cleared (fits the BN254 scalar field).
pub fn public_values_digest(public_values: &[u8]) -> [u8; 32] {
    let mut d = sha256v(&[public_values]).to_bytes();
    d[0] &= 0x1f;
    d
}

/// Verify `proof` (SP1 v6.1.0 Groth16 encoding: selector | exitCode | vkRoot | nonce | 8 words)
/// for program `vkey` and its committed `public_values`.
pub fn verify(vkey: &[u8; 32], public_values: &[u8], proof: &[u8]) -> Result<(), Sp1Error> {
    if proof.len() != 4 + 32 * 11 { return Err(Sp1Error::Length); }
    if proof[0..4] != VERIFIER_SELECTOR { return Err(Sp1Error::Selector); }
    let w = |i: usize| -> [u8; 32] { proof[4 + 32 * i..4 + 32 * (i + 1)].try_into().unwrap() };
    let (exit_code, vk_root, nonce) = (w(0), w(1), w(2));
    if exit_code != [0u8; 32] { return Err(Sp1Error::ExitCode); }
    if vk_root != VK_ROOT { return Err(Sp1Error::VkRoot); }

    let inputs = [*vkey, public_values_digest(public_values), exit_code, vk_root, nonce];
    // L = CONSTANT + sum(input_i * PUB_i)
    let mut acc = CONSTANT;
    for (s, p) in inputs.iter().zip(PUB.iter()) {
        if s.as_slice() >= R.as_slice() { return Err(Sp1Error::NotInField); }
        let mut m = [0u8; 96];
        m[..64].copy_from_slice(p);
        m[64..].copy_from_slice(s);
        let sp = alt_bn128_multiplication(&m).map_err(|_| Sp1Error::Curve)?;
        let mut a = [0u8; 128];
        a[..64].copy_from_slice(&acc);
        a[64..].copy_from_slice(&sp);
        acc = alt_bn128_addition(&a).map_err(|_| Sp1Error::Curve)?.try_into().map_err(|_| Sp1Error::Curve)?;
    }

    // e(A, B) * e(C, -delta) * e(alpha, -beta) * e(L, -gamma) == 1
    let p = &proof[4 + 96..];
    let mut pairs = Vec::with_capacity(4 * 192);
    pairs.extend_from_slice(&p[0..64]);     // A
    pairs.extend_from_slice(&p[64..192]);   // B
    pairs.extend_from_slice(&p[192..256]);  // C
    pairs.extend_from_slice(&DELTA_NEG);
    pairs.extend_from_slice(&ALPHA);
    pairs.extend_from_slice(&BETA_NEG);
    pairs.extend_from_slice(&acc);
    pairs.extend_from_slice(&GAMMA_NEG);
    let r = alt_bn128_pairing(&pairs).map_err(|_| Sp1Error::Curve)?;
    let mut one = [0u8; 32];
    one[31] = 1;
    if r.as_slice() != one { return Err(Sp1Error::Invalid); }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hexd(s: &str) -> Vec<u8> {
        let s = s.trim_start_matches("0x");
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }
    fn field<'a>(j: &'a str, k: &str) -> &'a str {
        let i = j.find(&format!("\"{k}\":\"")).unwrap() + k.len() + 4;
        &j[i..i + j[i..].find('"').unwrap()]
    }
    fn fixture() -> ([u8; 32], Vec<u8>, Vec<u8>) {
        let j = std::fs::read_to_string(std::env::var("G16_FIXTURE").unwrap()).unwrap();
        (hexd(field(&j, "vkey")).try_into().unwrap(), hexd(field(&j, "publicValues")), hexd(field(&j, "proof")))
    }

    #[test]
    fn real_moonlink_proof_verifies() {
        let (vk, pv, proof) = fixture();
        assert_eq!(verify(&vk, &pv, &proof), Ok(()));
    }

    #[test]
    fn rejects_tampering() {
        let (vk, pv, proof) = fixture();
        let mut pv2 = pv.clone(); let n = pv2.len(); pv2[n - 1] ^= 1;
        assert_eq!(verify(&vk, &pv2, &proof), Err(Sp1Error::Invalid));
        let mut vk2 = vk; vk2[31] ^= 1;
        assert_eq!(verify(&vk2, &pv, &proof), Err(Sp1Error::Invalid));
        let mut p2 = proof.clone(); p2[4 + 96 + 40] ^= 1;
        assert!(verify(&vk, &pv, &p2).is_err());
        let mut p3 = proof.clone(); p3[4 + 32 + 5] ^= 1;
        assert_eq!(verify(&vk, &pv, &p3), Err(Sp1Error::VkRoot));
        let mut p4 = proof.clone(); p4[0] ^= 1;
        assert_eq!(verify(&vk, &pv, &p4), Err(Sp1Error::Selector));
    }
}
