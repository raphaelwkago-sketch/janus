// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {AlpenglowBLS} from "./AlpenglowBLS.sol";

/// Commitment to a validator set (what sets[] stores): keccak256(abi.encode(pks, stakes)) and the total stake.
function setHashOf(bytes memory pks, uint256[] memory stakes) pure returns (bytes32) {
    return keccak256(abi.encode(pks, stakes));
}

function totalStakeOf(uint256[] memory stakes) pure returns (uint256 total) {
    for (uint256 i = 0; i < stakes.length; i++) total += stakes[i];
}

/// Ethereum-side light client for Solana Alpenglow: accepts a block as final only with a valid
/// BLS finalization certificate from the epoch's validator set (no committee, no multisig).
contract MoonlinkLightClient {
    struct ValidatorSet {
        bytes32 hash;       // keccak256(abi.encode(pks, stakes)), pks in Alpenglow rank order
        uint256 totalStake;
    }
    struct Agg {
        bytes sig;          // G2, 256 bytes (EIP-2537 encoding)
        uint256[] bits;     // signer bitmap over rank order
    }

    uint16 public immutable shredVersion;
    uint64 public immutable slotsPerEpoch;
    uint64 public immutable firstNormalEpoch;  // Solana epoch schedule warmup (0 / 0 when the cluster has none)
    uint64 public immutable firstNormalSlot;
    mapping(uint64 => ValidatorSet) public sets;       // epoch -> set used to verify that epoch's certs
    mapping(uint64 => bytes32) public finalizedBlock;  // slot -> block_id

    event Finalized(uint64 indexed slot, bytes32 blockId, bool fastPath);

    error UnknownEpoch(uint64 epoch);
    error WrongSet();
    error BelowThreshold(uint256 signed, uint256 total);
    error BadSignature();

    /// Trusted starting point: the first epoch's set commitment (see setHashOf, totalStakeOf). Passing the hash, not the
    /// key list, keeps deployment small for large sets (testnet: 471 validators = 60 KB of keys).
    /// warmup_: the cluster's epoch schedule starts with short epochs (testnet, mainnet), as in Agave's EpochSchedule.
    constructor(uint16 shredVersion_, uint64 slotsPerEpoch_, bool warmup_, uint64 epoch, bytes32 setHash, uint256 totalStake) {
        shredVersion = shredVersion_;
        slotsPerEpoch = slotsPerEpoch_;
        if (warmup_) {
            uint64 p = 32; uint64 e = 0;                 // MINIMUM_SLOTS_PER_EPOCH = 32
            while (p < slotsPerEpoch_) { p <<= 1; e++; }  // e = log2(next_power_of_two(spe)) - log2(32)
            firstNormalEpoch = e;
            firstNormalSlot = (p - 32);                  // 32 * (2^e - 1)
        }
        sets[epoch] = ValidatorSet(setHash, totalStake);
    }

    error WarmupSlot(uint64 slot);

    function epochOf(uint64 slot) public view returns (uint64) {
        if (slot < firstNormalSlot) revert WarmupSlot(slot);
        return firstNormalEpoch + (slot - firstNormalSlot) / slotsPerEpoch;
    }

    function _le64(uint64 x) internal pure returns (bytes8 r) {
        uint64 y;
        for (uint256 i = 0; i < 8; i++) y |= ((x >> uint64(8 * i)) & 0xff) << uint64(8 * (7 - i));
        r = bytes8(y);
    }

    function _le16(uint16 x) internal pure returns (bytes2) {
        return bytes2(uint16((x >> 8) | (x << 8)));
    }

    function notarPayload(uint64 slot, bytes32 blockId) public view returns (bytes memory) {
        return abi.encodePacked(uint8(1), _le64(slot), blockId, _le16(shredVersion));
    }

    function finalPayload(uint64 slot) public view returns (bytes memory) {
        return abi.encodePacked(uint8(2), _le64(slot), _le16(shredVersion));
    }

    /// Fast path: one aggregate over the notar payload with >= 80% stake.
    /// Slow path: notar aggregate >= 60% AND finalize aggregate >= 60%.
    function _verifyCert(
        uint64 slot,
        bytes32 blockId,
        ValidatorSet memory vs,
        bytes calldata pks,
        uint256[] calldata stakes,
        Agg[] calldata aggs
    ) internal view returns (bool fast) {
        if (keccak256(abi.encode(pks, stakes)) != vs.hash) revert WrongSet();
        fast = aggs.length == 1;
        _check(pks, stakes, aggs[0], notarPayload(slot, blockId), vs.totalStake, fast ? 80 : 60);
        if (!fast) _check(pks, stakes, aggs[1], finalPayload(slot), vs.totalStake, 60);
    }

    function submitCertificate(
        uint64 slot,
        bytes32 blockId,
        bytes calldata pks,
        uint256[] calldata stakes,
        Agg[] calldata aggs
    ) external {
        uint64 epoch = epochOf(slot);
        ValidatorSet memory vs = sets[epoch];
        if (vs.hash == bytes32(0)) revert UnknownEpoch(epoch);
        bool fast = _verifyCert(slot, blockId, vs, pks, stakes, aggs);
        finalizedBlock[slot] = blockId;
        emit Finalized(slot, blockId, fast);
    }

    function _check(
        bytes calldata pks,
        uint256[] calldata stakes,
        Agg calldata a,
        bytes memory payload,
        uint256 total,
        uint256 pct
    ) internal view {
        (bytes memory apk, uint256 signed) = AlpenglowBLS.aggregate(pks, stakes, a.bits);
        if (signed * 100 < total * pct) revert BelowThreshold(signed, total);
        if (!AlpenglowBLS.verify(apk, payload, a.sig)) revert BadSignature();
    }
}
