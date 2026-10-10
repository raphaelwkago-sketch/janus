// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {AlpenglowBLS} from "./AlpenglowBLS.sol";

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
    mapping(uint64 => ValidatorSet) public sets;       // epoch -> set used to verify that epoch's certs
    mapping(uint64 => bytes32) public finalizedBlock;  // slot -> block_id

    event Finalized(uint64 indexed slot, bytes32 blockId, bool fastPath);

    error UnknownEpoch(uint64 epoch);
    error WrongSet();
    error BelowThreshold(uint256 signed, uint256 total);
    error BadSignature();

    constructor(uint16 shredVersion_, uint64 slotsPerEpoch_, uint64 epoch, bytes memory pks, uint256[] memory stakes) {
        shredVersion = shredVersion_;
        slotsPerEpoch = slotsPerEpoch_;
        uint256 total;
        for (uint256 i = 0; i < stakes.length; i++) total += stakes[i];
        sets[epoch] = ValidatorSet(keccak256(abi.encode(pks, stakes)), total);
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
        uint64 epoch = slot / slotsPerEpoch;
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
