// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// BLS12-381 checks for Alpenglow certificates using Ethereum's EIP-2537 precompiles (live since Pectra).
/// Pubkeys in G1, signatures in G2, ciphersuite BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_ (same as Solana's).
/// Points use the EIP-2537 uncompressed encoding: G1 = 128 bytes, G2 = 256 bytes.
library AlpenglowBLS {
    address constant G1ADD = address(0x0b);
    address constant G2ADD = address(0x0d);
    address constant PAIRING = address(0x0f);
    address constant MAP_FP2_TO_G2 = address(0x11);
    address constant MODEXP = address(0x05);

    bytes constant DST = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
    bytes constant POP_DST = "BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
    // (p - 1) / 2, split as (high 16 bytes, low 32 bytes) of the 48-byte value
    uint256 constant HALF_HI = 0x0d0088f51cbff34d258dd3db21a5d66b;
    uint256 constant HALF_LO = 0xb23ba5c279c2895fb39869507b587b120f55ffff58a9ffffdcff7fffffffd555;
    // field modulus p as 64 bytes (16 zero bytes + 48)
    bytes constant P = hex"000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab";
    // -G1 generator (x, p - y)
    bytes constant NEG_G1 = hex"0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb00000000000000000000000000000000114d1d6855d545a8aa7d76c8cf2e21f267816aef1db507c96655b9d5caac42364e6f38ba0ecb751bad54dcd6b939c2ca";

    error PrecompileFailed(address which);

    function _call(address to, bytes memory input, uint256 outLen) private view returns (bytes memory out) {
        out = new bytes(outLen);
        bool ok;
        assembly {
            ok := staticcall(gas(), to, add(input, 32), mload(input), add(out, 32), outLen)
        }
        if (!ok) revert PrecompileFailed(to);
    }

    /// RFC 9380 expand_message_xmd with SHA-256, 256 output bytes.
    function expandMsg(bytes memory msg_, bytes memory dst) internal pure returns (bytes memory out) {
        bytes memory dstPrime = abi.encodePacked(dst, uint8(dst.length));
        bytes32 b0 = sha256(abi.encodePacked(new bytes(64), msg_, uint16(256), uint8(0), dstPrime));
        bytes32 bi = sha256(abi.encodePacked(b0, uint8(1), dstPrime));
        out = abi.encodePacked(bi);
        for (uint8 i = 2; i <= 8; i++) {
            bi = sha256(abi.encodePacked(b0 ^ bi, i, dstPrime));
            out = abi.encodePacked(out, bi);
        }
    }

    function _modP(bytes memory e64) private view returns (bytes memory) {
        return _call(MODEXP, abi.encodePacked(uint256(64), uint256(1), uint256(64), e64, uint8(1), P), 64);
    }

    function _slice64(bytes memory b, uint256 off) private pure returns (bytes memory r) {
        r = new bytes(64);
        assembly {
            mstore(add(r, 32), mload(add(add(b, 32), off)))
            mstore(add(r, 64), mload(add(add(b, 64), off)))
        }
    }

    /// hash_to_curve for G2 (random oracle): two field elements -> map -> add.
    function hashToG2(bytes memory msg_) internal view returns (bytes memory) {
        return hashToG2(msg_, DST);
    }

    function hashToG2(bytes memory msg_, bytes memory dst) internal view returns (bytes memory) {
        bytes memory u = expandMsg(msg_, dst);
        bytes memory q0 = _call(MAP_FP2_TO_G2, abi.encodePacked(_modP(_slice64(u, 0)), _modP(_slice64(u, 64))), 256);
        bytes memory q1 = _call(MAP_FP2_TO_G2, abi.encodePacked(_modP(_slice64(u, 128)), _modP(_slice64(u, 192))), 256);
        return _call(G2ADD, abi.encodePacked(q0, q1), 256);
    }

    /// Sum the G1 pubkeys whose bit is set; also returns their stake. pks = n * 128 bytes.
    function aggregate(bytes calldata pks, uint256[] calldata stakes, uint256[] calldata bits)
        internal view returns (bytes memory acc, uint256 signed)
    {
        // one 256-byte scratch buffer: [acc | pk_i] -> G1ADD -> acc (no per-key allocation)
        bytes memory buf = new bytes(256); // acc starts as the point at infinity (zeros)
        uint256 n = stakes.length;
        require(pks.length == n * 128, "pks length");
        bool ok = true;
        for (uint256 i = 0; i < n; i++) {
            if ((bits[i >> 8] >> (i & 255)) & 1 == 0) continue;
            assembly {
                let p := add(buf, 32)
                calldatacopy(add(p, 128), add(pks.offset, mul(i, 128)), 128)
                ok := and(ok, staticcall(gas(), 0x0b, p, 256, p, 128))
            }
            signed += stakes[i];
        }
        if (!ok) revert PrecompileFailed(G1ADD);
        acc = new bytes(128);
        assembly {
            mcopy(add(acc, 32), add(buf, 32), 128)
        }
    }

    /// e(aggPk, H(m)) == e(G1, sig)
    function verify(bytes memory aggPk, bytes memory msg_, bytes calldata sig) internal view returns (bool) {
        bytes memory out = _call(PAIRING, abi.encodePacked(aggPk, hashToG2(msg_), NEG_G1, sig), 32);
        return uint256(bytes32(out)) == 1;
    }

    /// ZCash-style compressed encoding (48 bytes) of an EIP-2537 G1 point.
    function compressG1(bytes calldata pk) internal pure returns (bytes memory c) {
        uint256 yHi = uint256(bytes32(pk[64:96])) & ((1 << 128) - 1);
        uint256 yLo = uint256(bytes32(pk[96:128]));
        bool big = yHi > HALF_HI || (yHi == HALF_HI && yLo > HALF_LO);
        c = abi.encodePacked(pk[16:64]);
        c[0] = bytes1(uint8(c[0]) | 0x80 | (big ? 0x20 : 0));
    }

    /// Solana/Alpenglow proof of possession: sig over (payload | compressed pk) with the POP DST.
    /// payload is "ALPENGLOW" | vote account pubkey as registered on Solana.
    function verifyPop(bytes calldata pk, bytes calldata payload, bytes calldata popSig) internal view returns (bool) {
        bytes memory h = hashToG2(abi.encodePacked(payload, compressG1(pk)), POP_DST);
        bytes memory out = _call(PAIRING, abi.encodePacked(pk, h, NEG_G1, popSig), 32);
        return uint256(bytes32(out)) == 1;
    }
}
