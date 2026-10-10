// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {Moonlink, ISP1Verifier} from "../src/Moonlink.sol";
import {MoonlinkLightClient} from "../src/MoonlinkLightClient.sol";
import {SP1Verifier} from "../src/sp1/v6.1.0/SP1VerifierGroth16.sol";

/// End to end with no mocks: real Alpenglow certificate + real SP1 Groth16 proof of the slot-1076 deposit,
/// checked by Succinct's own v6.1.0 Groth16 verifier contract.
contract RealProofTest is Test {
    using stdJson for string;

    Moonlink ml;
    bytes pks;
    uint256[] stakes;
    MoonlinkLightClient.Agg[] aggs;
    uint64 slot;
    bytes32 blockId;
    bytes32 vkey;
    bytes publicValues;
    bytes proof;
    address constant TO = 0x1111111111111111111111111111111111111111;
    bytes32 constant DEPOSIT_PROGRAM = 0xd71dec929591a91ff4c4199baa018069b1f79ccd1d1bf2a5d67c2f39d447eb5d;

    function setUp() public {
        string memory j = vm.readFile(string.concat(vm.projectRoot(), "/test/fixtures/cert_1076.json"));
        pks = j.readBytes(".pks");
        stakes = j.readUintArray(".stakes");
        aggs.push();
        aggs[0].sig = j.readBytes(".sig0");
        aggs[0].bits = j.readUintArray(".bits0");
        slot = uint64(j.readUint(".slot"));
        blockId = j.readBytes32(".blockId");
        string memory g = vm.readFile(string.concat(vm.projectRoot(), "/test/fixtures/groth16_1076.json"));
        vkey = g.readBytes32(".vkey");
        publicValues = g.readBytes(".publicValues");
        proof = g.readBytes(".proof");
        ISP1Verifier v = ISP1Verifier(address(new SP1Verifier()));
        ml = new Moonlink(uint16(j.readUint(".sv")), 200, slot / 200, pks, stakes, v, vkey, DEPOSIT_PROGRAM, bytes32(uint256(2)));
    }

    function test_realProof_endToEnd() public {
        ml.submitCertificate(slot, blockId, pks, stakes, aggs);
        uint256 g0 = gasleft();
        ml.claim(publicValues, proof);
        console.log("claim gas (Groth16 verify + mint):", g0 - gasleft());
        assertEq(ml.balanceOf(TO), 3e9);
        assertTrue(ml.claimed(7));
    }

    function test_realProof_rejects_editedAmount() public {
        ml.submitCertificate(slot, blockId, pks, stakes, aggs);
        Moonlink.PublicValues memory pv = abi.decode(publicValues, (Moonlink.PublicValues));
        pv.receipts[0].amount = 500e9;
        vm.expectRevert();
        ml.claim(abi.encode(pv), proof);
    }

    function test_realProof_rejects_editedRecipient() public {
        ml.submitCertificate(slot, blockId, pks, stakes, aggs);
        Moonlink.PublicValues memory pv = abi.decode(publicValues, (Moonlink.PublicValues));
        pv.receipts[0].eth = address(0xbad);
        vm.expectRevert();
        ml.claim(abi.encode(pv), proof);
    }

    function test_realProof_rejects_corruptedProof() public {
        ml.submitCertificate(slot, blockId, pks, stakes, aggs);
        bytes memory p = proof;
        p[40] = bytes1(uint8(p[40]) ^ 1);
        vm.expectRevert();
        ml.claim(publicValues, p);
    }

    function test_realProof_rejects_withoutCertificate() public {
        vm.expectRevert(Moonlink.NotFinalized.selector);
        ml.claim(publicValues, proof);
    }
}
