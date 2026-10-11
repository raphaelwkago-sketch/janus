// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {Moonlink, ISP1Verifier} from "../src/Moonlink.sol";
import {MoonlinkLightClient, setHashOf, totalStakeOf} from "../src/MoonlinkLightClient.sol";

/// Accepts any proof: isolates the bridge logic. The real SP1 Groth16 verifier is tested separately.
contract MockSP1 is ISP1Verifier {
    function verifyProof(bytes32, bytes calldata, bytes calldata) external pure {}
}

contract MoonlinkTest is Test {
    using stdJson for string;

    Moonlink ml;
    string j;
    bytes pks;
    uint256[] stakes;
    MoonlinkLightClient.Agg[] aggs;
    uint64 slot;
    bytes32 blockId;
    bytes32 constant DEPOSIT_PROGRAM = 0xd71dec929591a91ff4c4199baa018069b1f79ccd1d1bf2a5d67c2f39d447eb5d;

    function setUp() public {
        j = vm.readFile(string.concat(vm.projectRoot(), "/test/fixtures/cert_1076.json"));
        pks = j.readBytes(".pks");
        stakes = j.readUintArray(".stakes");
        aggs.push();
        aggs[0].sig = j.readBytes(".sig0");
        aggs[0].bits = j.readUintArray(".bits0");
        slot = uint64(j.readUint(".slot"));
        blockId = j.readBytes32(".blockId");
        ml = new Moonlink(uint16(j.readUint(".sv")), 200, false, slot / 200, setHashOf(pks, stakes), totalStakeOf(stakes), new MockSP1(), bytes32(uint256(1)), DEPOSIT_PROGRAM, bytes32(uint256(2)));
    }

    function pv(uint64 s, bytes32 bid, bytes32 prog, address to, uint64 amount, uint64 nonce) internal pure returns (bytes memory) {
        Moonlink.Receipt[] memory r = new Moonlink.Receipt[](1);
        r[0] = Moonlink.Receipt(to, amount, nonce);
        return abi.encode(Moonlink.PublicValues(s, bid, prog, r));
    }

    function test_claim_afterCertificate() public {
        ml.submitCertificate(slot, blockId, pks, stakes, aggs);
        ml.claim(pv(slot, blockId, DEPOSIT_PROGRAM, address(0x1111111111111111111111111111111111111111), 3e9, 7), "");
        assertEq(ml.balanceOf(address(0x1111111111111111111111111111111111111111)), 3e9);
    }

    function test_claim_rejects_unfinalizedBlock() public {
        vm.expectRevert(Moonlink.NotFinalized.selector);
        ml.claim(pv(slot, blockId, DEPOSIT_PROGRAM, address(0x1111), 3e9, 7), "");
    }

    function test_claim_rejects_otherBlockSameSlot() public {
        ml.submitCertificate(slot, blockId, pks, stakes, aggs);
        vm.expectRevert(Moonlink.NotFinalized.selector);
        ml.claim(pv(slot, bytes32(uint256(blockId) ^ 1), DEPOSIT_PROGRAM, address(0x1111), 3e9, 7), "");
    }

    function test_claim_rejects_otherProgram() public {
        ml.submitCertificate(slot, blockId, pks, stakes, aggs);
        vm.expectRevert(Moonlink.WrongProgram.selector);
        ml.claim(pv(slot, blockId, bytes32(uint256(DEPOSIT_PROGRAM) ^ 1), address(0x1111), 3e9, 7), "");
    }

    function test_claim_rejects_doubleClaim() public {
        ml.submitCertificate(slot, blockId, pks, stakes, aggs);
        ml.claim(pv(slot, blockId, DEPOSIT_PROGRAM, address(0x1111), 3e9, 7), "");
        vm.expectRevert(abi.encodeWithSelector(Moonlink.AlreadyClaimed.selector, uint64(7)));
        ml.claim(pv(slot, blockId, DEPOSIT_PROGRAM, address(0x1111), 3e9, 7), "");
    }

    function test_burn_writesProvableSlot() public {
        address u = address(0x1111111111111111111111111111111111111111);
        ml.submitCertificate(slot, blockId, pks, stakes, aggs);
        ml.claim(pv(slot, blockId, DEPOSIT_PROGRAM, u, 3e9, 7), "");
        bytes32 sol = bytes32(uint256(0xabcdef));
        vm.prank(u);
        uint64 n = ml.burn(1e9, sol);
        assertEq(n, 0);
        assertEq(ml.balanceOf(u), 2e9);
        assertEq(ml.totalSupply(), 2e9);
        // the exact storage word Solana will check via the Ethereum storage proof
        bytes32 key = keccak256(abi.encode(uint256(n), ml.BURNS_SLOT()));
        assertEq(vm.load(address(ml), key), keccak256(abi.encodePacked(sol, uint64(1e9), uint64(0))));
        vm.prank(u);
        assertEq(ml.burn(1e9, sol), 1);
    }

    function test_burn_rejects_moreThanBalance() public {
        vm.prank(address(0x2222));
        vm.expectRevert(Moonlink.BadBurn.selector);
        ml.burn(1, bytes32(uint256(1)));
    }
}
