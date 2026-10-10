// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {MoonlinkLightClient} from "../src/MoonlinkLightClient.sol";
import {AlpenglowBLS} from "../src/AlpenglowBLS.sol";

contract BLSHarness {
    function h2c(bytes memory m) external view returns (bytes memory) {
        return AlpenglowBLS.hashToG2(m);
    }
}

contract LightClientTest is Test {
    using stdJson for string;

    struct Fx {
        uint64 slot; bytes32 blockId; uint16 sv; uint64 spe; uint64 epoch;
        bytes pks; uint256[] stakes; MoonlinkLightClient.Agg[] aggs;
    }

    function load(string memory name) internal view returns (Fx memory f, string memory j) {
        j = vm.readFile(string.concat(vm.projectRoot(), "/test/fixtures/", name));
        f.slot = uint64(j.readUint(".slot"));
        f.blockId = j.readBytes32(".blockId");
        f.sv = uint16(j.readUint(".sv"));
        f.spe = uint64(j.readUint(".spe"));
        f.epoch = uint64(j.readUint(".epoch"));
        f.pks = j.readBytes(".pks");
        f.stakes = j.readUintArray(".stakes");
        uint256 n = j.readUint(".nAgg");
        f.aggs = new MoonlinkLightClient.Agg[](n);
        for (uint256 i = 0; i < n; i++) {
            f.aggs[i].sig = j.readBytes(string.concat(".sig", vm.toString(i)));
            f.aggs[i].bits = j.readUintArray(string.concat(".bits", vm.toString(i)));
        }
    }

    function deploy(Fx memory f) internal returns (MoonlinkLightClient lc) {
        lc = new MoonlinkLightClient(f.sv, f.spe, f.epoch, f.pks, f.stakes);
    }

    function test_hashToCurveMatchesPyEcc() public {
        (, string memory j) = load("cert_1076.json");
        BLSHarness h = new BLSHarness();
        assertEq(h.h2c(j.readBytes(".msg0")), j.readBytes(".hm0"));
    }

    function test_realCertificate_slot1076() public {
        (Fx memory f,) = load("cert_1076.json");
        MoonlinkLightClient lc = deploy(f);
        uint256 g = gasleft();
        lc.submitCertificate(f.slot, f.blockId, f.pks, f.stakes, f.aggs);
        console.log("gas: real 4-validator cert verify =", g - gasleft());
        assertEq(lc.finalizedBlock(f.slot), f.blockId);
    }

    function test_rejects_wrongBlockId() public {
        (Fx memory f,) = load("cert_1076.json");
        MoonlinkLightClient lc = deploy(f);
        vm.expectRevert(MoonlinkLightClient.BadSignature.selector);
        lc.submitCertificate(f.slot, bytes32(uint256(f.blockId) ^ 1), f.pks, f.stakes, f.aggs);
    }

    function test_rejects_wrongSlot() public {
        (Fx memory f,) = load("cert_1076.json");
        MoonlinkLightClient lc = deploy(f);
        vm.expectRevert(MoonlinkLightClient.BadSignature.selector);
        lc.submitCertificate(f.slot + 1, f.blockId, f.pks, f.stakes, f.aggs);
    }

    function test_rejects_fakeValidatorSet() public {
        (Fx memory f,) = load("cert_1076.json");
        MoonlinkLightClient lc = deploy(f);
        f.stakes[0] += 1;
        vm.expectRevert(MoonlinkLightClient.WrongSet.selector);
        lc.submitCertificate(f.slot, f.blockId, f.pks, f.stakes, f.aggs);
    }

    function test_rejects_droppedSigner() public {
        (Fx memory f,) = load("cert_1076.json");
        MoonlinkLightClient lc = deploy(f);
        f.aggs[0].bits[0] &= ~uint256(1); // claim validator 0 didn't sign: 75% < 80% fast threshold
        vm.expectRevert(abi.encodeWithSelector(MoonlinkLightClient.BelowThreshold.selector, f.stakes[1] + f.stakes[2] + f.stakes[3], f.stakes[0] + f.stakes[1] + f.stakes[2] + f.stakes[3]));
        lc.submitCertificate(f.slot, f.blockId, f.pks, f.stakes, f.aggs);
    }

    function test_rejects_wrongEpoch() public {
        (Fx memory f,) = load("cert_1076.json");
        MoonlinkLightClient lc = deploy(f);
        vm.expectRevert(abi.encodeWithSelector(MoonlinkLightClient.UnknownEpoch.selector, f.epoch + 1));
        lc.submitCertificate(f.slot + f.spe, f.blockId, f.pks, f.stakes, f.aggs);
    }

    function test_mainnetScale_680validators() public {
        (Fx memory f, string memory j) = load("cert_sim680.json");
        MoonlinkLightClient lc = deploy(f);
        uint256 g = gasleft();
        lc.submitCertificate(f.slot, f.blockId, f.pks, f.stakes, f.aggs);
        console.log("gas: simulated 680-validator cert verify (execution) =", g - gasleft());
        console.log("signers:", j.readUint(".nSigners"), " calldata bytes ~", f.pks.length + f.stakes.length * 32);
        assertEq(lc.finalizedBlock(f.slot), f.blockId);
    }
}
