// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {Moonlink, ISP1Verifier} from "../src/Moonlink.sol";
import {MoonlinkLightClient} from "../src/MoonlinkLightClient.sol";
import {SP1Verifier} from "../src/sp1/v6.1.0/SP1VerifierGroth16.sol";

/// Validator-set handoff with real data: Ethereum trusts epoch E-1's set, then learns epoch E's set from
/// the recorder account on Solana (SP1 Groth16 proof) + the record block's BLS certificate, accepted only
/// because those signers also hold >= 60% of epoch E-1's stake.
contract SetHandoffTest is Test {
    using stdJson for string;

    Moonlink ml;
    string j;
    bytes pksOld; uint256[] stakesOld; bytes pksNew; uint256[] stakesNew;
    MoonlinkLightClient.Agg[] aggs;
    Moonlink.Handoff h;
    bytes setPv; bytes setProof;
    bytes32 constant DEPOSIT_PROGRAM = 0xd71dec929591a91ff4c4199baa018069b1f79ccd1d1bf2a5d67c2f39d447eb5d;
    bytes32 recorder;

    function setUp() public {
        j = vm.readFile(string.concat(vm.projectRoot(), "/test/fixtures/set_handoff.json"));
        pksOld = j.readBytes(".pksOld"); stakesOld = j.readUintArray(".stakesOld");
        pksNew = j.readBytes(".pksNew"); stakesNew = j.readUintArray(".stakesNew");
        setPv = j.readBytes(".setPublicValues"); setProof = j.readBytes(".setProof");
        aggs.push(); aggs[0].sig = j.readBytes(".sig0"); aggs[0].bits = j.readUintArray(".bits0");
        Moonlink.SetValues memory s = abi.decode(setPv, (Moonlink.SetValues));
        recorder = s.program;
        ml = _deploy(pksOld, stakesOld);
        h.pksOld = pksOld; h.stakesOld = stakesOld;
        uint256[] memory oi = j.readUintArray(".oldIndexOfNewRank");
        for (uint256 i = 0; i < oi.length; i++) { h.oldIndexOfNewRank.push(oi[i]); h.popPayload.push(""); h.popSig.push(""); }
    }

    function _deploy(bytes memory pks, uint256[] memory stakes) internal returns (Moonlink) {
        return new Moonlink(uint16(j.readUint(".sv")), 200, uint64(j.readUint(".epochOld")), pks, stakes,
            ISP1Verifier(address(new SP1Verifier())), j.readBytes32(".vkey"), DEPOSIT_PROGRAM, recorder);
    }

    function test_handoff_realData() public {
        uint256 g0 = gasleft();
        ml.installNextSet(setPv, setProof, pksNew, stakesNew, aggs, h);
        console.log("installNextSet gas (4 validators):", g0 - gasleft());
        uint64 e = uint64(j.readUint(".epochNew"));
        (bytes32 hash, uint256 total) = ml.sets(e);
        assertEq(hash, keccak256(abi.encode(pksNew, stakesNew)));
        assertEq(ml.finalizedBlock(uint64(j.readUint(".slot"))), j.readBytes32(".blockId"));
        console.log("new set total stake:", total);

        // a later real block of the new epoch now verifies through the installed set alone
        MoonlinkLightClient.Agg[] memory a2 = new MoonlinkLightClient.Agg[](1);
        a2[0].sig = j.readBytes(".sig2"); a2[0].bits = j.readUintArray(".bits2");
        uint64 s2 = uint64(j.readUint(".slot2"));
        ml.submitCertificate(s2, j.readBytes32(".blockId2"), pksNew, stakesNew, a2);
        assertEq(ml.finalizedBlock(s2), j.readBytes32(".blockId2"));
    }

    function test_handoff_rejects_secondInstall() public {
        ml.installNextSet(setPv, setProof, pksNew, stakesNew, aggs, h);
        vm.expectRevert(Moonlink.BadEpoch.selector);
        ml.installNextSet(setPv, setProof, pksNew, stakesNew, aggs, h);
    }

    function test_handoff_rejects_editedSetValues() public {
        Moonlink.SetValues memory s = abi.decode(setPv, (Moonlink.SetValues));
        s.setHash = keccak256("attacker set");
        vm.expectRevert();
        ml.installNextSet(abi.encode(s), setProof, pksNew, stakesNew, aggs, h);
    }

    function test_handoff_rejects_otherKeysThanProven() public {
        bytes memory fake = bytes.concat(pksNew); fake[60] ^= 0x01;   // relayer swaps in a different key list
        vm.expectRevert(MoonlinkLightClient.WrongSet.selector);
        ml.installNextSet(setPv, setProof, fake, stakesNew, aggs, h);
    }

    function test_handoff_rejects_wrongOldSet() public {
        h.stakesOld[0] += 1;
        vm.expectRevert(MoonlinkLightClient.WrongSet.selector);
        ml.installNextSet(setPv, setProof, pksNew, stakesNew, aggs, h);
    }

    function test_handoff_rejects_mismatchedOldKey() public {
        // claim new rank 0 is old validator #2 when it is not
        uint256 o = h.oldIndexOfNewRank[0];
        h.oldIndexOfNewRank[0] = o == 1 ? 2 : 1;
        vm.expectRevert(abi.encodeWithSelector(Moonlink.SignerKeyMismatch.selector, 0));
        ml.installNextSet(setPv, setProof, pksNew, stakesNew, aggs, h);
    }

    function test_handoff_rejects_newSignerWithoutPop() public {
        h.oldIndexOfNewRank[1] = 0;   // pretend rank 1 is a brand-new validator: it must prove key possession
        vm.expectRevert(abi.encodeWithSelector(Moonlink.MissingPop.selector, 1));
        ml.installNextSet(setPv, setProof, pksNew, stakesNew, aggs, h);
    }

    function test_handoff_rejects_lessThan60pctOfOldStake() public {
        // Ethereum trusted an old set where an extra validator (who did NOT sign) held most of the stake:
        // the new set's signers then cover < 60% of the old stake and the handoff must stop.
        bytes memory extra = hex"0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1";
        bytes memory pks = bytes.concat(pksOld, extra);
        uint256[] memory st = new uint256[](stakesOld.length + 1);
        uint256 sum;
        for (uint256 i = 0; i < stakesOld.length; i++) { st[i] = stakesOld[i]; sum += stakesOld[i]; }
        st[stakesOld.length] = sum;   // the non-signer holds 50% -> signers hold 50% < 60%
        ml = _deploy(pks, st);
        h.pksOld = pks; h.stakesOld = st;
        vm.expectRevert(abi.encodeWithSelector(Moonlink.HandoffTooLow.selector, sum, 2 * sum));
        ml.installNextSet(setPv, setProof, pksNew, stakesNew, aggs, h);
    }
}
