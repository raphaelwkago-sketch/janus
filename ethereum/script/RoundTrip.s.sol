// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {Moonlink, ISP1Verifier} from "../src/Moonlink.sol";
import {MoonlinkLightClient, setHashOf, totalStakeOf} from "../src/MoonlinkLightClient.sol";
import {SP1Verifier} from "../src/sp1/v6.1.0/SP1VerifierGroth16.sol";

/// Real round trip on a live Ethereum network (Sepolia):
///  1. deploy Succinct's v6.1.0 Groth16 verifier + Moonlink (trusting the Solana cluster's validator set)
///  2. submit the real BLS finalization certificate of the deposit block
///  3. claim with the real SP1 Groth16 proof -> wrapped SOL minted to the depositor's Ethereum address
///  4. burn part of it toward a Solana address -> burns[nonce] written to storage (proven later on Solana)
/// env: CERT, G16 (fixture paths), SOL_RECIPIENT (bytes32), BURN (lamports)
contract RoundTrip is Script {
    using stdJson for string;
    bytes32 constant DEPOSIT_PROGRAM = 0xd71dec929591a91ff4c4199baa018069b1f79ccd1d1bf2a5d67c2f39d447eb5d;

    function run() external {
        string memory j = vm.readFile(vm.envString("CERT"));
        string memory g = vm.readFile(vm.envString("G16"));
        bytes memory pks = j.readBytes(".pks");
        uint256[] memory stakes = j.readUintArray(".stakes");
        uint64 slot = uint64(j.readUint(".slot"));
        MoonlinkLightClient.Agg[] memory aggs = new MoonlinkLightClient.Agg[](j.readUint(".nAgg"));
        for (uint256 i = 0; i < aggs.length; i++) {
            aggs[i].sig = j.readBytes(string.concat(".sig", vm.toString(i)));
            aggs[i].bits = j.readUintArray(string.concat(".bits", vm.toString(i)));
        }

        vm.startBroadcast();
        SP1Verifier v = new SP1Verifier();
        Moonlink ml = new Moonlink(uint16(j.readUint(".sv")), 200, false, slot / 200, setHashOf(pks, stakes), totalStakeOf(stakes),
            ISP1Verifier(address(v)), g.readBytes32(".vkey"), DEPOSIT_PROGRAM, bytes32(uint256(2)));
        ml.submitCertificate(slot, j.readBytes32(".blockId"), pks, stakes, aggs);
        ml.claim(g.readBytes(".publicValues"), g.readBytes(".proof"));
        uint64 nonce = ml.burn(uint64(vm.envUint("BURN")), vm.envBytes32("SOL_RECIPIENT"));
        vm.stopBroadcast();

        console.log("verifier", address(v));
        console.log("moonlink", address(ml));
        console.log("balance after burn", ml.balanceOf(msg.sender));
        console.log("burn nonce", nonce);
    }
}
