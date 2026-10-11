// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;
import {Script, console} from "forge-std/Script.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {MoonlinkLightClient, setHashOf, totalStakeOf} from "../src/MoonlinkLightClient.sol";

/// Deploy + submit a certificate as real transactions on anvil (receipts give true gas incl. calldata).
contract Measure is Script {
    using stdJson for string;
    function run(string memory name) external {
        string memory j = vm.readFile(string.concat(vm.projectRoot(), "/test/fixtures/", name));
        bytes memory pks = j.readBytes(".pks");
        uint256[] memory stakes = j.readUintArray(".stakes");
        uint256 n = j.readUint(".nAgg");
        MoonlinkLightClient.Agg[] memory aggs = new MoonlinkLightClient.Agg[](n);
        for (uint256 i = 0; i < n; i++) {
            aggs[i].sig = j.readBytes(string.concat(".sig", vm.toString(i)));
            aggs[i].bits = j.readUintArray(string.concat(".bits", vm.toString(i)));
        }
        uint64 slot = uint64(j.readUint(".slot"));
        vm.startBroadcast();
        MoonlinkLightClient lc = new MoonlinkLightClient(uint16(j.readUint(".sv")), uint64(j.readUint(".spe")), false, uint64(j.readUint(".epoch")), setHashOf(pks, stakes), totalStakeOf(stakes));
        lc.submitCertificate(slot, j.readBytes32(".blockId"), pks, stakes, aggs);
        vm.stopBroadcast();
        console.log("finalized", lc.finalizedBlock(slot) == j.readBytes32(".blockId"));
    }
}
