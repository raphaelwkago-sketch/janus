// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {MoonlinkLightClient} from "../src/MoonlinkLightClient.sol";

/// Solana testnet epoch schedule (getEpochSchedule: firstNormalEpoch 14, firstNormalSlot 524256, 432000 slots).
contract WarmupTest is Test {
    function test_testnetSchedule() public {
        MoonlinkLightClient lc = new MoonlinkLightClient(4457, 432000, true, 1056, bytes32(uint256(1)), 1);
        assertEq(lc.firstNormalEpoch(), 14);
        assertEq(lc.firstNormalSlot(), 524256);
        assertEq(lc.epochOf(524256), 14);
        assertEq(lc.epochOf(450906700), 1056);   // the testnet deposit slot (getEpochInfo said epoch 1056)
        vm.expectRevert(abi.encodeWithSelector(MoonlinkLightClient.WarmupSlot.selector, uint64(524255)));
        lc.epochOf(524255);
    }

    function test_noWarmup() public {
        MoonlinkLightClient lc = new MoonlinkLightClient(18915, 200, false, 5, bytes32(uint256(1)), 1);
        assertEq(lc.epochOf(1076), 5);
    }
}
