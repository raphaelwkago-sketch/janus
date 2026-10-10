// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;
import {Test, console} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {AlpenglowBLS} from "../src/AlpenglowBLS.sol";

contract H {
    function setHash(bytes calldata pks, uint256[] calldata stakes) external pure returns (bytes32) { return keccak256(abi.encode(pks, stakes)); }
    function agg(bytes calldata pks, uint256[] calldata stakes, uint256[] calldata bits) external view returns (uint256 s) { (, s) = AlpenglowBLS.aggregate(pks, stakes, bits); }
    function h2c(bytes memory m) external view returns (bytes memory) { return AlpenglowBLS.hashToG2(m); }
    function nothing(bytes calldata pks, uint256[] calldata stakes) external pure returns (uint256) { return pks.length + stakes.length; }
}
contract ProfileTest is Test {
    using stdJson for string;
    function test_profile680() public {
        string memory j = vm.readFile(string.concat(vm.projectRoot(), "/test/fixtures/cert_sim680.json"));
        bytes memory pks = j.readBytes(".pks"); uint256[] memory st = j.readUintArray(".stakes"); uint256[] memory b = j.readUintArray(".bits0");
        H h = new H(); uint256 g;
        g = gasleft(); h.nothing(pks, st); console.log("call w/ 108KB args only:", g - gasleft());
        g = gasleft(); h.setHash(pks, st); console.log("set hash:", g - gasleft());
        g = gasleft(); h.agg(pks, st, b); console.log("aggregate 599 keys:", g - gasleft());
        g = gasleft(); h.h2c(j.readBytes(".msg0")); console.log("hash to G2:", g - gasleft());
    }
}
