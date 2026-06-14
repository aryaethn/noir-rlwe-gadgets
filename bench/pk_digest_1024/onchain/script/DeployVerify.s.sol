// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {Script, console} from "forge-std/Script.sol";
import {HonkVerifier} from "../src/HonkVerifier.sol";

/// Deploy the UltraHonk verifier to a live node (Anvil) and verify the PK-BFV proof on-chain.
contract DeployVerify is Script {
    function run() external {
        bytes memory proof = vm.readFileBinary("test/fixtures/proof");
        bytes memory raw = vm.readFileBinary("test/fixtures/public_inputs");
        uint256 n = raw.length / 32;
        bytes32[] memory pi = new bytes32[](n);
        for (uint256 i = 0; i < n; i++) {
            bytes32 w;
            uint256 off = 0x20 + i * 0x20;
            assembly {
                w := mload(add(raw, off))
            }
            pi[i] = w;
        }

        vm.startBroadcast();
        HonkVerifier v = new HonkVerifier();
        vm.stopBroadcast();

        bool ok = v.verify(proof, pi); // eth_call against the deployed contract
        console.log("HonkVerifier deployed at:", address(v));
        console.log("public inputs:", n);
        console.log("on-chain verify result:", ok);
        require(ok, "on-chain verification failed");
    }
}
