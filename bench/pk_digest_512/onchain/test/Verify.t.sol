// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {HonkVerifier} from "../src/HonkVerifier.sol";

/// On-chain verification of the PUBLIC-KEY-BFV proof-of-encryption proof (preset bfv_1024_27,
/// digest variant). The lone public input is the ciphertext/public-key digest.
/// Deploys the bb-generated UltraHonk Solidity verifier and verifies a real proof.
contract VerifyTest is Test {
    HonkVerifier internal verifier;

    function setUp() public {
        verifier = new HonkVerifier();
    }

    function _loadPublicInputs() internal view returns (bytes32[] memory pi) {
        bytes memory raw = vm.readFileBinary("test/fixtures/public_inputs");
        uint256 n = raw.length / 32;
        pi = new bytes32[](n);
        for (uint256 i = 0; i < n; i++) {
            bytes32 word;
            uint256 off = 0x20 + i * 0x20;
            assembly {
                word := mload(add(raw, off))
            }
            pi[i] = word;
        }
    }

    function test_verify_valid_proof_onchain() public {
        bytes memory proof = vm.readFileBinary("test/fixtures/proof");
        bytes32[] memory publicInputs = _loadPublicInputs();

        uint256 gasBefore = gasleft();
        bool ok = verifier.verify(proof, publicInputs);
        uint256 gasUsed = gasBefore - gasleft();

        emit log_named_uint("num_public_inputs", publicInputs.length);
        emit log_named_uint("proof_bytes", proof.length);
        emit log_named_uint("verify_gas", gasUsed);
        assertTrue(ok, "on-chain verification failed");
    }

    function test_reject_tampered_public_input() public {
        bytes memory proof = vm.readFileBinary("test/fixtures/proof");
        bytes32[] memory publicInputs = _loadPublicInputs();
        // Flip the public input (the digest): verification must fail (revert or false).
        publicInputs[0] = bytes32(uint256(publicInputs[0]) ^ 1);
        try verifier.verify(proof, publicInputs) returns (bool ok) {
            assertFalse(ok, "tampered public input unexpectedly accepted");
        } catch {
            // a revert (e.g. SumcheckFailed) is also a valid rejection
        }
    }
}
