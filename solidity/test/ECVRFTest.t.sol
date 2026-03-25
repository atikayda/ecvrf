// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import {ECVRFVerifier} from "../src/ECVRFVerifier.sol";
import {ECVRFProver} from "../src/ECVRFProver.sol";
import {Secp256k1} from "../src/Secp256k1.sol";

contract ECVRFTest is Test {
    ECVRFVerifier verifier;
    ECVRFProver prover;

    function setUp() public {
        verifier = new ECVRFVerifier();
        prover = new ECVRFProver();
    }

    // --- Positive verification tests ---

    function test_verify_emptyAlpha_sk1() public view {
        bytes memory pk = hex"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        bytes memory pi = hex"024192220588c4ef502f5d2ab75552edfbe0256cebb0424efb9c4c58f438c3dcb43740e701a78589f13a3577908db37b1ddb55edaf0706552da59a41b69be3740878407cf6d13675cd94802a33b5e629f7";
        bytes memory alpha = hex"";
        bytes32 expectedBeta = hex"6bf7eda22a89f87fb8c8e17fa111727ca02d0a23db29fdcbe7ac84280e8bde24";

        (bool valid, bytes32 beta) = verifier.verify(pk, pi, alpha);
        assertTrue(valid, "should be valid");
        assertEq(beta, expectedBeta, "beta mismatch");
    }

    function test_verify_emptyAlpha_keyA() public view {
        bytes memory pk = hex"020996f71bc0c30d4141d85e1e7395e0198a2c6237e4a8b8cc0207c78082f97438";
        bytes memory pi = hex"022e28af17f33bfe54984cde0743a289f4ce943397c6bf61c4d9597878f014550b0d3710b3014d7cc4601bccef00eafec7a2173e2c53aa82214d2a97e08ab77584c4a20378f99fe347bc963ca0500017bb";
        bytes memory alpha = hex"";
        bytes32 expectedBeta = hex"508f9a404c2074e1701ba9098043fca178282943d7892f2476aa5b925de51695";

        (bool valid, bytes32 beta) = verifier.verify(pk, pi, alpha);
        assertTrue(valid, "should be valid");
        assertEq(beta, expectedBeta, "beta mismatch");
    }

    function test_verify_emptyAlpha_keyB() public view {
        // h_ctr = 1 (second iteration of try-and-increment)
        bytes memory pk = hex"0303cb5b074daa30cc43f58bfec280185bc2543d67aff533baee6afbe61b6492fb";
        bytes memory pi = hex"032e7686ba8b2cd61b75ccce93ae49cd97ff5d65009586d9db7fb0d1420f3d087b520b88c0422a7b4dbd97471b79a50393cc4400324f49c38bb308fef58fca7f81dd94f86aa0861a604fe544ab13bd7706";
        bytes memory alpha = hex"";
        bytes32 expectedBeta = hex"816255bf4c87656e41e4c1c0e40ecc6e11ee86d996da843f74d49c1f80cdbcc3";

        (bool valid, bytes32 beta) = verifier.verify(pk, pi, alpha);
        assertTrue(valid, "should be valid");
        assertEq(beta, expectedBeta, "beta mismatch");
    }

    function test_verify_singleNullByte_keyA() public view {
        // h_ctr = 2 (third iteration)
        bytes memory pk = hex"020996f71bc0c30d4141d85e1e7395e0198a2c6237e4a8b8cc0207c78082f97438";
        bytes memory pi = hex"03da2e8fe3af65da1e68e133cd65e7dc4309db3ceea971cd916c0f0e93e25125c4824458e8883c15642109e1b6d9b0273ab5245ae674014aa3c8142d15d9578bdeba4eb83c7a34b5324cca1bb891932f25";
        bytes memory alpha = hex"00";
        bytes32 expectedBeta = hex"91e438c9fbdd0949502acd234d39e085af7d9bf6c92d35116f67430f70733a45";

        (bool valid, bytes32 beta) = verifier.verify(pk, pi, alpha);
        assertTrue(valid, "should be valid");
        assertEq(beta, expectedBeta, "beta mismatch");
    }

    function test_verify_singleByte41_keyA() public view {
        bytes memory pk = hex"020996f71bc0c30d4141d85e1e7395e0198a2c6237e4a8b8cc0207c78082f97438";
        bytes memory pi = hex"02fd3537cf75c1fe158e4a2332012c8c6088f957aa6c16426bdfe5519d0e80c0e7123275d2dd206fce4e27d1ab38563255833ac30af2bb52352bc33d98aa8ff9ee29bb4d6eba5da1bb2234f602de78b014";
        bytes memory alpha = hex"41";
        bytes32 expectedBeta = hex"22740fb5af534a8813f5e0badec8f4cd1857d55c7ee47baec9ccf144f1a18fc5";

        (bool valid, bytes32 beta) = verifier.verify(pk, pi, alpha);
        assertTrue(valid, "should be valid");
        assertEq(beta, expectedBeta, "beta mismatch");
    }

    // --- Negative verification tests ---

    function test_neg_tamperedGamma_byte5() public view {
        bytes memory pk = hex"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        bytes memory pi = hex"024192220589c4ef502f5d2ab75552edfbe0256cebb0424efb9c4c58f438c3dcb43740e701a78589f13a3577908db37b1ddb55edaf0706552da59a41b69be3740878407cf6d13675cd94802a33b5e629f7";
        (bool valid,) = verifier.verify(pk, pi, hex"");
        assertFalse(valid, "tampered gamma byte5");
    }

    function test_neg_tamperedGamma_byte1() public view {
        bytes memory pk = hex"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        bytes memory pi = hex"02c192220588c4ef502f5d2ab75552edfbe0256cebb0424efb9c4c58f438c3dcb43740e701a78589f13a3577908db37b1ddb55edaf0706552da59a41b69be3740878407cf6d13675cd94802a33b5e629f7";
        (bool valid,) = verifier.verify(pk, pi, hex"");
        assertFalse(valid, "tampered gamma byte1");
    }

    function test_neg_tamperedC_byte33() public view {
        bytes memory pk = hex"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        bytes memory pi = hex"024192220588c4ef502f5d2ab75552edfbe0256cebb0424efb9c4c58f438c3dcb43640e701a78589f13a3577908db37b1ddb55edaf0706552da59a41b69be3740878407cf6d13675cd94802a33b5e629f7";
        (bool valid,) = verifier.verify(pk, pi, hex"");
        assertFalse(valid, "tampered c byte33");
    }

    function test_neg_zeroedChallenge() public view {
        bytes memory pk = hex"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        bytes memory pi = hex"024192220588c4ef502f5d2ab75552edfbe0256cebb0424efb9c4c58f438c3dcb400000000000000000000000000000000db55edaf0706552da59a41b69be3740878407cf6d13675cd94802a33b5e629f7";
        (bool valid,) = verifier.verify(pk, pi, hex"");
        assertFalse(valid, "zeroed challenge");
    }

    function test_neg_tamperedS() public view {
        bytes memory pk = hex"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        bytes memory pi = hex"024192220588c4ef502f5d2ab75552edfbe0256cebb0424efb9c4c58f438c3dcb43740e701a78589f13a3577908db37b1dda55edaf0706552da59a41b69be3740878407cf6d13675cd94802a33b5e629f7";
        (bool valid,) = verifier.verify(pk, pi, hex"");
        assertFalse(valid, "tampered s");
    }

    function test_neg_sEqualsN() public view {
        bytes memory pk = hex"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        bytes memory pi = hex"024192220588c4ef502f5d2ab75552edfbe0256cebb0424efb9c4c58f438c3dcb43740e701a78589f13a3577908db37b1dfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";
        (bool valid,) = verifier.verify(pk, pi, hex"");
        assertFalse(valid, "s = n");
    }

    function test_neg_sEqualsNPlus1() public view {
        bytes memory pk = hex"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        bytes memory pi = hex"024192220588c4ef502f5d2ab75552edfbe0256cebb0424efb9c4c58f438c3dcb43740e701a78589f13a3577908db37b1dfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364142";
        (bool valid,) = verifier.verify(pk, pi, hex"");
        assertFalse(valid, "s = n+1");
    }

    function test_neg_wrongPK() public view {
        bytes memory pk = hex"0303cb5b074daa30cc43f58bfec280185bc2543d67aff533baee6afbe61b6492fb";
        bytes memory pi = hex"024192220588c4ef502f5d2ab75552edfbe0256cebb0424efb9c4c58f438c3dcb43740e701a78589f13a3577908db37b1ddb55edaf0706552da59a41b69be3740878407cf6d13675cd94802a33b5e629f7";
        (bool valid,) = verifier.verify(pk, pi, hex"");
        assertFalse(valid, "wrong pk");
    }

    function test_neg_wrongAlpha() public view {
        bytes memory pk = hex"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        bytes memory pi = hex"024192220588c4ef502f5d2ab75552edfbe0256cebb0424efb9c4c58f438c3dcb43740e701a78589f13a3577908db37b1ddb55edaf0706552da59a41b69be3740878407cf6d13675cd94802a33b5e629f7";
        (bool valid,) = verifier.verify(pk, pi, hex"deadbeef");
        assertFalse(valid, "wrong alpha");
    }

    function test_neg_truncatedProof() public view {
        bytes memory pk = hex"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        bytes memory pi = hex"024192220588c4ef502f5d2ab75552edfbe0256cebb0424efb9c4c58f438c3dcb43740e701a78589f13a3577908db37b1ddb55edaf0706552da59a41b69be3740878407cf6d13675cd94802a33b5e629";
        (bool valid,) = verifier.verify(pk, pi, hex"");
        assertFalse(valid, "truncated proof");
    }

    function test_neg_extendedProof() public view {
        bytes memory pk = hex"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        bytes memory pi = hex"024192220588c4ef502f5d2ab75552edfbe0256cebb0424efb9c4c58f438c3dcb43740e701a78589f13a3577908db37b1ddb55edaf0706552da59a41b69be3740878407cf6d13675cd94802a33b5e629f7ff";
        (bool valid,) = verifier.verify(pk, pi, hex"");
        assertFalse(valid, "extended proof");
    }

    function test_neg_gammaNotOnCurve() public view {
        bytes memory pk = hex"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        bytes memory pi = hex"02ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff3740e701a78589f13a3577908db37b1ddb55edaf0706552da59a41b69be3740878407cf6d13675cd94802a33b5e629f7";
        (bool valid,) = verifier.verify(pk, pi, hex"");
        assertFalse(valid, "gamma not on curve");
    }

    function test_neg_allZeroProof() public view {
        bytes memory pk = hex"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        bytes memory pi = hex"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
        (bool valid,) = verifier.verify(pk, pi, hex"");
        assertFalse(valid, "all-zero proof");
    }

    function test_neg_invalidPrefix04() public view {
        bytes memory pk = hex"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        bytes memory pi = hex"044192220588c4ef502f5d2ab75552edfbe0256cebb0424efb9c4c58f438c3dcb43740e701a78589f13a3577908db37b1ddb55edaf0706552da59a41b69be3740878407cf6d13675cd94802a33b5e629f7";
        (bool valid,) = verifier.verify(pk, pi, hex"");
        assertFalse(valid, "invalid prefix 0x04");
    }

    function test_neg_emptyVsNullByteAlpha() public view {
        bytes memory pk = hex"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        // Proof for empty alpha verified with single null byte alpha
        bytes memory pi = hex"024192220588c4ef502f5d2ab75552edfbe0256cebb0424efb9c4c58f438c3dcb43740e701a78589f13a3577908db37b1ddb55edaf0706552da59a41b69be3740878407cf6d13675cd94802a33b5e629f7";
        (bool valid,) = verifier.verify(pk, pi, hex"00");
        assertFalse(valid, "empty vs null byte alpha");
    }

    // --- Prove tests ---

    function test_prove_emptyAlpha_sk1() public view {
        bytes32 sk = bytes32(uint256(1));
        bytes memory expectedPi = hex"024192220588c4ef502f5d2ab75552edfbe0256cebb0424efb9c4c58f438c3dcb43740e701a78589f13a3577908db37b1ddb55edaf0706552da59a41b69be3740878407cf6d13675cd94802a33b5e629f7";
        bytes32 expectedBeta = hex"6bf7eda22a89f87fb8c8e17fa111727ca02d0a23db29fdcbe7ac84280e8bde24";

        (bytes memory pi, bytes32 beta) = prover.prove(sk, hex"");
        assertEq(pi, expectedPi, "pi mismatch");
        assertEq(beta, expectedBeta, "beta mismatch");
    }

    function test_prove_emptyAlpha_keyA() public view {
        bytes32 sk = hex"9828d8ebfd85e5ddd819e7a87515a882f7b0c2b664e852949eaa4028f5d83934";
        bytes memory expectedPi = hex"022e28af17f33bfe54984cde0743a289f4ce943397c6bf61c4d9597878f014550b0d3710b3014d7cc4601bccef00eafec7a2173e2c53aa82214d2a97e08ab77584c4a20378f99fe347bc963ca0500017bb";
        bytes32 expectedBeta = hex"508f9a404c2074e1701ba9098043fca178282943d7892f2476aa5b925de51695";

        (bytes memory pi, bytes32 beta) = prover.prove(sk, hex"");
        assertEq(pi, expectedPi, "pi mismatch");
        assertEq(beta, expectedBeta, "beta mismatch");
    }

    function test_prove_singleByte41_keyA() public view {
        bytes32 sk = hex"9828d8ebfd85e5ddd819e7a87515a882f7b0c2b664e852949eaa4028f5d83934";
        bytes memory expectedPi = hex"02fd3537cf75c1fe158e4a2332012c8c6088f957aa6c16426bdfe5519d0e80c0e7123275d2dd206fce4e27d1ab38563255833ac30af2bb52352bc33d98aa8ff9ee29bb4d6eba5da1bb2234f602de78b014";
        bytes32 expectedBeta = hex"22740fb5af534a8813f5e0badec8f4cd1857d55c7ee47baec9ccf144f1a18fc5";

        (bytes memory pi, bytes32 beta) = prover.prove(sk, hex"41");
        assertEq(pi, expectedPi, "pi mismatch");
        assertEq(beta, expectedBeta, "beta mismatch");
    }

    // --- Round-trip test ---

    function test_roundTrip() public view {
        bytes32 sk = bytes32(uint256(1));
        bytes memory pk = hex"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        bytes memory alpha = hex"deadbeef";

        (bytes memory pi, bytes32 proveBeta) = prover.prove(sk, alpha);
        (bool valid, bytes32 verifyBeta) = verifier.verify(pk, pi, alpha);
        assertTrue(valid, "round-trip verify failed");
        assertEq(proveBeta, verifyBeta, "beta mismatch in round-trip");
    }

    // --- proofToHash test ---

    function test_proofToHash() public view {
        bytes memory pi = hex"024192220588c4ef502f5d2ab75552edfbe0256cebb0424efb9c4c58f438c3dcb43740e701a78589f13a3577908db37b1ddb55edaf0706552da59a41b69be3740878407cf6d13675cd94802a33b5e629f7";
        bytes32 expected = hex"6bf7eda22a89f87fb8c8e17fa111727ca02d0a23db29fdcbe7ac84280e8bde24";
        assertEq(verifier.proofToHash(pi), expected, "proofToHash mismatch");
    }

    // --- EC arithmetic unit tests ---

    function test_decompressGenerator() public view {
        bytes memory compressed = hex"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        (uint256 x, uint256 y, bool ok) = Secp256k1.decompress(compressed);
        assertTrue(ok, "decompress failed");
        assertEq(x, Secp256k1.GX, "x mismatch");
        assertEq(y, Secp256k1.GY, "y mismatch");
    }

    function test_compressGenerator() public pure {
        bytes memory result = Secp256k1.compress(Secp256k1.GX, Secp256k1.GY);
        bytes memory expected = hex"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        assertEq(result, expected, "compress mismatch");
    }

    function test_ecMul_1xG() public view {
        (uint256 x, uint256 y) = Secp256k1.ecMul(1, Secp256k1.GX, Secp256k1.GY);
        assertEq(x, Secp256k1.GX, "1*G x");
        assertEq(y, Secp256k1.GY, "1*G y");
    }

    function test_ecMul_2xG() public view {
        (uint256 x, uint256 y) = Secp256k1.ecMul(2, Secp256k1.GX, Secp256k1.GY);
        assertTrue(Secp256k1.isOnCurve(x, y), "2*G not on curve");
        // 2*G compressed: 02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5
        bytes memory comp = Secp256k1.compress(x, y);
        assertEq(comp, hex"02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5", "2*G");
    }
}
