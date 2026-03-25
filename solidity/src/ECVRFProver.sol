// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Secp256k1} from "./Secp256k1.sol";
import {ECVRFBase} from "./ECVRFBase.sol";

contract ECVRFProver is ECVRFBase {
    function prove(bytes32 sk, bytes calldata alpha)
        external view returns (bytes memory pi, bytes32 beta)
    {
        uint256 x = uint256(sk);
        require(x > 0 && x < Secp256k1.N, "invalid sk");

        (uint256 yX, uint256 yY) = Secp256k1.ecMul(x, Secp256k1.GX, Secp256k1.GY);
        (uint256 hX, uint256 hY, bool hOk) = _encodeToCurve(yX, yY, alpha);
        require(hOk, "encode_to_curve failed");

        (uint256 gammaX, uint256 gammaY) = Secp256k1.ecMul(x, hX, hY);
        uint256 k = _rfc6979(x, hX, hY);
        (uint256 uX, uint256 uY) = Secp256k1.ecMul(k, Secp256k1.GX, Secp256k1.GY);
        (uint256 vX, uint256 vY) = Secp256k1.ecMul(k, hX, hY);

        uint128 c = _challengeGeneration(yX, yY, hX, hY, gammaX, gammaY, uX, uY, vX, vY);
        uint256 s = addmod(k, mulmod(uint256(c), x, Secp256k1.N), Secp256k1.N);

        pi = abi.encodePacked(Secp256k1.compress(gammaX, gammaY), bytes16(c), bytes32(s));
        beta = _proofToHash(gammaX, gammaY);
    }

    function _rfc6979(uint256 skVal, uint256 hX, uint256 hY) internal pure returns (uint256) {
        bytes memory hComp = Secp256k1.compress(hX, hY);
        bytes32 h1 = sha256(hComp);
        bytes32 xBytes = bytes32(skVal);
        bytes32 h1Adj = bytes32(uint256(h1) % Secp256k1.N);

        bytes32 v = bytes32(0x0101010101010101010101010101010101010101010101010101010101010101);
        bytes32 k = bytes32(0);

        k = _hmac(k, abi.encodePacked(v, uint8(0x00), xBytes, h1Adj));
        v = _hmac(k, abi.encodePacked(v));
        k = _hmac(k, abi.encodePacked(v, uint8(0x01), xBytes, h1Adj));
        v = _hmac(k, abi.encodePacked(v));

        for (uint256 i = 0; i < 256; i++) {
            v = _hmac(k, abi.encodePacked(v));
            uint256 candidate = uint256(v);
            if (candidate >= 1 && candidate < Secp256k1.N) return candidate;
            k = _hmac(k, abi.encodePacked(v, uint8(0x00)));
            v = _hmac(k, abi.encodePacked(v));
        }
        revert("rfc6979: no valid nonce");
    }

    function _hmac(bytes32 key, bytes memory message) internal pure returns (bytes32) {
        bytes memory ipad = new bytes(64);
        bytes memory opad = new bytes(64);
        for (uint256 i = 0; i < 32; i++) {
            ipad[i] = bytes1(uint8(key[i]) ^ 0x36);
            opad[i] = bytes1(uint8(key[i]) ^ 0x5c);
        }
        for (uint256 i = 32; i < 64; i++) {
            ipad[i] = 0x36;
            opad[i] = 0x5c;
        }
        bytes32 inner = sha256(abi.encodePacked(ipad, message));
        return sha256(abi.encodePacked(opad, inner));
    }
}
