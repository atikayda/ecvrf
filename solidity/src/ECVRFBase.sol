// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Secp256k1} from "./Secp256k1.sol";

abstract contract ECVRFBase {
    uint8 internal constant SUITE_BYTE = 0xFE;

    function _encodeToCurve(uint256 pkX, uint256 pkY, bytes calldata alpha)
        internal view returns (uint256, uint256, bool)
    {
        bytes memory pkComp = Secp256k1.compress(pkX, pkY);
        for (uint256 ctr = 0; ctr < 256; ctr++) {
            bytes32 candidate = sha256(
                abi.encodePacked(SUITE_BYTE, uint8(0x01), pkComp, alpha, uint8(ctr), uint8(0x00))
            );
            bytes memory comp = new bytes(33);
            comp[0] = 0x02;
            assembly { mstore(add(comp, 0x21), candidate) }
            (uint256 x, uint256 y, bool ok) = Secp256k1.decompress(comp);
            if (ok) return (x, y, true);
        }
        return (0, 0, false);
    }

    function _challengeGeneration(
        uint256 yX, uint256 yY,
        uint256 hX, uint256 hY,
        uint256 gammaX, uint256 gammaY,
        uint256 uX, uint256 uY,
        uint256 vX, uint256 vY
    ) internal pure returns (uint128) {
        bytes32 ch = sha256(abi.encodePacked(
            SUITE_BYTE, uint8(0x02),
            Secp256k1.compress(yX, yY),
            Secp256k1.compress(hX, hY),
            Secp256k1.compress(gammaX, gammaY),
            Secp256k1.compress(uX, uY),
            Secp256k1.compress(vX, vY),
            uint8(0x00)
        ));
        return uint128(bytes16(ch));
    }

    function _proofToHash(uint256 gammaX, uint256 gammaY) internal pure returns (bytes32) {
        return sha256(abi.encodePacked(
            SUITE_BYTE, uint8(0x03), Secp256k1.compress(gammaX, gammaY), uint8(0x00)
        ));
    }

    function _mulAdd(uint256 s1, uint256 p1x, uint256 p1y, uint256 s2, uint256 p2x, uint256 p2y)
        internal view returns (uint256, uint256)
    {
        (uint256 r1x, uint256 r1y) = Secp256k1.ecMul(s1, p1x, p1y);
        (uint256 r2x, uint256 r2y) = Secp256k1.ecMul(s2, p2x, p2y);
        return Secp256k1.ecAdd(r1x, r1y, r2x, r2y);
    }
}
