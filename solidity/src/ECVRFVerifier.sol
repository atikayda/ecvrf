// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Secp256k1} from "./Secp256k1.sol";
import {ECVRFBase} from "./ECVRFBase.sol";

contract ECVRFVerifier is ECVRFBase {
    function verify(bytes calldata pk, bytes calldata pi, bytes calldata alpha)
        external view returns (bool valid, bytes32 beta)
    {
        if (pi.length != 81) return (false, bytes32(0));

        (uint256 gammaX, uint256 gammaY, bool gOk) = Secp256k1.decompress(bytes(pi[0:33]));
        if (!gOk || !Secp256k1.isOnCurve(gammaX, gammaY)) return (false, bytes32(0));

        uint128 c = uint128(bytes16(pi[33:49]));
        uint256 s = uint256(bytes32(pi[49:81]));
        if (s >= Secp256k1.N) return (false, bytes32(0));

        (uint256 pkX, uint256 pkY, bool pkOk) = Secp256k1.decompress(bytes(pk));
        if (!pkOk) return (false, bytes32(0));

        (uint256 hX, uint256 hY, bool hOk) = _encodeToCurve(pkX, pkY, alpha);
        if (!hOk) return (false, bytes32(0));

        uint256 nc = Secp256k1.N - uint256(c);
        (uint256 uX, uint256 uY) = _mulAdd(s, Secp256k1.GX, Secp256k1.GY, nc, pkX, pkY);
        (uint256 vX, uint256 vY) = _mulAdd(s, hX, hY, nc, gammaX, gammaY);

        uint128 cPrime = _challengeGeneration(pkX, pkY, hX, hY, gammaX, gammaY, uX, uY, vX, vY);
        if (c != cPrime) return (false, bytes32(0));

        beta = _proofToHash(gammaX, gammaY);
        valid = true;
    }

    function proofToHash(bytes calldata pi) external view returns (bytes32) {
        require(pi.length == 81, "invalid proof length");
        (uint256 gx, uint256 gy, bool ok) = Secp256k1.decompress(bytes(pi[0:33]));
        require(ok, "invalid Gamma");
        return _proofToHash(gx, gy);
    }
}
