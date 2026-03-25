// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

library Secp256k1 {
    uint256 internal constant P =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
    uint256 internal constant N =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
    uint256 internal constant GX =
        0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
    uint256 internal constant GY =
        0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;
    uint256 internal constant B = 7;
    uint256 internal constant PP1D4 =
        0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffffbfffff0c;

    function modExp(uint256 b, uint256 e, uint256 m) internal view returns (uint256 result) {
        assembly {
            let p := mload(0x40)
            mstore(p, 0x20)
            mstore(add(p, 0x20), 0x20)
            mstore(add(p, 0x40), 0x20)
            mstore(add(p, 0x60), b)
            mstore(add(p, 0x80), e)
            mstore(add(p, 0xa0), m)
            if iszero(staticcall(gas(), 0x05, p, 0xc0, p, 0x20)) { revert(0, 0) }
            result := mload(p)
        }
    }

    function invMod(uint256 a) internal view returns (uint256) {
        return modExp(a, P - 2, P);
    }

    function decompress(bytes memory data) internal view returns (uint256 x, uint256 y, bool ok) {
        if (data.length != 33) return (0, 0, false);
        uint8 prefix;
        assembly {
            prefix := byte(0, mload(add(data, 0x20)))
            x := mload(add(data, 0x21))
        }
        if (prefix != 0x02 && prefix != 0x03) return (0, 0, false);
        if (x >= P) return (0, 0, false);

        uint256 rhs = addmod(mulmod(mulmod(x, x, P), x, P), B, P);
        y = modExp(rhs, PP1D4, P);
        if (mulmod(y, y, P) != rhs) return (0, 0, false);

        if ((y & 1 == 1) != (prefix == 0x03)) y = P - y;
        ok = true;
    }

    function compress(uint256 x, uint256 y) internal pure returns (bytes memory out) {
        out = new bytes(33);
        uint8 pfx = (y & 1 == 0) ? 0x02 : 0x03;
        assembly {
            mstore8(add(out, 0x20), pfx)
            mstore(add(out, 0x21), x)
        }
    }

    function isOnCurve(uint256 x, uint256 y) internal pure returns (bool) {
        if (x >= P || y >= P) return false;
        return mulmod(y, y, P) == addmod(mulmod(mulmod(x, x, P), x, P), B, P);
    }

    function jacDouble(uint256 x1, uint256 y1, uint256 z1)
        internal pure returns (uint256 x3, uint256 y3, uint256 z3)
    {
        if (z1 == 0 || y1 == 0) return (0, 0, 0);
        uint256 p = P;
        uint256 m = mulmod(3, mulmod(x1, x1, p), p);
        uint256 y1sq = mulmod(y1, y1, p);
        uint256 s = mulmod(4, mulmod(x1, y1sq, p), p);
        x3 = addmod(mulmod(m, m, p), p - mulmod(2, s, p), p);
        y3 = addmod(
            mulmod(m, addmod(s, p - x3, p), p),
            p - mulmod(8, mulmod(y1sq, y1sq, p), p),
            p
        );
        z3 = mulmod(2, mulmod(y1, z1, p), p);
    }

    function jacAddMixed(uint256 x1, uint256 y1, uint256 z1, uint256 x2, uint256 y2)
        internal pure returns (uint256 x3, uint256 y3, uint256 z3)
    {
        if (z1 == 0) return (x2, y2, 1);
        uint256 p = P;
        uint256 z1sq = mulmod(z1, z1, p);
        uint256 u2 = mulmod(x2, z1sq, p);
        uint256 s2 = mulmod(y2, mulmod(z1sq, z1, p), p);
        uint256 h = addmod(u2, p - x1, p);
        uint256 r = addmod(s2, p - y1, p);
        if (h == 0) {
            if (r == 0) return jacDouble(x1, y1, z1);
            return (0, 0, 0);
        }
        uint256 h2 = mulmod(h, h, p);
        uint256 h3 = mulmod(h2, h, p);
        uint256 u1h2 = mulmod(x1, h2, p);
        x3 = addmod(addmod(mulmod(r, r, p), p - h3, p), p - mulmod(2, u1h2, p), p);
        y3 = addmod(mulmod(r, addmod(u1h2, p - x3, p), p), p - mulmod(y1, h3, p), p);
        z3 = mulmod(h, z1, p);
    }

    function jacToAffine(uint256 x, uint256 y, uint256 z)
        internal view returns (uint256 ax, uint256 ay)
    {
        if (z == 0) return (0, 0);
        uint256 zi = invMod(z);
        uint256 zi2 = mulmod(zi, zi, P);
        ax = mulmod(x, zi2, P);
        ay = mulmod(y, mulmod(zi2, zi, P), P);
    }

    function ecMul(uint256 k, uint256 px, uint256 py)
        internal view returns (uint256, uint256)
    {
        if (k == 0 || (px == 0 && py == 0)) return (0, 0);
        if (k == 1) return (px, py);
        uint256 jx; uint256 jy; uint256 jz;
        uint256 bit = 1 << 255;
        while (bit > 0 && (k & bit) == 0) bit >>= 1;
        while (bit > 0) {
            (jx, jy, jz) = jacDouble(jx, jy, jz);
            if (k & bit != 0) (jx, jy, jz) = jacAddMixed(jx, jy, jz, px, py);
            bit >>= 1;
        }
        return jacToAffine(jx, jy, jz);
    }

    function ecAdd(uint256 x1, uint256 y1, uint256 x2, uint256 y2)
        internal view returns (uint256, uint256)
    {
        if (x1 == 0 && y1 == 0) return (x2, y2);
        if (x2 == 0 && y2 == 0) return (x1, y1);
        if (x1 == x2) {
            if (y1 == y2) {
                (uint256 dx, uint256 dy, uint256 dz) = jacDouble(x1, y1, 1);
                return jacToAffine(dx, dy, dz);
            }
            return (0, 0);
        }
        (uint256 ax, uint256 ay, uint256 az) = jacAddMixed(x1, y1, 1, x2, y2);
        return jacToAffine(ax, ay, az);
    }
}
