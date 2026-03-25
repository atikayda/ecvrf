using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using SHA256 = System.Security.Cryptography.SHA256;

namespace Ecvrf;

public static class EcvrfSecp256k1
{
    private const byte SuiteByte = 0xFE;
    public const int ProofLen = 81;
    public const int BetaLen = 32;
    private const int ChallengeLen = 16;
    private const int ScalarLen = 32;
    private const int CompressedLen = 33;

    private static readonly X9ECParameters CurveParams = ECNamedCurveTable.GetByName("secp256k1");
    private static readonly ECCurve Curve = CurveParams.Curve;
    private static readonly ECPoint G = CurveParams.G;
    private static readonly BigInteger N = CurveParams.N;
    private static readonly BigInteger TwoTo128 = BigInteger.One.ShiftLeft(128);

    private static byte[] PointToString(ECPoint point) =>
        point.Normalize().GetEncoded(compressed: true);

    private static ECPoint StringToPoint(byte[] data) =>
        Curve.DecodePoint(data);

    private static byte[] Sha256Hash(byte[] data)
    {
        using var sha = SHA256.Create();
        return sha.ComputeHash(data);
    }

    private static (ECPoint point, int ctr) EncodeToCurveTai(ECPoint pkPoint, byte[] alpha)
    {
        var pkBytes = PointToString(pkPoint);

        for (int ctr = 0; ctr <= 255; ctr++)
        {
            var hashInput = new byte[2 + CompressedLen + alpha.Length + 2];
            int off = 0;
            hashInput[off++] = SuiteByte;
            hashInput[off++] = 0x01;
            Buffer.BlockCopy(pkBytes, 0, hashInput, off, CompressedLen);
            off += CompressedLen;
            Buffer.BlockCopy(alpha, 0, hashInput, off, alpha.Length);
            off += alpha.Length;
            hashInput[off++] = (byte)ctr;
            hashInput[off] = 0x00;

            var hash = Sha256Hash(hashInput);

            var compressed = new byte[CompressedLen];
            compressed[0] = 0x02;
            Buffer.BlockCopy(hash, 0, compressed, 1, 32);

            try
            {
                var point = Curve.DecodePoint(compressed);
                if (point.IsInfinity)
                    continue;
                return (point.Normalize(), ctr);
            }
            catch
            {
                continue;
            }
        }

        throw new InvalidOperationException("encode_to_curve: no valid point found in 256 iterations");
    }

    private static BigInteger NonceGenerationRfc6979(BigInteger sk, ECPoint hPoint)
    {
        var hCompressed = PointToString(hPoint);
        var digest = Sha256Hash(hCompressed);

        var kCalc = new HMacDsaKCalculator(new Sha256Digest());
        kCalc.Init(N, sk, digest);
        return kCalc.NextK();
    }

    private static BigInteger ChallengeGeneration(ECPoint y, ECPoint h, ECPoint gamma, ECPoint u, ECPoint v)
    {
        var hashInput = new byte[2 + 5 * CompressedLen + 1];
        int off = 0;
        hashInput[off++] = SuiteByte;
        hashInput[off++] = 0x02;
        CopyPoint(y, hashInput, ref off);
        CopyPoint(h, hashInput, ref off);
        CopyPoint(gamma, hashInput, ref off);
        CopyPoint(u, hashInput, ref off);
        CopyPoint(v, hashInput, ref off);
        hashInput[off] = 0x00;

        var cHash = Sha256Hash(hashInput);

        var cBytes = new byte[ChallengeLen];
        Buffer.BlockCopy(cHash, 0, cBytes, 0, ChallengeLen);
        return new BigInteger(1, cBytes);
    }

    private static void CopyPoint(ECPoint point, byte[] dest, ref int offset)
    {
        var encoded = PointToString(point);
        Buffer.BlockCopy(encoded, 0, dest, offset, CompressedLen);
        offset += CompressedLen;
    }

    private static byte[] ProofToHashInner(ECPoint gamma)
    {
        var gammaBytes = PointToString(gamma);

        var hashInput = new byte[2 + CompressedLen + 1];
        hashInput[0] = SuiteByte;
        hashInput[1] = 0x03;
        Buffer.BlockCopy(gammaBytes, 0, hashInput, 2, CompressedLen);
        hashInput[2 + CompressedLen] = 0x00;

        return Sha256Hash(hashInput);
    }

    private static (ECPoint gamma, BigInteger c, BigInteger s) DecodeProof(byte[] pi)
    {
        if (pi.Length != ProofLen)
            throw new ArgumentException($"proof must be {ProofLen} bytes, got {pi.Length}");

        var gammaBytes = new byte[CompressedLen];
        Buffer.BlockCopy(pi, 0, gammaBytes, 0, CompressedLen);
        var gamma = StringToPoint(gammaBytes);
        if (gamma.IsInfinity)
            throw new ArgumentException("gamma is the point at infinity");

        var cBytes = new byte[ChallengeLen];
        Buffer.BlockCopy(pi, CompressedLen, cBytes, 0, ChallengeLen);
        var c = new BigInteger(1, cBytes);

        var sBytes = new byte[ScalarLen];
        Buffer.BlockCopy(pi, CompressedLen + ChallengeLen, sBytes, 0, ScalarLen);
        var s = new BigInteger(1, sBytes);

        return (gamma, c, s);
    }

    private static byte[] BigIntToFixedBytes(BigInteger val, int length)
    {
        var raw = val.ToByteArrayUnsigned();
        if (raw.Length == length)
            return raw;
        var result = new byte[length];
        var copyLen = Math.Min(raw.Length, length);
        Buffer.BlockCopy(raw, 0, result, length - copyLen, copyLen);
        return result;
    }

    public static byte[] Prove(byte[] sk, byte[] alpha)
    {
        if (sk.Length != ScalarLen)
            throw new ArgumentException($"sk must be {ScalarLen} bytes, got {sk.Length}");

        var x = new BigInteger(1, sk);
        if (x.SignValue <= 0 || x.CompareTo(N) >= 0)
            throw new ArgumentException("sk must be in range (0, n)");

        var y = G.Multiply(x).Normalize();
        var (h, _) = EncodeToCurveTai(y, alpha);
        var gamma = h.Multiply(x).Normalize();
        var k = NonceGenerationRfc6979(x, h);
        var u = G.Multiply(k).Normalize();
        var v = h.Multiply(k).Normalize();
        var c = ChallengeGeneration(y, h, gamma, u, v);
        var s = k.Add(c.Multiply(x)).Mod(N);

        var pi = new byte[ProofLen];
        Buffer.BlockCopy(PointToString(gamma), 0, pi, 0, CompressedLen);
        Buffer.BlockCopy(BigIntToFixedBytes(c, ChallengeLen), 0, pi, CompressedLen, ChallengeLen);
        Buffer.BlockCopy(BigIntToFixedBytes(s, ScalarLen), 0, pi, CompressedLen + ChallengeLen, ScalarLen);

        return pi;
    }

    public static (bool valid, byte[]? beta) Verify(byte[] pk, byte[] pi, byte[] alpha)
    {
        ECPoint gamma;
        BigInteger c, s;
        try
        {
            (gamma, c, s) = DecodeProof(pi);
        }
        catch
        {
            return (false, null);
        }

        if (s.CompareTo(N) >= 0)
            return (false, null);
        if (c.CompareTo(TwoTo128) >= 0)
            return (false, null);

        ECPoint y;
        try
        {
            y = StringToPoint(pk);
        }
        catch
        {
            return (false, null);
        }

        var (h, _) = EncodeToCurveTai(y, alpha);

        // U = s*G - c*Y  =  s*G + (n-c)*Y
        var negC = N.Subtract(c);
        var u = G.Multiply(s).Add(y.Multiply(negC)).Normalize();

        // V = s*H - c*Gamma  =  s*H + (n-c)*Gamma
        var v = h.Multiply(s).Add(gamma.Multiply(negC)).Normalize();

        var cPrime = ChallengeGeneration(y, h, gamma, u, v);

        if (c.Equals(cPrime))
        {
            var beta = ProofToHashInner(gamma);
            return (true, beta);
        }

        return (false, null);
    }

    public static byte[] DerivePublicKey(byte[] sk)
    {
        if (sk.Length != ScalarLen)
            throw new ArgumentException($"sk must be {ScalarLen} bytes, got {sk.Length}");

        var x = new BigInteger(1, sk);
        if (x.SignValue <= 0 || x.CompareTo(N) >= 0)
            throw new ArgumentException("sk must be in range (0, n)");

        return PointToString(G.Multiply(x).Normalize());
    }

    public static byte[] ProofToHash(byte[] pi)
    {
        var (gamma, _, _) = DecodeProof(pi);
        return ProofToHashInner(gamma);
    }
}
