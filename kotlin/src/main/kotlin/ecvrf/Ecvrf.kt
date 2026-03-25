package ecvrf

import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.ec.CustomNamedCurves
import org.bouncycastle.crypto.signers.HMacDSAKCalculator
import org.bouncycastle.math.ec.ECPoint
import java.math.BigInteger
import java.security.MessageDigest

object Ecvrf {
    private val PARAMS = CustomNamedCurves.getByName("secp256k1")
    private val CURVE = PARAMS.curve
    private val G = PARAMS.g
    private val N = PARAMS.n
    private const val SUITE_BYTE: Byte = 0xFE.toByte()
    private const val PROOF_LEN = 81
    private const val COMPRESSED_LEN = 33
    private const val CHALLENGE_LEN = 16
    private const val SCALAR_LEN = 32
    private val TWO_POW_128: BigInteger = BigInteger.ONE.shiftLeft(128)

    class VerifyResult(val valid: Boolean, val beta: ByteArray?)

    private fun sha256(data: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(data)

    private fun pointToBytes(point: ECPoint): ByteArray =
        point.getEncoded(true)

    private fun bytesToPoint(data: ByteArray): ECPoint =
        CURVE.decodePoint(data)

    private fun bigIntToBytes(value: BigInteger, length: Int): ByteArray {
        val bytes = value.toByteArray()
        return when {
            bytes.size == length -> bytes
            bytes.size > length -> bytes.copyOfRange(bytes.size - length, bytes.size)
            else -> ByteArray(length - bytes.size) + bytes
        }
    }

    fun encodeToCurve(pkPoint: ECPoint, alpha: ByteArray): Pair<ECPoint, Int> {
        val pkBytes = pointToBytes(pkPoint)
        val prefix = byteArrayOf(SUITE_BYTE, 0x01) + pkBytes
        for (ctr in 0..255) {
            val hashInput = prefix + alpha + byteArrayOf(ctr.toByte(), 0x00)
            val candidate = sha256(hashInput)
            try {
                return CURVE.decodePoint(byteArrayOf(0x02) + candidate) to ctr
            } catch (_: Exception) {
                continue
            }
        }
        throw IllegalStateException("encode_to_curve: no valid point found in 256 iterations")
    }

    fun nonceGenerationRFC6979(sk: BigInteger, hPoint: ECPoint): BigInteger {
        val h1 = sha256(pointToBytes(hPoint))
        val calculator = HMacDSAKCalculator(SHA256Digest())
        calculator.init(N, sk, h1)
        return calculator.nextK()
    }

    fun challengeGeneration(
        y: ECPoint, h: ECPoint, gamma: ECPoint, u: ECPoint, v: ECPoint
    ): BigInteger {
        val hashInput = byteArrayOf(SUITE_BYTE, 0x02) +
            pointToBytes(y) + pointToBytes(h) + pointToBytes(gamma) +
            pointToBytes(u) + pointToBytes(v) + byteArrayOf(0x00)
        return BigInteger(1, sha256(hashInput).copyOfRange(0, CHALLENGE_LEN))
    }

    private fun computeBeta(gamma: ECPoint): ByteArray {
        val hashInput = byteArrayOf(SUITE_BYTE, 0x03) + pointToBytes(gamma) + byteArrayOf(0x00)
        return sha256(hashInput)
    }

    fun decodeProof(pi: ByteArray): Triple<ECPoint, BigInteger, BigInteger> {
        require(pi.size == PROOF_LEN) { "proof must be $PROOF_LEN bytes, got ${pi.size}" }
        val gamma = bytesToPoint(pi.copyOfRange(0, COMPRESSED_LEN))
        val c = BigInteger(1, pi.copyOfRange(COMPRESSED_LEN, COMPRESSED_LEN + CHALLENGE_LEN))
        val s = BigInteger(1, pi.copyOfRange(COMPRESSED_LEN + CHALLENGE_LEN, PROOF_LEN))
        return Triple(gamma, c, s)
    }

    fun prove(sk: ByteArray, alpha: ByteArray): ByteArray {
        require(sk.size == SCALAR_LEN) { "secret key must be $SCALAR_LEN bytes, got ${sk.size}" }
        val x = BigInteger(1, sk)
        require(x > BigInteger.ZERO && x < N) { "secret key must be in range (0, n)" }

        val y = G.multiply(x)
        val (h, _) = encodeToCurve(y, alpha)
        val gamma = h.multiply(x)
        val k = nonceGenerationRFC6979(x, h)
        val u = G.multiply(k)
        val v = h.multiply(k)
        val c = challengeGeneration(y, h, gamma, u, v)
        val s = k.add(c.multiply(x)).mod(N)

        return pointToBytes(gamma) + bigIntToBytes(c, CHALLENGE_LEN) + bigIntToBytes(s, SCALAR_LEN)
    }

    fun verify(pk: ByteArray, pi: ByteArray, alpha: ByteArray): VerifyResult {
        try {
            val (gamma, c, s) = decodeProof(pi)
            if (gamma.isInfinity) return VerifyResult(false, null)
            if (s >= N) return VerifyResult(false, null)
            if (c >= TWO_POW_128) return VerifyResult(false, null)

            val y = bytesToPoint(pk)
            val (h, _) = encodeToCurve(y, alpha)

            val u = G.multiply(s).add(y.multiply(N.subtract(c)))
            val v = h.multiply(s).add(gamma.multiply(N.subtract(c)))

            val cPrime = challengeGeneration(y, h, gamma, u, v)
            if (c == cPrime) {
                return VerifyResult(true, computeBeta(gamma))
            }
            return VerifyResult(false, null)
        } catch (_: Exception) {
            return VerifyResult(false, null)
        }
    }

    fun getPublicKey(sk: ByteArray): ByteArray {
        require(sk.size == SCALAR_LEN) { "secret key must be $SCALAR_LEN bytes, got ${sk.size}" }
        val x = BigInteger(1, sk)
        require(x > BigInteger.ZERO && x < N) { "secret key must be in range (0, n)" }
        return pointToBytes(G.multiply(x))
    }

    fun proofToHash(pi: ByteArray): ByteArray {
        val (gamma, _, _) = decodeProof(pi)
        return computeBeta(gamma)
    }
}
