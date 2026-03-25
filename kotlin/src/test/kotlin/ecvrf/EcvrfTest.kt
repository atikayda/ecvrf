package ecvrf

import com.google.gson.Gson
import com.google.gson.JsonObject
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.DynamicTest
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestFactory
import java.io.File

class EcvrfTest {
    private val vectors: JsonObject by lazy {
        val file = File("../vectors/vectors.json")
        Gson().fromJson(file.readText(), JsonObject::class.java)
    }

    private fun hexToBytes(hex: String): ByteArray {
        if (hex.isEmpty()) return ByteArray(0)
        return hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    }

    private fun bytesToHex(bytes: ByteArray): String =
        bytes.joinToString("") { "%02x".format(it) }

    @TestFactory
    fun `prove produces byte-identical proofs`(): List<DynamicTest> {
        val vecs = vectors.getAsJsonArray("vectors")
        return vecs.map { elem ->
            val vec = elem.asJsonObject
            val label = vec.get("label").asString
            DynamicTest.dynamicTest("prove: $label") {
                val sk = hexToBytes(vec.get("sk").asString)
                val alpha = hexToBytes(vec.get("alpha").asString)
                val expectedPi = vec.get("pi").asString

                val pi = Ecvrf.prove(sk, alpha)
                assertEquals(expectedPi, bytesToHex(pi), "pi mismatch for $label")
            }
        }
    }

    @TestFactory
    fun `verify accepts valid proofs`(): List<DynamicTest> {
        val vecs = vectors.getAsJsonArray("vectors")
        return vecs.map { elem ->
            val vec = elem.asJsonObject
            val label = vec.get("label").asString
            DynamicTest.dynamicTest("verify: $label") {
                val pk = hexToBytes(vec.get("pk").asString)
                val alpha = hexToBytes(vec.get("alpha").asString)
                val pi = hexToBytes(vec.get("pi").asString)
                val expectedBeta = vec.get("beta").asString

                val result = Ecvrf.verify(pk, pi, alpha)
                assertTrue(result.valid, "verify should return VALID for $label")
                assertNotNull(result.beta)
                assertEquals(expectedBeta, bytesToHex(result.beta!!), "beta mismatch for $label")
            }
        }
    }

    @TestFactory
    fun `proofToHash produces correct beta`(): List<DynamicTest> {
        val vecs = vectors.getAsJsonArray("vectors")
        return vecs.map { elem ->
            val vec = elem.asJsonObject
            val label = vec.get("label").asString
            DynamicTest.dynamicTest("proofToHash: $label") {
                val pi = hexToBytes(vec.get("pi").asString)
                val expectedBeta = vec.get("beta").asString

                val beta = Ecvrf.proofToHash(pi)
                assertEquals(expectedBeta, bytesToHex(beta), "beta mismatch for $label")
            }
        }
    }

    @TestFactory
    fun `verify rejects negative vectors`(): List<DynamicTest> {
        val negVecs = vectors.getAsJsonArray("negative_vectors")
        return negVecs.map { elem ->
            val vec = elem.asJsonObject
            val description = vec.get("description").asString
            DynamicTest.dynamicTest("negative: $description") {
                val pk = hexToBytes(vec.get("pk").asString)
                val alpha = hexToBytes(vec.get("alpha").asString)
                val pi = hexToBytes(vec.get("pi").asString)

                val result = Ecvrf.verify(pk, pi, alpha)
                assertFalse(result.valid, "verify should return INVALID for: $description")
            }
        }
    }

    @Test
    fun `prove is deterministic`() {
        val vecs = vectors.getAsJsonArray("vectors")
        val vec = vecs[0].asJsonObject
        val sk = hexToBytes(vec.get("sk").asString)
        val alpha = hexToBytes(vec.get("alpha").asString)

        val pi1 = Ecvrf.prove(sk, alpha)
        val pi2 = Ecvrf.prove(sk, alpha)
        assertArrayEquals(pi1, pi2, "VRF prove must be deterministic")
    }

    @Test
    fun `getPublicKey derives correct keys`() {
        val vecs = vectors.getAsJsonArray("vectors")
        val seenKeys = mutableSetOf<String>()
        for (elem in vecs) {
            val vec = elem.asJsonObject
            val skHex = vec.get("sk").asString
            if (skHex in seenKeys) continue
            seenKeys.add(skHex)

            val sk = hexToBytes(skHex)
            val expectedPk = vec.get("pk").asString
            val pk = Ecvrf.getPublicKey(sk)
            assertEquals(expectedPk, bytesToHex(pk), "public key derivation failed for sk=$skHex")
        }
    }
}
