package ecvrf

import java.io.File

fun main(args: Array<String>) {
    if (args.isEmpty()) {
        System.err.println("usage: ecvrf-kotlin prove|verify ...")
        System.exit(1)
    }

    fun readAlpha(args: Array<String>, idx: Int): String {
        if (idx < args.size && args[idx] == "--alpha-file" && idx + 1 < args.size)
            return File(args[idx + 1]).readText().trim()
        if (idx < args.size)
            return args[idx]
        System.err.println("missing alpha argument")
        System.exit(1)
        return ""
    }

    fun hexDecode(hex: String): ByteArray {
        return ByteArray(hex.length / 2) {
            hex.substring(it * 2, it * 2 + 2).toInt(16).toByte()
        }
    }

    fun hexEncode(bytes: ByteArray): String =
        bytes.joinToString("") { "%02x".format(it) }

    when (args[0]) {
        "prove" -> {
            val sk = hexDecode(args[1])
            val alphaHex = readAlpha(args, 2)
            val alpha = hexDecode(alphaHex)
            val pi = Ecvrf.prove(sk, alpha)
            val beta = Ecvrf.proofToHash(pi)
            println("""{"pi":"${hexEncode(pi)}","beta":"${hexEncode(beta)}"}""")
        }
        "verify" -> {
            val pk = hexDecode(args[1])
            val pi = hexDecode(args[2])
            val alphaHex = readAlpha(args, 3)
            val alpha = hexDecode(alphaHex)
            val result = Ecvrf.verify(pk, pi, alpha)
            val b = result.beta
            val betaStr = if (b != null) "\"" + hexEncode(b) + "\"" else "null"
            println("{\"valid\":" + result.valid + ",\"beta\":" + betaStr + "}")
        }
        else -> {
            System.err.println("unknown command: ${args[0]}")
            System.exit(1)
        }
    }
}
