/// RFC 9381 ECVRF-SECP256K1-SHA256-TAI
///
/// Verifiable Random Function using secp256k1, SHA-256, and try-and-increment
/// hash-to-curve. Implements the final RFC 9381 standard — not draft-05/06.
///
/// Suite byte: 0xFE (community convention for secp256k1).
import Foundation
import CryptoKit
import libsecp256k1
import BigInt

// MARK: - Constants

private let suiteByte: UInt8 = 0xFE
public let proofLength = 81
public let betaLength = 32
private let challengeLength = 16
private let scalarLength = 32
private let compressedPointLength = 33

private let curveOrder = BigUInt("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", radix: 16)!

// MARK: - Errors

public enum ECVRFError: Error, CustomStringConvertible {
    case invalidSecretKey(String)
    case invalidPublicKey
    case invalidProofLength(Int)
    case invalidPoint
    case encodeToCurveFailed
    case pointArithmeticFailed
    case scalarOverflow

    public var description: String {
        switch self {
        case .invalidSecretKey(let reason): return "ecvrf: invalid secret key: \(reason)"
        case .invalidPublicKey: return "ecvrf: invalid public key"
        case .invalidProofLength(let n): return "ecvrf: proof must be 81 bytes, got \(n)"
        case .invalidPoint: return "ecvrf: invalid curve point"
        case .encodeToCurveFailed: return "ecvrf: encode_to_curve failed after 256 iterations"
        case .pointArithmeticFailed: return "ecvrf: point arithmetic failed"
        case .scalarOverflow: return "ecvrf: scalar >= group order"
        }
    }
}

// MARK: - secp256k1 Context (created once, thread-safe for read operations)

private let ctx: OpaquePointer = {
    // SECP256K1_CONTEXT_NONE = SECP256K1_FLAGS_TYPE_CONTEXT = (1 << 0) = 1
    guard let c = secp256k1_context_create(1) else {
        fatalError("Failed to create secp256k1 context")
    }
    return c
}()

// MARK: - Low-level Point Operations

private func parsePoint(_ bytes: [UInt8]) throws -> secp256k1_pubkey {
    var pk = secp256k1_pubkey()
    guard secp256k1_ec_pubkey_parse(ctx, &pk, bytes, bytes.count) == 1 else {
        throw ECVRFError.invalidPoint
    }
    return pk
}

private func compressPoint(_ pk: secp256k1_pubkey) -> [UInt8] {
    var output = [UInt8](repeating: 0, count: compressedPointLength)
    var len = compressedPointLength
    var key = pk
    // SECP256K1_EC_COMPRESSED = (1<<1)|(1<<8) = 258
    secp256k1_ec_pubkey_serialize(ctx, &output, &len, &key, 258)
    return output
}

private func createPubkey(fromSecret sk: [UInt8]) throws -> secp256k1_pubkey {
    var pk = secp256k1_pubkey()
    guard secp256k1_ec_pubkey_create(ctx, &pk, sk) == 1 else {
        throw ECVRFError.invalidSecretKey("secp256k1_ec_pubkey_create failed")
    }
    return pk
}

/// Compute scalar * point using secp256k1_ec_pubkey_tweak_mul (in-place).
private func scalarMul(_ point: secp256k1_pubkey, _ scalar: [UInt8]) throws -> secp256k1_pubkey {
    var result = point
    guard secp256k1_ec_pubkey_tweak_mul(ctx, &result, scalar) == 1 else {
        throw ECVRFError.pointArithmeticFailed
    }
    return result
}

/// Compute scalar * G (generator) using secp256k1_ec_pubkey_create.
private func baseMul(_ scalar: [UInt8]) throws -> secp256k1_pubkey {
    return try createPubkey(fromSecret: scalar)
}

/// Compute p1 + p2 using secp256k1_ec_pubkey_combine.
private func pointAdd(_ a: secp256k1_pubkey, _ b: secp256k1_pubkey) throws -> secp256k1_pubkey {
    var out = secp256k1_pubkey()
    var p1 = a
    var p2 = b

    let ok: Int32 = withUnsafePointer(to: &p1) { ptr1 in
        withUnsafePointer(to: &p2) { ptr2 in
            let ptrs: [UnsafePointer<secp256k1_pubkey>?] = [ptr1, ptr2]
            return ptrs.withUnsafeBufferPointer { buf in
                secp256k1_ec_pubkey_combine(ctx, &out, buf.baseAddress!, 2)
            }
        }
    }

    guard ok == 1 else { throw ECVRFError.pointArithmeticFailed }
    return out
}

// MARK: - Scalar Helpers

private func toBytes(_ value: BigUInt, length: Int) -> [UInt8] {
    let raw = value.serialize()
    var bytes = [UInt8](raw)
    while bytes.count < length { bytes.insert(0, at: 0) }
    if bytes.count > length { bytes = Array(bytes.suffix(length)) }
    return bytes
}

private func fromBytes(_ bytes: [UInt8]) -> BigUInt {
    return BigUInt(Data(bytes))
}

// MARK: - SHA-256

private func sha256(_ input: [UInt8]) -> [UInt8] {
    return Array(SHA256.hash(data: input))
}

// MARK: - HMAC-SHA256

private func hmacSHA256(key: [UInt8], data: [UInt8]) -> [UInt8] {
    let k = SymmetricKey(data: key)
    var h = HMAC<SHA256>(key: k)
    h.update(data: data)
    return Array(h.finalize())
}

// MARK: - RFC 6979 Deterministic Nonce (Section 3.2)

private func rfc6979Nonce(secretKey: [UInt8], messageHash: [UInt8]) -> BigUInt {
    let x = fromBytes(secretKey)
    let h1Int = fromBytes(messageHash)

    let xOctets = toBytes(x, length: 32)
    let h1Octets = toBytes(h1Int % curveOrder, length: 32) // bits2octets

    var v = [UInt8](repeating: 0x01, count: 32)
    var k = [UInt8](repeating: 0x00, count: 32)

    // Step d
    k = hmacSHA256(key: k, data: v + [0x00] + xOctets + h1Octets)
    // Step e
    v = hmacSHA256(key: k, data: v)
    // Step f
    k = hmacSHA256(key: k, data: v + [0x01] + xOctets + h1Octets)
    // Step g
    v = hmacSHA256(key: k, data: v)

    // Step h — generate candidates until valid
    while true {
        v = hmacSHA256(key: k, data: v)
        let candidate = fromBytes(v)
        if candidate >= 1 && candidate < curveOrder {
            return candidate
        }
        k = hmacSHA256(key: k, data: v + [0x00])
        v = hmacSHA256(key: k, data: v)
    }
}

/// RFC 9381 Section 5.4.2.1 — nonce from SK and H point.
private func nonceGeneration(secretKey: [UInt8], hPoint: secp256k1_pubkey) -> BigUInt {
    let hBytes = compressPoint(hPoint)
    let h1 = sha256(hBytes)
    return rfc6979Nonce(secretKey: secretKey, messageHash: h1)
}

// MARK: - RFC 9381 Section 5.4.1.1 — encode_to_curve (try_and_increment)

private func encodeToCurve(
    pkPoint: secp256k1_pubkey, alpha: [UInt8]
) throws -> (point: secp256k1_pubkey, ctr: Int) {
    let pkBytes = compressPoint(pkPoint)

    let prefix: [UInt8] = [suiteByte, 0x01] + pkBytes

    for ctr in 0..<256 {
        let hashInput = prefix + alpha + [UInt8(ctr), 0x00]
        let candidate = sha256(hashInput)

        var compressed = [UInt8](repeating: 0, count: compressedPointLength)
        compressed[0] = 0x02 // even y-coordinate
        for i in 0..<32 { compressed[i + 1] = candidate[i] }

        var pk = secp256k1_pubkey()
        if secp256k1_ec_pubkey_parse(ctx, &pk, compressed, compressedPointLength) == 1 {
            return (pk, ctr)
        }
    }

    throw ECVRFError.encodeToCurveFailed
}

// MARK: - RFC 9381 Section 5.4.3 — challenge_generation (5-point)

private func challengeGeneration(
    y: secp256k1_pubkey,
    h: secp256k1_pubkey,
    gamma: secp256k1_pubkey,
    u: secp256k1_pubkey,
    v: secp256k1_pubkey
) -> BigUInt {
    var input: [UInt8] = [suiteByte, 0x02]
    input += compressPoint(y)
    input += compressPoint(h)
    input += compressPoint(gamma)
    input += compressPoint(u)
    input += compressPoint(v)
    input += [0x00]

    let cHash = sha256(input)
    return fromBytes(Array(cHash.prefix(challengeLength)))
}

// MARK: - RFC 9381 Section 5.2 — proof_to_hash

private func proofToHashCore(gamma: secp256k1_pubkey) -> [UInt8] {
    // Cofactor is 1 for secp256k1, so cofactor*Gamma = Gamma
    let input: [UInt8] = [suiteByte, 0x03] + compressPoint(gamma) + [0x00]
    return sha256(input)
}

// MARK: - Decode / Encode Proof

private func decodeProof(_ pi: [UInt8]) throws -> (gamma: secp256k1_pubkey, c: BigUInt, s: BigUInt) {
    guard pi.count == proofLength else {
        throw ECVRFError.invalidProofLength(pi.count)
    }

    let gamma = try parsePoint(Array(pi[0..<compressedPointLength]))

    let cBytes = Array(pi[compressedPointLength..<(compressedPointLength + challengeLength)])
    let c = fromBytes(cBytes)

    let sBytes = Array(pi[(compressedPointLength + challengeLength)..<proofLength])
    let s = fromBytes(sBytes)

    return (gamma, c, s)
}

private func encodeProof(gamma: secp256k1_pubkey, c: BigUInt, s: BigUInt) -> [UInt8] {
    return compressPoint(gamma) + toBytes(c, length: challengeLength) + toBytes(s, length: scalarLength)
}

// MARK: - Public API

/// RFC 9381 Section 5.1 — generate a VRF proof.
///
/// - Parameters:
///   - sk: 32-byte secret key (big-endian scalar)
///   - alpha: arbitrary-length alpha string
/// - Returns: 81-byte proof: Gamma(33) || c(16) || s(32)
public func ecvrfProve(sk: [UInt8], alpha: [UInt8]) throws -> [UInt8] {
    guard sk.count == scalarLength else {
        throw ECVRFError.invalidSecretKey("must be 32 bytes, got \(sk.count)")
    }
    let x = fromBytes(sk)
    guard x > 0 && x < curveOrder else {
        throw ECVRFError.invalidSecretKey("out of range (0, n)")
    }

    let y = try createPubkey(fromSecret: sk)
    let (h, _) = try encodeToCurve(pkPoint: y, alpha: alpha)
    let gamma = try scalarMul(h, sk)

    let k = nonceGeneration(secretKey: sk, hPoint: h)
    let kBytes = toBytes(k, length: scalarLength)

    let u = try baseMul(kBytes)
    let v = try scalarMul(h, kBytes)

    let c = challengeGeneration(y: y, h: h, gamma: gamma, u: u, v: v)
    let s = (k + c * x) % curveOrder

    return encodeProof(gamma: gamma, c: c, s: s)
}

/// RFC 9381 Section 5.3 — verify a VRF proof.
///
/// - Parameters:
///   - pk: 33-byte compressed public key
///   - pi: 81-byte proof
///   - alpha: arbitrary-length alpha string
/// - Returns: (valid, beta) where beta is the 32-byte VRF output if valid
public func ecvrfVerify(pk: [UInt8], pi: [UInt8], alpha: [UInt8]) -> (valid: Bool, beta: [UInt8]?) {
    do {
        let (gamma, c, s) = try decodeProof(pi)

        guard s < curveOrder else { return (false, nil) }
        guard c < (BigUInt(1) << 128) else { return (false, nil) }

        let y = try parsePoint(pk)
        let (h, _) = try encodeToCurve(pkPoint: y, alpha: alpha)

        let sBytes = toBytes(s, length: scalarLength)
        let negC = curveOrder - c
        let negCBytes = toBytes(negC, length: scalarLength)

        // U = s*G - c*Y = s*G + (n-c)*Y
        let sG = try baseMul(sBytes)
        let negCY = try scalarMul(y, negCBytes)
        let u = try pointAdd(sG, negCY)

        // V = s*H - c*Gamma = s*H + (n-c)*Gamma
        let sH = try scalarMul(h, sBytes)
        let negCGamma = try scalarMul(gamma, negCBytes)
        let v = try pointAdd(sH, negCGamma)

        let cPrime = challengeGeneration(y: y, h: h, gamma: gamma, u: u, v: v)

        if c == cPrime {
            return (true, proofToHashCore(gamma: gamma))
        }
        return (false, nil)
    } catch {
        return (false, nil)
    }
}

/// Extract VRF output (beta, 32 bytes) from a validated proof.
public func ecvrfProofToHash(_ pi: [UInt8]) throws -> [UInt8] {
    let (gamma, _, _) = try decodeProof(pi)
    return proofToHashCore(gamma: gamma)
}

/// Derive compressed public key (33 bytes) from a secret key.
public func ecvrfDerivePublicKey(_ sk: [UInt8]) throws -> [UInt8] {
    guard sk.count == scalarLength else {
        throw ECVRFError.invalidSecretKey("must be 32 bytes, got \(sk.count)")
    }
    let x = fromBytes(sk)
    guard x > 0 && x < curveOrder else {
        throw ECVRFError.invalidSecretKey("out of range (0, n)")
    }
    return compressPoint(try createPubkey(fromSecret: sk))
}
