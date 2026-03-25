import Foundation
import ECVRF

struct VectorsFile: Decodable {
    let suite: String
    let spec: String
    let vectors: [PositiveVector]
    let negative_vectors: [NegativeVector]
}

struct PositiveVector: Decodable {
    let label: String
    let sk: String
    let pk: String
    let alpha: String
    let alpha_string: String?
    let h: String
    let h_ctr: Int
    let k: String
    let gamma: String
    let u: String
    let v: String
    let c: String
    let s: String
    let pi: String
    let beta: String
}

struct NegativeVector: Decodable {
    let description: String
    let pk: String
    let alpha: String
    let pi: String
    let expected_verify: Bool
}

func hexDecode(_ hex: String) -> [UInt8] {
    var bytes = [UInt8]()
    bytes.reserveCapacity(hex.count / 2)
    var idx = hex.startIndex
    while idx < hex.endIndex {
        let next = hex.index(idx, offsetBy: 2)
        bytes.append(UInt8(hex[idx..<next], radix: 16)!)
        idx = next
    }
    return bytes
}

func hexEncode(_ bytes: [UInt8]) -> String {
    bytes.map { String(format: "%02x", $0) }.joined()
}

var passed = 0
var failed = 0

func assert(_ condition: Bool, _ message: String) {
    if condition {
        passed += 1
    } else {
        failed += 1
        print("  FAIL: \(message)")
    }
}

// Load vectors
let args = CommandLine.arguments
let vectorsPath: String
if args.count > 1 {
    vectorsPath = args[1]
} else {
    // Default: relative to executable's assumed location in the repo
    var url = URL(fileURLWithPath: #filePath)
    for _ in 0..<4 { url.deleteLastPathComponent() }
    url.appendPathComponent("vectors")
    url.appendPathComponent("vectors.json")
    vectorsPath = url.path
}

guard FileManager.default.fileExists(atPath: vectorsPath) else {
    print("ERROR: vectors.json not found at \(vectorsPath)")
    print("Usage: ecvrf-test [path/to/vectors.json]")
    exit(1)
}

let data = try Data(contentsOf: URL(fileURLWithPath: vectorsPath))
let vectors = try JSONDecoder().decode(VectorsFile.self, from: data)

print("ECVRF-SECP256K1-SHA256-TAI — Swift Test Runner")
print("================================================")
print("Loaded \(vectors.vectors.count) positive + \(vectors.negative_vectors.count) negative vectors\n")

// --- Test: DerivePublicKey ---
print("DerivePublicKey...")
for vec in vectors.vectors {
    let sk = hexDecode(vec.sk)
    do {
        let pk = try ecvrfDerivePublicKey(sk)
        assert(hexEncode(pk) == vec.pk.lowercased(), "DerivePublicKey [\(vec.label)]")
    } catch {
        assert(false, "DerivePublicKey threw [\(vec.label)]: \(error)")
    }
}
print("  \(passed) passed")
let pkPassed = passed
passed = 0

// --- Test: Prove (byte-identical) ---
print("\nProve (byte-identical pi)...")
for vec in vectors.vectors {
    let sk = hexDecode(vec.sk)
    let alpha = hexDecode(vec.alpha)
    do {
        let pi = try ecvrfProve(sk: sk, alpha: alpha)
        let piHex = hexEncode(pi)
        let expected = vec.pi.lowercased()
        assert(piHex == expected, "Prove [\(vec.label)]")
        if piHex != expected {
            print("    expected: \(expected)")
            print("    got:      \(piHex)")
        }
    } catch {
        assert(false, "Prove threw [\(vec.label)]: \(error)")
    }
}
let provePassed = passed
let proveFailed = failed
print("  \(provePassed) passed, \(proveFailed) failed")
passed = 0
failed = 0

// --- Test: Verify (positive) ---
print("\nVerify (positive vectors)...")
for vec in vectors.vectors {
    let pk = hexDecode(vec.pk)
    let alpha = hexDecode(vec.alpha)
    let pi = hexDecode(vec.pi)
    let (valid, beta) = ecvrfVerify(pk: pk, pi: pi, alpha: alpha)
    assert(valid, "Verify [\(vec.label)]")
    if let beta = beta {
        assert(hexEncode(beta) == vec.beta.lowercased(), "Verify beta [\(vec.label)]")
    } else {
        assert(false, "Verify returned nil beta [\(vec.label)]")
    }
}
let verifyPosPassed = passed
let verifyPosFailed = failed
print("  \(verifyPosPassed) passed, \(verifyPosFailed) failed")
passed = 0
failed = 0

// --- Test: Verify (negative) ---
print("\nVerify (negative vectors)...")
for vec in vectors.negative_vectors {
    let pk = hexDecode(vec.pk)
    let alpha = hexDecode(vec.alpha)
    let pi = hexDecode(vec.pi)
    let (valid, _) = ecvrfVerify(pk: pk, pi: pi, alpha: alpha)
    assert(!valid, "Negative [\(vec.description)]")
}
let verifyNegPassed = passed
let verifyNegFailed = failed
print("  \(verifyNegPassed) passed, \(verifyNegFailed) failed")
passed = 0
failed = 0

// --- Test: ProofToHash ---
print("\nProofToHash...")
for vec in vectors.vectors {
    let pi = hexDecode(vec.pi)
    do {
        let beta = try ecvrfProofToHash(pi)
        assert(hexEncode(beta) == vec.beta.lowercased(), "ProofToHash [\(vec.label)]")
    } catch {
        assert(false, "ProofToHash threw [\(vec.label)]: \(error)")
    }
}
let pthPassed = passed
let pthFailed = failed
print("  \(pthPassed) passed, \(pthFailed) failed")
passed = 0
failed = 0

// --- Test: Determinism ---
print("\nDeterminism...")
do {
    let vec = vectors.vectors[0]
    let sk = hexDecode(vec.sk)
    let alpha = hexDecode(vec.alpha)
    let pi1 = try ecvrfProve(sk: sk, alpha: alpha)
    let pi2 = try ecvrfProve(sk: sk, alpha: alpha)
    assert(pi1 == pi2, "Determinism")
} catch {
    assert(false, "Determinism threw: \(error)")
}
let detPassed = passed
let detFailed = failed
print("  \(detPassed) passed, \(detFailed) failed")

// --- Summary ---
let totalPassed = pkPassed + provePassed + verifyPosPassed + verifyNegPassed + pthPassed + detPassed
let totalFailed = proveFailed + verifyPosFailed + verifyNegFailed + pthFailed + detFailed

print("\n================================================")
print("Total: \(totalPassed) passed, \(totalFailed) failed")

if totalFailed > 0 {
    exit(1)
} else {
    print("\nAll tests passed!")
}
