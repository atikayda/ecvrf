import Foundation
import ECVRF

func hexDecode(_ hex: String) -> [UInt8] {
    var bytes = [UInt8]()
    let chars = Array(hex)
    for i in stride(from: 0, to: chars.count - 1, by: 2) {
        if let b = UInt8(String(chars[i...i+1]), radix: 16) {
            bytes.append(b)
        }
    }
    return bytes
}

func hexEncode(_ bytes: [UInt8]) -> String {
    bytes.map { String(format: "%02x", $0) }.joined()
}

func readAlpha(_ args: [String], _ idx: Int) -> String {
    if idx < args.count && args[idx] == "--alpha-file" && idx + 1 < args.count {
        let contents = try! String(contentsOfFile: args[idx + 1], encoding: .utf8)
        return contents.trimmingCharacters(in: .whitespacesAndNewlines)
    }
    if idx < args.count { return args[idx] }
    fputs("missing alpha argument\n", stderr)
    exit(1)
}

let args = Array(CommandLine.arguments.dropFirst())
guard let cmd = args.first else {
    fputs("usage: ecvrf-swift prove|verify ...\n", stderr)
    exit(1)
}

switch cmd {
case "prove":
    let sk = hexDecode(args[1])
    let alphaHex = readAlpha(args, 2)
    let alpha = hexDecode(alphaHex)
    do {
        let pi = try ecvrfProve(sk: sk, alpha: alpha)
        let beta = try ecvrfProofToHash(pi)
        print("{\"pi\":\"\(hexEncode(pi))\",\"beta\":\"\(hexEncode(beta))\"}")
    } catch {
        fputs("prove failed: \(error)\n", stderr)
        exit(1)
    }
case "verify":
    let pk = hexDecode(args[1])
    let pi = hexDecode(args[2])
    let alphaHex = readAlpha(args, 3)
    let alpha = hexDecode(alphaHex)
    let (valid, beta) = ecvrfVerify(pk: pk, pi: pi, alpha: alpha)
    if valid, let beta = beta {
        print("{\"valid\":true,\"beta\":\"\(hexEncode(beta))\"}")
    } else {
        print("{\"valid\":false,\"beta\":null}")
    }
default:
    fputs("unknown command: \(cmd)\n", stderr)
    exit(1)
}
