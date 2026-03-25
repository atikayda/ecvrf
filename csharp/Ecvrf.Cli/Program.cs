using System.Text.Json;
using Ecvrf;

static byte[] HexDecode(string hex)
{
    var bytes = new byte[hex.Length / 2];
    for (int i = 0; i < bytes.Length; i++)
        bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
    return bytes;
}

static string HexEncode(byte[] bytes) =>
    BitConverter.ToString(bytes).Replace("-", "").ToLowerInvariant();

static string ReadAlpha(string[] args, int idx)
{
    if (idx < args.Length && args[idx] == "--alpha-file" && idx + 1 < args.Length)
        return File.ReadAllText(args[idx + 1]).Trim();
    if (idx < args.Length)
        return args[idx];
    Console.Error.WriteLine("missing alpha argument");
    Environment.Exit(1);
    return "";
}

if (args.Length < 1)
{
    Console.Error.WriteLine("usage: ecvrf-csharp prove|verify ...");
    return 1;
}

if (args[0] == "prove")
{
    var sk = HexDecode(args[1]);
    var alphaHex = ReadAlpha(args, 2);
    var alpha = HexDecode(alphaHex);
    var pi = EcvrfSecp256k1.Prove(sk, alpha);
    var beta = EcvrfSecp256k1.ProofToHash(pi);
    Console.WriteLine(JsonSerializer.Serialize(new { pi = HexEncode(pi), beta = HexEncode(beta) }));
}
else if (args[0] == "verify")
{
    var pk = HexDecode(args[1]);
    var pi = HexDecode(args[2]);
    var alphaHex = ReadAlpha(args, 3);
    var alpha = HexDecode(alphaHex);
    var (valid, beta) = EcvrfSecp256k1.Verify(pk, pi, alpha);
    Console.WriteLine(JsonSerializer.Serialize(new { valid, beta = beta != null ? HexEncode(beta) : (string?)null }));
}
else
{
    Console.Error.WriteLine($"unknown command: {args[0]}");
    return 1;
}

return 0;
