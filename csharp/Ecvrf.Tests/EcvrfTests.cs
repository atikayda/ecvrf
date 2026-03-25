using System.Text.Json;
using System.Text.Json.Serialization;

namespace Ecvrf.Tests;

public class EcvrfTests
{
    private static readonly VectorFile Vectors = LoadVectors();

    private static VectorFile LoadVectors()
    {
        var json = File.ReadAllText(Path.Combine("..", "..", "..", "..", "..", "vectors", "vectors.json"));
        return JsonSerializer.Deserialize<VectorFile>(json)
            ?? throw new InvalidOperationException("Failed to parse vectors.json");
    }

    private static byte[] HexToBytes(string hex) =>
        Convert.FromHexString(hex);

    [Fact]
    public void Prove_AllVectors()
    {
        foreach (var vec in Vectors.Vectors)
        {
            var sk = HexToBytes(vec.Sk);
            var alpha = HexToBytes(vec.Alpha);

            var pi = EcvrfSecp256k1.Prove(sk, alpha);
            var got = Convert.ToHexStringLower(pi);

            Assert.True(got == vec.Pi, $"[{vec.Label}] pi mismatch\n  got:  {got}\n  want: {vec.Pi}");
        }
    }

    [Fact]
    public void Verify_AllVectors()
    {
        foreach (var vec in Vectors.Vectors)
        {
            var pk = HexToBytes(vec.Pk);
            var alpha = HexToBytes(vec.Alpha);
            var pi = HexToBytes(vec.Pi);

            var (valid, beta) = EcvrfSecp256k1.Verify(pk, pi, alpha);

            Assert.True(valid, $"[{vec.Label}] Verify returned invalid for valid proof");
            Assert.NotNull(beta);
            var got = Convert.ToHexStringLower(beta);
            Assert.True(got == vec.Beta, $"[{vec.Label}] beta mismatch\n  got:  {got}\n  want: {vec.Beta}");
        }
    }

    [Fact]
    public void ProofToHash_AllVectors()
    {
        foreach (var vec in Vectors.Vectors)
        {
            var pi = HexToBytes(vec.Pi);
            var beta = EcvrfSecp256k1.ProofToHash(pi);
            var got = Convert.ToHexStringLower(beta);

            Assert.True(got == vec.Beta, $"[{vec.Label}] beta mismatch\n  got:  {got}\n  want: {vec.Beta}");
        }
    }

    [Fact]
    public void NegativeVerify_AllVectors()
    {
        foreach (var vec in Vectors.NegativeVectors)
        {
            var pk = HexToBytes(vec.Pk);
            var alpha = HexToBytes(vec.Alpha);
            var pi = HexToBytes(vec.Pi);

            var (valid, _) = EcvrfSecp256k1.Verify(pk, pi, alpha);

            Assert.True(valid == vec.ExpectedVerify,
                $"[{vec.Description}] expected verify={vec.ExpectedVerify}, got {valid}");
        }
    }

    [Fact]
    public void DerivePublicKey_AllVectors()
    {
        foreach (var vec in Vectors.Vectors)
        {
            var sk = HexToBytes(vec.Sk);
            var pk = EcvrfSecp256k1.DerivePublicKey(sk);
            var got = Convert.ToHexStringLower(pk);

            Assert.True(got == vec.Pk, $"[{vec.Label}] pk mismatch\n  got:  {got}\n  want: {vec.Pk}");
        }
    }

    [Fact]
    public void Prove_Deterministic()
    {
        var vec = Vectors.Vectors[0];
        var sk = HexToBytes(vec.Sk);
        var alpha = HexToBytes(vec.Alpha);

        var pi1 = EcvrfSecp256k1.Prove(sk, alpha);
        var pi2 = EcvrfSecp256k1.Prove(sk, alpha);

        Assert.Equal(Convert.ToHexStringLower(pi1), Convert.ToHexStringLower(pi2));
    }

    [Fact]
    public void RoundTrip_AllVectors()
    {
        foreach (var vec in Vectors.Vectors)
        {
            var sk = HexToBytes(vec.Sk);
            var pk = HexToBytes(vec.Pk);
            var alpha = HexToBytes(vec.Alpha);

            var pi = EcvrfSecp256k1.Prove(sk, alpha);
            var (valid, beta) = EcvrfSecp256k1.Verify(pk, pi, alpha);

            Assert.True(valid, $"[{vec.Label}] round-trip: Verify rejected own proof");
            Assert.NotNull(beta);

            var betaFromHash = EcvrfSecp256k1.ProofToHash(pi);
            Assert.Equal(Convert.ToHexStringLower(beta), Convert.ToHexStringLower(betaFromHash));
        }
    }

    [Theory]
    [InlineData("zero key", "0000000000000000000000000000000000000000000000000000000000000000")]
    [InlineData("sk = n", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")]
    public void Prove_RejectsInvalidSK(string _, string skHex)
    {
        var sk = HexToBytes(skHex);
        Assert.ThrowsAny<Exception>(() => EcvrfSecp256k1.Prove(sk, [0x74, 0x65, 0x73, 0x74]));
    }

    [Fact]
    public void Prove_RejectsWrongLength()
    {
        Assert.ThrowsAny<Exception>(() => EcvrfSecp256k1.Prove(new byte[31], [0x01]));
        Assert.ThrowsAny<Exception>(() => EcvrfSecp256k1.Prove(new byte[33], [0x01]));
    }
}

public class VectorFile
{
    [JsonPropertyName("suite")]
    public string Suite { get; set; } = "";

    [JsonPropertyName("spec")]
    public string Spec { get; set; } = "";

    [JsonPropertyName("vectors")]
    public List<PositiveVector> Vectors { get; set; } = [];

    [JsonPropertyName("negative_vectors")]
    public List<NegativeVector> NegativeVectors { get; set; } = [];
}

public class PositiveVector
{
    [JsonPropertyName("label")]
    public string Label { get; set; } = "";

    [JsonPropertyName("sk")]
    public string Sk { get; set; } = "";

    [JsonPropertyName("pk")]
    public string Pk { get; set; } = "";

    [JsonPropertyName("alpha")]
    public string Alpha { get; set; } = "";

    [JsonPropertyName("pi")]
    public string Pi { get; set; } = "";

    [JsonPropertyName("beta")]
    public string Beta { get; set; } = "";
}

public class NegativeVector
{
    [JsonPropertyName("description")]
    public string Description { get; set; } = "";

    [JsonPropertyName("pk")]
    public string Pk { get; set; } = "";

    [JsonPropertyName("alpha")]
    public string Alpha { get; set; } = "";

    [JsonPropertyName("pi")]
    public string Pi { get; set; } = "";

    [JsonPropertyName("expected_verify")]
    public bool ExpectedVerify { get; set; }
}
