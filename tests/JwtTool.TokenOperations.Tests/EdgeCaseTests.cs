using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using JwtTool.TokenOperations;
using Xunit;

namespace JwtTool.TokenOperations.Tests;

public class EdgeCaseTests
{
    private const string Secret = "your-256-bit-secret";

    [Fact]
    public void Decode_a_part_whose_length_mod_4_is_1_warns_instead_of_crashing()
    {
        // A 5-character signature: 5 % 4 == 1, unrepresentable in base64.
        var header = ToBase64Url("""{"alg":"HS256"}""");
        var payload = ToBase64Url("""{"sub":"a"}""");
        var token = $"{header}.{payload}.abcde";

        var result = TokenDecoder.Decode(token);

        Assert.Null(result.ParseError);
        Assert.Contains(result.Warnings, w => w.Contains("Signature"));
    }

    [Fact]
    public void Verify_a_part_whose_length_mod_4_is_1_is_invalid_without_throwing()
    {
        var header = ToBase64Url("""{"alg":"HS256"}""");
        var payload = ToBase64Url("""{"sub":"a"}""");
        var token = $"{header}.{payload}.abcde";

        var result = TokenVerifier.Verify(token, SignatureAlgorithm.HS256, Secret);

        Assert.False(result.IsValid);
        Assert.NotNull(result.Reason);
    }

    [Fact]
    public void Unicode_payload_round_trips_through_encode_decode_and_verify()
    {
        var payload = """{"sub":"日本語テスト","emoji":"🔐🚀","name":"Ünïcødé"}""";

        var token = TokenEncoder.Encode("""{"alg":"HS256","typ":"JWT"}""", payload, SignatureAlgorithm.HS256, Secret);

        var decoded = TokenDecoder.Decode(token);
        Assert.Null(decoded.ParseError);
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse(payload), JsonNode.Parse(decoded.PayloadJson!)));
        Assert.True(TokenVerifier.Verify(token, SignatureAlgorithm.HS256, Secret).IsValid);
    }

    [Fact]
    public void Unicode_payload_round_trips_through_rs256_encode_decode_and_verify()
    {
        var payload = """{"sub":"日本語テスト","emoji":"🔐🚀","name":"Ünïcødé"}""";

        using var rsa = RSA.Create(2048);
        var token = TokenEncoder.Encode(
            """{"alg":"RS256","typ":"JWT"}""",
            payload, SignatureAlgorithm.RS256, rsa.ExportPkcs8PrivateKeyPem());

        var decoded = TokenDecoder.Decode(token);
        Assert.Null(decoded.ParseError);
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse(payload), JsonNode.Parse(decoded.PayloadJson!)));
        Assert.True(TokenVerifier.Verify(token, SignatureAlgorithm.RS256, rsa.ExportSubjectPublicKeyInfoPem()).IsValid);
    }

    private static string ToBase64Url(string s) =>
        Convert.ToBase64String(Encoding.UTF8.GetBytes(s)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
