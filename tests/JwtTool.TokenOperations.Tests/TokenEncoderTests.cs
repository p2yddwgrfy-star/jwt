using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using JwtTool.TokenOperations;
using Xunit;

namespace JwtTool.TokenOperations.Tests;

public class TokenEncoderTests
{
    private const string CanonicalSecret = "your-256-bit-secret";

    [Fact]
    public void Encode_hs256_round_trips_through_decode_and_verify()
    {
        var header = """{"alg":"HS256","typ":"JWT"}""";
        var payload = """{"sub":"1234567890","name":"John Doe","iat":1516239022}""";

        var token = TokenEncoder.Encode(header, payload, SignatureAlgorithm.HS256, CanonicalSecret);

        var decoded = TokenDecoder.Decode(token);
        Assert.Null(decoded.ParseError);
        Assert.Equal("HS256", decoded.Algorithm);
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse(header), JsonNode.Parse(decoded.HeaderJson!)));
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse(payload), JsonNode.Parse(decoded.PayloadJson!)));

        var verified = TokenVerifier.Verify(token, SignatureAlgorithm.HS256, CanonicalSecret);
        Assert.True(verified.IsValid);
        Assert.Null(verified.Reason);
    }

    [Fact]
    public void Encode_output_signature_part_is_base64url_without_padding()
    {
        var token = TokenEncoder.Encode("""{"alg":"HS256"}""", """{"sub":"a"}""", SignatureAlgorithm.HS256, CanonicalSecret);

        var signaturePart = token.Split('.')[2];
        Assert.DoesNotContain("=", signaturePart);
        Assert.DoesNotContain("+", signaturePart);
        Assert.DoesNotContain("/", signaturePart);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void Encode_rejects_a_missing_key(string key)
    {
        var result = Assert.Throws<ArgumentException>(
            () => TokenEncoder.Encode("""{"alg":"HS256"}""", """{"sub":"a"}""", SignatureAlgorithm.HS256, key));

        Assert.Contains("Key is required to Encode", result.Message);
    }

    [Fact]
    public void Encode_rejects_header_that_is_not_valid_json()
    {
        var result = Assert.Throws<ArgumentException>(
            () => TokenEncoder.Encode("not json", """{"sub":"a"}""", SignatureAlgorithm.HS256, "secret"));

        Assert.Contains("Header", result.Message);
    }

    [Fact]
    public void Encode_rejects_payload_that_is_not_valid_json()
    {
        var result = Assert.Throws<ArgumentException>(
            () => TokenEncoder.Encode("""{"alg":"HS256"}""", "{broken", SignatureAlgorithm.HS256, "secret"));

        Assert.Contains("Payload", result.Message);
    }

    [Fact]
    public void Encode_rejects_header_without_alg_mismatching_chosen_algorithm()
    {
        // Header says HS384 but the caller chose HS256: refuse rather than emit a lying token.
        var ex = Assert.Throws<ArgumentException>(
            () => TokenEncoder.Encode("""{"alg":"HS384","typ":"JWT"}""", """{"sub":"a"}""", SignatureAlgorithm.HS256, "secret"));

        Assert.Contains("HS256", ex.Message);
    }

    [Fact]
    public void Encode_with_missing_alg_header_adds_the_chosen_one()
    {
        var token = TokenEncoder.Encode("""{"typ":"JWT"}""", """{"sub":"a"}""", SignatureAlgorithm.HS256, CanonicalSecret);

        var decoded = TokenDecoder.Decode(token);
        Assert.Equal("HS256", decoded.Algorithm);
        Assert.True(TokenVerifier.Verify(token, SignatureAlgorithm.HS256, CanonicalSecret).IsValid);
    }

    [Fact]
    public void Encode_rs256_round_trips_and_verifies_with_the_public_key()
    {
        using var rsa = RSA.Create(2048);
        var privatePem = rsa.ExportPkcs8PrivateKeyPem();
        var publicPem = rsa.ExportSubjectPublicKeyInfoPem();

        var token = TokenEncoder.Encode("""{"alg":"RS256","typ":"JWT"}""", """{"sub":"rsa"}""", SignatureAlgorithm.RS256, privatePem);

        Assert.True(TokenVerifier.Verify(token, SignatureAlgorithm.RS256, publicPem).IsValid);
    }
}
