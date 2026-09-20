using System.Text.Json.Nodes;
using JwtTool.TokenOperations;
using Xunit;

namespace JwtTool.TokenOperations.Tests;

public class TokenDecoderDecodeTests
{
    // Canonical example token from jwt.io — independent source of truth.
    // Header: {"alg":"HS256","typ":"JWT"}
    // Payload: {"sub":"1234567890","name":"John Doe","iat":1516239022}
    private const string CanonicalToken =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

    private static readonly string CanonicalHeaderJson =
        """{"alg":"HS256","typ":"JWT"}""";

    private static readonly string CanonicalPayloadJson =
        """{"sub":"1234567890","name":"John Doe","iat":1516239022}""";

    [Fact]
    public void Decode_canonical_token_yields_exact_header_and_payload()
    {
        var result = TokenDecoder.Decode(CanonicalToken);

        Assert.Null(result.ParseError);
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse(CanonicalHeaderJson), JsonNode.Parse(result.HeaderJson!)));
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse(CanonicalPayloadJson), JsonNode.Parse(result.PayloadJson!)));
    }

    [Fact]
    public void Decode_canonical_token_reports_algorithm_and_raw_signature()
    {
        var result = TokenDecoder.Decode(CanonicalToken);

        Assert.Equal("HS256", result.Algorithm);
        Assert.Equal("SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", result.SignatureBase64Url);
    }

    [Fact]
    public void Decode_canonical_token_exposes_iat_as_human_readable_time_claim()
    {
        var result = TokenDecoder.Decode(CanonicalToken);

        var iat = Assert.Single(result.TimeClaims, c => c.Name == "iat");
        Assert.Equal(new DateTimeOffset(2018, 1, 18, 1, 30, 22, TimeSpan.Zero), iat.Value);
        Assert.False(iat.IsExpired);
        Assert.False(iat.NotYetValid);
    }

    [Fact]
    public void Decode_token_with_past_exp_flags_it_expired()
    {
        // exp = 1000000000 → 2001-09-09T01:46:40Z
        var token = MakeToken("""{"exp":1000000000}""");

        var result = TokenDecoder.Decode(token);

        var exp = Assert.Single(result.TimeClaims, c => c.Name == "exp");
        Assert.Equal(new DateTimeOffset(2001, 9, 9, 1, 46, 40, TimeSpan.Zero), exp.Value);
        Assert.True(exp.IsExpired);
        Assert.False(exp.NotYetValid);
    }

    [Fact]
    public void Decode_token_with_future_nbf_flags_it_not_yet_valid()
    {
        var future = DateTimeOffset.UtcNow.AddHours(1).ToUnixTimeSeconds();
        var token = MakeToken($$"""{"nbf":{{future}}}""");

        var result = TokenDecoder.Decode(token);

        var nbf = Assert.Single(result.TimeClaims, c => c.Name == "nbf");
        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(future), nbf.Value);
        Assert.True(nbf.NotYetValid);
        Assert.False(nbf.IsExpired);
    }

    [Fact]
    public void Decode_tolerates_a_single_trailing_dot_after_the_signature()
    {
        // A common paste artifact: the token ends with a stray dot.
        var result = TokenDecoder.Decode(CanonicalToken + ".");

        Assert.Null(result.ParseError);
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse(CanonicalPayloadJson), JsonNode.Parse(result.PayloadJson!)));
        Assert.Equal("SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", result.SignatureBase64Url);
    }

    [Fact]
    public void Decode_reports_the_true_part_count_for_a_four_part_input()
    {
        var result = TokenDecoder.Decode(CanonicalToken + ".extra");

        Assert.True(result.IsUnparseable);
        Assert.Contains("this input has 4 part(s)", result.ParseError);
    }

    /// Encodes a payload into a three-part token with an HS256-style header.
    /// Independent of the implementation under test: plain base64url encoding of known JSON.
    private static string MakeToken(string payloadJson)
    {
        static string Encode(string s) =>
            Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(s))
                .TrimEnd('=').Replace('+', '-').Replace('/', '_');

        return $"{Encode("""{"alg":"HS256","typ":"JWT"}""")}.{Encode(payloadJson)}.c2lnbmF0dXJl";
    }
}
