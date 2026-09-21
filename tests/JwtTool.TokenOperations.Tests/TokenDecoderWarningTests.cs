using JwtTool.TokenOperations;
using Xunit;

namespace JwtTool.TokenOperations.Tests;

public class TokenDecoderWarningTests
{
    private const string Signature = "c2lnbmF0dXJl";

    [Fact]
    public void Decode_unsigned_token_warns_alg_none_but_still_renders()
    {
        var token = MakeToken("""{"alg":"none"}""", """{"sub":"a"}""");

        var result = TokenDecoder.Decode(token);

        Assert.Null(result.ParseError);
        Assert.Equal("none", result.Algorithm);
        Assert.Contains(result.Warnings, w => w.Contains("unsigned") && w.Contains("alg: none"));
        Assert.NotNull(result.PayloadJson);
    }

    [Fact]
    public void Decode_token_with_non_base64url_header_warns_and_still_decodes_payload()
    {
        var token = $"%%%not-base64@@.eyJzdWIiOiJhIn0.{Signature}";

        var result = TokenDecoder.Decode(token);

        Assert.Null(result.ParseError);
        Assert.Contains(result.Warnings, w => w.Contains("Header") && w.Contains("base64url"));
        Assert.NotNull(result.PayloadJson);
        Assert.Null(result.HeaderJson);
    }

    [Fact]
    public void Decode_token_with_non_json_payload_warns_but_keeps_signature()
    {
        var token = $"{ToBase64Url("""{"alg":"HS256","typ":"JWT"}""")}.{ToBase64Url("hello, this is not json")}.{Signature}";

        var result = TokenDecoder.Decode(token);

        Assert.Null(result.ParseError);
        Assert.Contains(result.Warnings, w => w.Contains("Payload") && w.Contains("JSON object"));
        Assert.Equal(Signature, result.SignatureBase64Url);
        Assert.Null(result.PayloadJson);
    }

    [Fact]
    public void Decode_token_with_a_valid_json_array_payload_warns_but_keeps_signature()
    {
        // Valid JSON that is not an object: "WzEsMl0" is the base64url of "[1,2]".
        var token = $"{ToBase64Url("""{"alg":"HS256","typ":"JWT"}""")}.WzEsMl0.{Signature}";

        var result = TokenDecoder.Decode(token);

        Assert.Null(result.ParseError);
        Assert.Contains(result.Warnings, w => w.Contains("Payload") && w.Contains("does not contain a JSON object"));
        Assert.Equal(Signature, result.SignatureBase64Url);
        Assert.Null(result.PayloadJson);
    }

    [Theory]
    [InlineData("42")]
    [InlineData("\"str\"")]
    [InlineData("null")]
    [InlineData("[]")]
    public void Decode_payloads_of_valid_json_that_is_not_an_object_warn(string json)
    {
        var token = MakeToken("""{"alg":"HS256"}""", json);

        var result = TokenDecoder.Decode(token);

        Assert.Null(result.ParseError);
        Assert.Contains(result.Warnings, w => w.Contains("Payload") && w.Contains("does not contain a JSON object"));
        Assert.Null(result.PayloadJson);
    }

    [Fact]
    public void Decode_token_with_empty_header_and_payload_parts_warns_each()
    {
        // An empty header or payload part reaches the reader, which names it in the warning.
        var result = TokenDecoder.Decode("..");

        Assert.Null(result.ParseError);
        Assert.Contains(result.Warnings, w => w.Contains("Header") && w.Contains("is empty"));
        Assert.Contains(result.Warnings, w => w.Contains("Payload") && w.Contains("is empty"));
        Assert.Null(result.HeaderJson);
        Assert.Null(result.PayloadJson);
    }

    [Fact]
    public void Decode_token_whose_header_has_no_alg_claim_yields_no_algorithm()
    {
        // A valid JSON object header with no alg claim: Algorithm stays null, the token
        // is not flagged unsigned, and the payload still decodes.
        var token = MakeToken("""{"typ":"JWT"}""", """{"sub":"a"}""");

        var result = TokenDecoder.Decode(token);

        Assert.Null(result.ParseError);
        Assert.Null(result.Algorithm);
        Assert.DoesNotContain(result.Warnings, w => w.Contains("unsigned"));
        Assert.NotNull(result.PayloadJson);
    }

    [Fact]
    public void Decode_token_whose_header_is_not_a_json_object_yields_no_algorithm()
    {
        // A valid-JSON non-object header: no Algorithm, the reader's warning names it.
        var token = MakeToken("[1,2]", """{"sub":"a"}""");

        var result = TokenDecoder.Decode(token);

        Assert.Null(result.ParseError);
        Assert.Null(result.Algorithm);
        Assert.Contains(result.Warnings, w => w.Contains("Header") && w.Contains("does not contain a JSON object"));
        Assert.NotNull(result.PayloadJson);
    }

    [Theory]
    [InlineData("only-two-parts")]
    [InlineData("a.b.c.d")]
    public void Decode_input_without_exactly_three_parts_is_unparseable(string token)
    {
        var result = TokenDecoder.Decode(token);

        Assert.True(result.IsUnparseable);
        Assert.NotNull(result.ParseError);
        Assert.Empty(result.Warnings);
    }

    [Fact]
    public void Decode_token_with_empty_signature_part_warns()
    {
        var token = $"{ToBase64Url("""{"alg":"HS256"}""")}.{ToBase64Url("""{"sub":"a"}""")}.";

        var result = TokenDecoder.Decode(token);

        Assert.Null(result.ParseError);
        Assert.Contains(result.Warnings, w => w.Contains("Signature") && w.Contains("empty"));
    }

    [Fact]
    public void Decode_token_with_string_exp_warns_claim_is_not_a_timestamp()
    {
        var token = MakeToken("""{"alg":"HS256"}""", """{"exp":"tomorrow"}""");

        var result = TokenDecoder.Decode(token);

        Assert.Null(result.ParseError);
        Assert.Contains(result.Warnings, w => w.Contains("'exp'") && w.Contains("not a numeric Unix timestamp"));
        Assert.Empty(result.TimeClaims);
    }

    [Fact]
    public void Decode_token_with_no_time_claims_warns_it_never_expires()
    {
        var token = MakeToken("""{"alg":"HS256"}""", """{"sub":"a"}""");

        var result = TokenDecoder.Decode(token);

        Assert.Null(result.ParseError);
        Assert.Contains(result.Warnings, w => w.Contains("no time Claims") && w.Contains("never expires"));
    }

    private static string MakeToken(string headerJson, string payloadJson) =>
        $"{ToBase64Url(headerJson)}.{ToBase64Url(payloadJson)}.{Signature}";

    private static string ToBase64Url(string s) =>
        Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(s))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
