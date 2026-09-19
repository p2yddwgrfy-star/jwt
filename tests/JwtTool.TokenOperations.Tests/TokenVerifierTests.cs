using System.Security.Cryptography;
using System.Text;
using JwtTool.TokenOperations;
using Xunit;

namespace JwtTool.TokenOperations.Tests;

public class TokenVerifierTests
{
    // Canonical jwt.io example token, signed with the famous secret "your-256-bit-secret".
    // Independent source of truth for a genuinely valid HS256 token.
    private const string CanonicalToken =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

    private const string CanonicalSecret = "your-256-bit-secret";

    [Fact]
    public void Verify_canonical_token_with_its_true_secret_is_valid()
    {
        var result = TokenVerifier.Verify(CanonicalToken, SignatureAlgorithm.HS256, CanonicalSecret);

        Assert.True(result.IsValid);
        Assert.Null(result.Reason);
    }

    [Fact]
    public void Verify_canonical_token_with_wrong_secret_is_invalid()
    {
        var result = TokenVerifier.Verify(CanonicalToken, SignatureAlgorithm.HS256, "not-the-secret");

        Assert.False(result.IsValid);
        Assert.NotNull(result.Reason);
    }

    [Theory]
    [InlineData(SignatureAlgorithm.HS384)]
    [InlineData(SignatureAlgorithm.HS512)]
    public void Verify_token_signed_with_hs384_or_hs512_and_matching_secret_is_valid(SignatureAlgorithm algorithm)
    {
        var token = SignHs("my-test-secret", algorithm, """{"sub":"a"}""");

        var result = TokenVerifier.Verify(token, algorithm, "my-test-secret");

        Assert.True(result.IsValid);
        Assert.Null(result.Reason);
    }

    [Fact]
    public void Verify_token_whose_header_alg_differs_from_chosen_algorithm_is_invalid()
    {
        // Canonical token has alg HS256 in its header; verifying as HS384 must be refused.
        var result = TokenVerifier.Verify(CanonicalToken, SignatureAlgorithm.HS384, CanonicalSecret);

        Assert.False(result.IsValid);
        Assert.Contains("HS256", result.Reason);
    }

    [Fact]
    public void Verify_unsigned_token_is_invalid_even_without_key()
    {
        var token = MakeToken("""{"alg":"none"}""", """{"sub":"a"}""", "");

        var result = TokenVerifier.Verify(token, SignatureAlgorithm.HS256, "any-secret");

        Assert.False(result.IsValid);
        Assert.Contains("unsigned", result.Reason);
    }

    [Fact]
    public void Verify_input_without_three_parts_is_invalid()
    {
        var result = TokenVerifier.Verify("not-a-token", SignatureAlgorithm.HS256, "secret");

        Assert.False(result.IsValid);
        Assert.NotNull(result.Reason);
    }

    [Fact]
    public void Verify_with_empty_key_is_invalid_and_explains_what_is_missing()
    {
        var result = TokenVerifier.Verify(CanonicalToken, SignatureAlgorithm.HS256, "");

        Assert.False(result.IsValid);
        Assert.Contains("Key", result.Reason);
    }

    /// Signs a payload with a plain HMAC over header.payload, independent of the library under test.
    private static string SignHs(string secret, SignatureAlgorithm algorithm, string payloadJson)
    {
        var header = algorithm switch
        {
            SignatureAlgorithm.HS384 => """{"alg":"HS384","typ":"JWT"}""",
            SignatureAlgorithm.HS512 => """{"alg":"HS512","typ":"JWT"}""",
            _ => """{"alg":"HS256","typ":"JWT"}""",
        };
        var signingInput = $"{Encode(header)}.{Encode(payloadJson)}";
        var key = Encoding.UTF8.GetBytes(secret);
        var signedBytes = Encoding.UTF8.GetBytes(signingInput);
        var sig = algorithm switch
        {
            SignatureAlgorithm.HS512 => new HMACSHA512(key).ComputeHash(signedBytes),
            SignatureAlgorithm.HS384 => new HMACSHA384(key).ComputeHash(signedBytes),
            _ => new HMACSHA256(key).ComputeHash(signedBytes),
        };
        return $"{signingInput}.{Encode(sig)}";
    }

    private static string MakeToken(string headerJson, string payloadJson, string signature) =>
        $"{Encode(headerJson)}.{Encode(payloadJson)}.{signature}";

    private static string Encode(string s) =>
        Encode(Encoding.UTF8.GetBytes(s));

    private static string Encode(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
