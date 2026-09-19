using JwtTool.TokenOperations;
using Xunit;

namespace JwtTool.TokenOperations.Tests;

public class TokenVerifierTrailingDotTests
{
    // Canonical jwt.io token signed with "your-256-bit-secret".
    private const string CanonicalToken =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

    private const string CanonicalSecret = "your-256-bit-secret";

    [Fact]
    public void Verify_tolerates_a_single_trailing_dot_like_decode_does()
    {
        var result = TokenVerifier.Verify(CanonicalToken + ".", SignatureAlgorithm.HS256, CanonicalSecret);

        Assert.True(result.IsValid);
        Assert.Null(result.Reason);
    }

    [Fact]
    public void Verify_with_trailing_dot_and_wrong_secret_reports_signature_mismatch()
    {
        var result = TokenVerifier.Verify(CanonicalToken + ".", SignatureAlgorithm.HS256, "wrong");

        Assert.False(result.IsValid);
        Assert.Contains("Signature", result.Reason);
    }

    [Fact]
    public void Verify_still_rejects_more_than_a_trailing_dot()
    {
        var result = TokenVerifier.Verify(CanonicalToken + ".extra", SignatureAlgorithm.HS256, CanonicalSecret);

        Assert.False(result.IsValid);
        Assert.Contains("three", result.Reason);
    }
}
