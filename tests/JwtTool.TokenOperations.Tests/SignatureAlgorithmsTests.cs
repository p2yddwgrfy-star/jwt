using System.Security.Cryptography;
using JwtTool.TokenOperations;
using Xunit;

namespace JwtTool.TokenOperations.Tests;

/// <summary>
/// Pins the one place that knows the Signature algorithms: the JWA name each enum member
/// maps to, what counts as an unsigned header alg, whether a Token's header alg matches the
/// chosen algorithm, and the HS-family HMAC factory. Verify and Encode both lean on these
/// rules; their user-facing wording stays at the call sites, pinned by their own suites.
/// </summary>
public class SignatureAlgorithmsTests
{
    [Theory]
    [InlineData(SignatureAlgorithm.HS256, "HS256")]
    [InlineData(SignatureAlgorithm.HS384, "HS384")]
    [InlineData(SignatureAlgorithm.HS512, "HS512")]
    [InlineData(SignatureAlgorithm.RS256, "RS256")]
    public void The_JWA_name_of_each_algorithm_is_its_enum_member(SignatureAlgorithm algorithm, string expected)
    {
        Assert.Equal(expected, SignatureAlgorithms.JwaName(algorithm));
    }

    [Theory]
    [InlineData("HS256", SignatureAlgorithm.HS256, true)]
    [InlineData("HS384", SignatureAlgorithm.HS384, true)]
    [InlineData("RS256", SignatureAlgorithm.RS256, true)]
    [InlineData("HS256", SignatureAlgorithm.HS384, false)]
    [InlineData("hs256", SignatureAlgorithm.HS256, false)] // JWA names are case-sensitive
    [InlineData("HS256 ", SignatureAlgorithm.HS256, false)]
    [InlineData("", SignatureAlgorithm.HS256, false)]
    public void A_header_alg_matches_only_the_same_chosen_algorithm(
        string headerAlg, SignatureAlgorithm algorithm, bool expected)
    {
        Assert.Equal(expected, SignatureAlgorithms.HeaderAlgMatches(headerAlg, algorithm));
    }

    [Theory]
    [InlineData("none", true)]
    [InlineData("None", true)]
    [InlineData("NONE", true)]
    [InlineData("HS256", false)]
    [InlineData("RS256", false)]
    [InlineData("garbage", false)]
    [InlineData("", false)]
    public void Only_alg_none_marks_a_token_unsigned(string headerAlg, bool expected)
    {
        Assert.Equal(expected, SignatureAlgorithms.IsUnsignedHeaderAlg(headerAlg));
    }

    [Fact]
    public void CreateHmac_builds_the_hasher_of_each_hs_family_member()
    {
        using var hs256 = SignatureAlgorithms.CreateHmac(SignatureAlgorithm.HS256, "your-256-bit-secret");
        using var hs384 = SignatureAlgorithms.CreateHmac(SignatureAlgorithm.HS384, "your-256-bit-secret");
        using var hs512 = SignatureAlgorithms.CreateHmac(SignatureAlgorithm.HS512, "your-256-bit-secret");

        Assert.IsType<HMACSHA256>(hs256);
        Assert.IsType<HMACSHA384>(hs384);
        Assert.IsType<HMACSHA512>(hs512);
    }

    [Fact]
    public void CreateHmac_signs_with_the_exact_key_bytes_given()
    {
        // Independent truth: the HS256 hasher over this key hashes this input to this digest.
        var key = "your-256-bit-secret";
        using var expected = new HMACSHA256(System.Text.Encoding.UTF8.GetBytes(key));

        using var actual = SignatureAlgorithms.CreateHmac(SignatureAlgorithm.HS256, key);

        Assert.Equal(
            expected.ComputeHash(System.Text.Encoding.UTF8.GetBytes("a.b")),
            actual.ComputeHash(System.Text.Encoding.UTF8.GetBytes("a.b")));
    }

    [Fact]
    public void CreateHmac_has_no_hasher_for_RS256()
    {
        var ex = Assert.Throws<ArgumentOutOfRangeException>(
            () => SignatureAlgorithms.CreateHmac(SignatureAlgorithm.RS256, "a pem"));

        Assert.Equal("algorithm", ex.ParamName);
    }
}
