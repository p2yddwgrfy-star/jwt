using System.Security.Cryptography;
using System.Text;

namespace JwtTool.TokenOperations;

/// <summary>The signing algorithms this tool supports for Verify and Encode.</summary>
public enum SignatureAlgorithm
{
    HS256,
    HS384,
    HS512,
    RS256,
}

/// <summary>
/// The one place that knows the Signature algorithms: their JWA names, what counts as an
/// unsigned header alg, whether a Token's header alg matches the chosen algorithm, and the
/// HS-family HMAC factory. Verify and Encode lean on these rules; their user-facing
/// wording stays deliberately different at each call site.
/// </summary>
public static class SignatureAlgorithms
{
    /// <summary>The JWA alg string of an algorithm. Enum member names are exactly the JWA strings for this set.</summary>
    public static string JwaName(SignatureAlgorithm algorithm) => algorithm.ToString();

    /// <summary>Whether the Token's header alg matches the chosen algorithm (JWA names, case-sensitive).</summary>
    public static bool HeaderAlgMatches(string headerAlg, SignatureAlgorithm algorithm) =>
        headerAlg.Equals(JwaName(algorithm), StringComparison.Ordinal);

    /// <summary>Whether the Token's header alg marks it unsigned — alg: none, any casing.</summary>
    public static bool IsUnsignedHeaderAlg(string headerAlg) =>
        headerAlg.Equals("none", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// The HMAC hasher of the HS-family member, over the exact key bytes of <paramref name="keyMaterial"/>.
    /// RS256 has no HMAC; the caller disposes the hasher when done.
    /// </summary>
    public static HMAC CreateHmac(SignatureAlgorithm algorithm, string keyMaterial) => algorithm switch
    {
        SignatureAlgorithm.HS256 => new HMACSHA256(Encoding.UTF8.GetBytes(keyMaterial)),
        SignatureAlgorithm.HS384 => new HMACSHA384(Encoding.UTF8.GetBytes(keyMaterial)),
        SignatureAlgorithm.HS512 => new HMACSHA512(Encoding.UTF8.GetBytes(keyMaterial)),
        _ => throw new ArgumentOutOfRangeException(nameof(algorithm)),
    };
}
