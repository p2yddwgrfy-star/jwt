using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;

namespace JwtTool.TokenOperations;

/// <summary>The signing algorithms this tool supports for Verify and Encode.</summary>
public enum SignatureAlgorithm
{
    HS256,
    HS384,
    HS512,
    RS256,
}

/// <summary>The outcome of Verify: a plain verdict plus the reason when invalid.</summary>
public sealed record VerifyResult(bool IsValid, string? Reason)
{
    public static readonly VerifyResult Valid = new(true, null);
}

/// <summary>
/// Strict Verify of a Token's Signature. The algorithm is chosen explicitly and cross-checked
/// against the Token header's alg; verification never falls back to unsecured.
/// </summary>
public static class TokenVerifier
{
    public static VerifyResult Verify(string token, SignatureAlgorithm algorithm, string keyMaterial)
    {
        var parts = token.Split('.');
        if (parts.Length == 4 && parts[3].Length == 0)
            parts = parts[..3]; // tolerate a single trailing dot, matching Decode's paste-artifact leniency
        if (parts.Length != 3)
            return new VerifyResult(false, "A Token is three parts joined by dots; this input does not have three.");

        var headerAlg = TokenPartReader.ReadJsonObject(parts[0], "Header").Obj?["alg"]?.GetValue<string>();
        if (headerAlg is null)
            return new VerifyResult(false, "The Header could not be read, so the algorithm cannot be cross-checked.");
        if (headerAlg.Equals("none", StringComparison.OrdinalIgnoreCase))
            return new VerifyResult(false,
                "The Token is unsigned (alg: none) — there is no Signature to Verify. Anyone could have forged its contents.");
        if (!headerAlg.Equals(SignatureAlgorithmName(algorithm), StringComparison.Ordinal))
            return new VerifyResult(false,
                $"The Token's header says alg {headerAlg}, but you chose {SignatureAlgorithmName(algorithm)}. " +
                "Verify with the algorithm the Token actually uses.");

        if (string.IsNullOrWhiteSpace(keyMaterial))
            return new VerifyResult(false, "A Key is required to Verify: paste the Secret (HS family) or PEM key pair (RS256).");

        var signingInput = $"{parts[0]}.{parts[1]}";
        var expected = Base64Url.DecodeToBytes(parts[2]);
        try
        {
            var valid = algorithm == SignatureAlgorithm.RS256
                ? VerifyRsaSignature(signingInput, expected, keyMaterial)
                : VerifyHmacSignature(algorithm, signingInput, expected, keyMaterial);

            return valid
                ? VerifyResult.Valid
                : new VerifyResult(false, "The Signature does not match this Key — the Token was signed with something else (or altered).");
        }
        catch (Exception ex) when (ex is CryptographicException or ArgumentException)
        {
            return new VerifyResult(false,
                "The Key could not be read as a PEM RSA key. Paste a complete BEGIN PUBLIC KEY or BEGIN PRIVATE KEY block.");
        }
    }

    private static string SignatureAlgorithmName(SignatureAlgorithm algorithm) =>
        algorithm.ToString(); // enum member names are exactly the JWA alg strings for this set

    private static bool VerifyHmacSignature(SignatureAlgorithm algorithm, string signingInput, byte[] expected, string keyMaterial)
    {
        var key = Encoding.UTF8.GetBytes(keyMaterial);
        var data = Encoding.UTF8.GetBytes(signingInput);
        var computed = algorithm switch
        {
            SignatureAlgorithm.HS256 => new HMACSHA256(key).ComputeHash(data),
            SignatureAlgorithm.HS384 => new HMACSHA384(key).ComputeHash(data),
            SignatureAlgorithm.HS512 => new HMACSHA512(key).ComputeHash(data),
            _ => throw new ArgumentOutOfRangeException(nameof(algorithm)),
        };
        return CryptographicOperations.FixedTimeEquals(expected, computed);
    }

    private static bool VerifyRsaSignature(string signingInput, byte[] expected, string keyMaterial)
    {
        using var rsa = RSA.Create();
        rsa.ImportFromPem(keyMaterial);
        return rsa.VerifyData(Encoding.UTF8.GetBytes(signingInput), expected,
            System.Security.Cryptography.HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }
}
