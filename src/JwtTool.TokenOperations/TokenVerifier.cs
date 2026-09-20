using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;

namespace JwtTool.TokenOperations;

/// <summary>The outcome of Verify: a plain verdict plus the reason when invalid.</summary>
public sealed record VerifyResult(bool IsValid, string? Reason)
{
    public static readonly VerifyResult Valid = new(true, null);
}

/// <summary>
/// Decides an RS256 signature over the signing input, expected signature bytes, and PEM key
/// material. The library defaults to BCL RSA (full .NET); the browser app supplies a
/// Web Crypto-backed implementation, because .NET on browser WebAssembly has no RSA.
/// </summary>
public delegate ValueTask<bool> RsaSignatureVerifier(
    string signingInput, byte[] expectedSignature, string keyMaterial);

/// <summary>
/// Strict Verify of a Token's Signature. The algorithm is chosen explicitly and cross-checked
/// against the Token header's alg; verification never falls back to unsecured.
/// </summary>
public static class TokenVerifier
{
    public static VerifyResult Verify(string token, SignatureAlgorithm algorithm, string keyMaterial) =>
        VerifyAsync(token, algorithm, keyMaterial).AsTask().GetAwaiter().GetResult();

    public static async ValueTask<VerifyResult> VerifyAsync(
        string token,
        SignatureAlgorithm algorithm,
        string keyMaterial,
        RsaSignatureVerifier? verifyRsaSignature = null)
    {
        var verifyRsa = verifyRsaSignature ?? BclRsaSignatureVerifier.VerifyAsync;
        var parts = TokenParts.Of(token);
        if (parts is null)
            return new VerifyResult(false, "A Token is three parts joined by dots; this input does not have three.");

        var headerAlg = TokenPartReader.ReadJsonObject(parts[0], "Header").Obj?["alg"]?.GetValue<string>();
        if (headerAlg is null)
            return new VerifyResult(false, "The Header could not be read, so the algorithm cannot be cross-checked.");
        if (SignatureAlgorithms.IsUnsignedHeaderAlg(headerAlg))
            return new VerifyResult(false,
                "The Token is unsigned (alg: none) — there is no Signature to Verify. Anyone could have forged its contents.");
        if (!SignatureAlgorithms.HeaderAlgMatches(headerAlg, algorithm))
            return new VerifyResult(false,
                $"The Token's header says alg {headerAlg}, but you chose {SignatureAlgorithms.JwaName(algorithm)}. " +
                "Verify with the algorithm the Token actually uses.");

        if (string.IsNullOrWhiteSpace(keyMaterial))
            return new VerifyResult(false, "A Key is required to Verify: paste the Secret (HS family) or PEM key pair (RS256).");

        var signingInput = $"{parts[0]}.{parts[1]}";
        byte[] expected;
        try
        {
            expected = Base64Url.DecodeToBytes(parts[2]);
        }
        catch (FormatException)
        {
            return new VerifyResult(false, "The Signature part is not valid base64url, so it cannot be a real signature.");
        }
        try
        {
            var valid = algorithm == SignatureAlgorithm.RS256
                ? await verifyRsa(signingInput, expected, keyMaterial)
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

    private static bool VerifyHmacSignature(SignatureAlgorithm algorithm, string signingInput, byte[] expected, string keyMaterial)
    {
        var data = Encoding.UTF8.GetBytes(signingInput);
        using HMAC hmac = SignatureAlgorithms.CreateHmac(algorithm, keyMaterial);
        var computed = hmac.ComputeHash(data);
        return CryptographicOperations.FixedTimeEquals(expected, computed);
    }

    /// <summary>BCL RSA — the default on full .NET. The browser app never calls this: WASM has no RSA.</summary>
    private static class BclRsaSignatureVerifier
    {
        public static ValueTask<bool> VerifyAsync(string signingInput, byte[] expected, string keyMaterial)
        {
            using var rsa = RSA.Create();
            rsa.ImportFromPem(keyMaterial);
            return ValueTask.FromResult(rsa.VerifyData(
                Encoding.UTF8.GetBytes(signingInput), expected,
                System.Security.Cryptography.HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
        }
    }
}
