using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;

namespace JwtTool.TokenOperations;

/// <summary>
/// Encode: constructs a new Token from editable header and payload JSON and signs it with a Key.
/// The header's alg is cross-checked against the chosen algorithm exactly as Verify does;
/// a missing alg is filled in with the chosen one.
/// </summary>
public delegate ValueTask<byte[]> RsaSignatureSigner(string signingInput, string keyMaterial);

public static class TokenEncoder
{
    public static string Encode(string headerJson, string payloadJson, SignatureAlgorithm algorithm, string keyMaterial) =>
        EncodeAsync(headerJson, payloadJson, algorithm, keyMaterial).AsTask().GetAwaiter().GetResult();

    public static async ValueTask<string> EncodeAsync(
        string headerJson,
        string payloadJson,
        SignatureAlgorithm algorithm,
        string keyMaterial,
        RsaSignatureSigner? signRsaSignature = null)
    {
        if (string.IsNullOrWhiteSpace(keyMaterial))
            throw new ArgumentException("A Key is required to Encode: a Secret (HS family) or PEM RSA key (RS256).", nameof(keyMaterial));

        var header = ParseObject(headerJson, "Header");
        var payload = ParseObject(payloadJson, "Payload");

        var algName = algorithm.ToString();
        if (header["alg"] is not { } existingAlg)
        {
            var reordered = new JsonObject { ["alg"] = algName };
            foreach (var property in header)
                reordered[property.Key] = property.Value?.DeepClone();
            header = reordered;
        }
        else if (!existingAlg.GetValue<string>().Equals(algName, StringComparison.Ordinal))
        {
            throw new ArgumentException(
                $"The Header's alg is {existingAlg.GetValue<string>()}, but you chose {algName}. " +
                "Edit the header or pick the matching algorithm.");
        }

        var headerPart = Base64Url.Encode(Encoding.UTF8.GetBytes(header.ToJsonString()));
        var payloadPart = Base64Url.Encode(Encoding.UTF8.GetBytes(payload.ToJsonString()));
        var signingInput = $"{headerPart}.{payloadPart}";
        var signature = await ComputeSignatureAsync(algorithm, keyMaterial, signingInput, signRsaSignature);
        return $"{headerPart}.{payloadPart}.{Base64Url.Encode(signature)}";
    }

    private static JsonObject ParseObject(string json, string name)
    {
        try
        {
            return JsonNode.Parse(json) is JsonObject obj
                ? obj
                : throw new ArgumentException($"The {name} does not contain a JSON object.");
        }
        catch (System.Text.Json.JsonException)
        {
            throw new ArgumentException($"The {name} is not valid JSON.");
        }
    }

    private static async ValueTask<byte[]> ComputeSignatureAsync(
        SignatureAlgorithm algorithm,
        string keyMaterial,
        string signingInput,
        RsaSignatureSigner? signRsaSignature)
    {
        var data = Encoding.UTF8.GetBytes(signingInput);
        if (algorithm == SignatureAlgorithm.RS256)
        {
            try
            {
                var signer = signRsaSignature ?? BclRsaSignatureSigner.SignAsync;
                return await signer(signingInput, keyMaterial);
            }
            catch (Exception ex) when (ex is CryptographicException or ArgumentException)
            {
                throw new ArgumentException(
                    "RS256 Encode needs the private key — a public key can only verify, not sign. " +
                    "Paste the BEGIN PRIVATE KEY block.", ex);
            }
        }

        var key = Encoding.UTF8.GetBytes(keyMaterial);
        using HMAC hmac = algorithm switch
        {
            SignatureAlgorithm.HS256 => new HMACSHA256(key),
            SignatureAlgorithm.HS384 => new HMACSHA384(key),
            SignatureAlgorithm.HS512 => new HMACSHA512(key),
            _ => throw new ArgumentOutOfRangeException(nameof(algorithm)),
        };
        return hmac.ComputeHash(data);
    }

    private static class BclRsaSignatureSigner
    {
        public static ValueTask<byte[]> SignAsync(string signingInput, string keyMaterial)
        {
            using var rsa = RSA.Create();
            rsa.ImportFromPem(keyMaterial);
            return ValueTask.FromResult(rsa.SignData(
                Encoding.UTF8.GetBytes(signingInput),
                System.Security.Cryptography.HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1));
        }
    }
}
