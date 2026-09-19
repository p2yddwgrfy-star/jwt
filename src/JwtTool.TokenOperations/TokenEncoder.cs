using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;

namespace JwtTool.TokenOperations;

/// <summary>
/// Encode: constructs a new Token from editable header and payload JSON and signs it with a Key.
/// The header's alg is cross-checked against the chosen algorithm exactly as Verify does;
/// a missing alg is filled in with the chosen one.
/// </summary>
public static class TokenEncoder
{
    public static string Encode(string headerJson, string payloadJson, SignatureAlgorithm algorithm, string keyMaterial)
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
        var signature = ComputeSignature(algorithm, keyMaterial, $"{headerPart}.{payloadPart}");
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

    private static byte[] ComputeSignature(SignatureAlgorithm algorithm, string keyMaterial, string signingInput)
    {
        var data = Encoding.UTF8.GetBytes(signingInput);
        if (algorithm == SignatureAlgorithm.RS256)
        {
            using var rsa = RSA.Create();
            rsa.ImportFromPem(keyMaterial);
            return rsa.SignData(data, System.Security.Cryptography.HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }

        var key = Encoding.UTF8.GetBytes(keyMaterial);
        return algorithm switch
        {
            SignatureAlgorithm.HS256 => new HMACSHA256(key).ComputeHash(data),
            SignatureAlgorithm.HS384 => new HMACSHA384(key).ComputeHash(data),
            SignatureAlgorithm.HS512 => new HMACSHA512(key).ComputeHash(data),
            _ => throw new ArgumentOutOfRangeException(nameof(algorithm)),
        };
    }
}
