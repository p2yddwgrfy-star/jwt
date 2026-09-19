using System.Text.Json;
using System.Text.Json.Nodes;

namespace JwtTool.TokenOperations;

/// <summary>A named time Claim from a Token payload, judged against the current clock.</summary>
public sealed record TimeClaim(string Name, DateTimeOffset Value, bool IsExpired, bool NotYetValid);

/// <summary>The outcome of Decode: whatever could be read from a Token, plus Warnings.</summary>
public sealed record DecodeResult(
    string? HeaderJson,
    string? PayloadJson,
    string? SignatureBase64Url,
    string? Algorithm,
    IReadOnlyList<TimeClaim> TimeClaims,
    IReadOnlyList<string> Warnings,
    string? ParseError)
{
    public static readonly DecodeResult Unparseable = new(null, null, null, null, [], [], null);
    public bool IsUnparseable => ParseError is not null;
}

/// <summary>
/// Lenient Decode of a compact Token: each part is parsed independently; anything unreadable
/// becomes a Warning rather than aborting. A clear ParseError is produced only for input
/// that cannot be parsed at all (not three dot-separated parts).
/// </summary>
public static class TokenDecoder
{
    private static readonly string[] TimeClaimNames = ["exp", "iat", "nbf"];

    public static DecodeResult Decode(string token)
    {
        var parts = token.Split('.');
        if (parts.Length == 4 && parts[3].Length == 0)
            parts = parts[..3]; // tolerate a single trailing dot: an empty Signature part, not a fourth part
        if (parts.Length != 3)
        {
            return DecodeResult.Unparseable with
            {
                ParseError = "A Token is three base64url parts joined by dots " +
                             $"(header.payload.signature); this input has {parts.Length} part(s).",
            };
        }

        var (headerJson, header, headerWarnings) = DecodePart(parts[0], "Header");
        var (payloadJson, payload, payloadWarnings) = DecodePart(parts[1], "Payload");
        var signatureWarning = parts[2].Length == 0 ? ["The Signature part is empty."] : Array.Empty<string>();
        var warnings = headerWarnings.Concat(payloadWarnings).Concat(signatureWarning).ToList();

        string? algorithm = null;
        if (header is not null)
        {
            algorithm = header["alg"]?.GetValue<string>();
            if (algorithm == "none")
                warnings.Add("This Token is unsigned (alg: none) — anyone can forge its contents.");
        }

        var timeClaims = payload is not null
            ? CollectTimeClaims(payload, warnings)
            : [];

        if (payloadJson is not null && timeClaims.Count == 0)
            warnings.Add("The Payload has no time Claims (exp, iat, nbf): this Token never expires.");

        return new DecodeResult(headerJson, payloadJson, parts[2], algorithm, timeClaims, warnings, null);
    }

    private static (string? Json, JsonObject? Obj, IEnumerable<string> Warnings) DecodePart(string part, string name)
    {
        var (obj, problem) = TokenPartReader.ReadJsonObject(part, name);
        return problem is not null
            ? (null, null, [problem])
            : (JsonSerializer.Serialize(obj, JsonOptions), obj, []);
    }

    private static List<TimeClaim> CollectTimeClaims(JsonObject payload, List<string> warnings)
    {
        var claims = new List<TimeClaim>();
        foreach (var name in TimeClaimNames)
        {
            if (payload.TryGetPropertyValue(name, out var node) &&
                node is JsonValue value && value.TryGetValue<long>(out var seconds))
            {
                var at = DateTimeOffset.FromUnixTimeSeconds(seconds);
                var now = DateTimeOffset.UtcNow;
                var isExpired = name == "exp" && at < now;
                var notYetValid = name == "nbf" && at > now;
                claims.Add(new TimeClaim(name, at, isExpired, notYetValid));
                if (isExpired)
                    warnings.Add($"The Token expired on {at:yyyy-MM-dd HH:mm:ss} UTC.");
            }
            else if (payload.ContainsKey(name))
            {
                warnings.Add($"The Claim '{name}' is present but not a numeric Unix timestamp.");
            }
        }
        return claims;
    }

    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };
}
