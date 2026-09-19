using System.Text.Json;
using System.Text.Json.Nodes;

namespace JwtTool.TokenOperations;

/// <summary>
/// Reads a single Token part as a JSON object, the one shape both Decode and Verify need.
/// The Problem string is user-facing: Decode shows it as a Warning, Verify treats it as unreadable.
/// </summary>
internal static class TokenPartReader
{
    public static (JsonObject? Obj, string? Problem) ReadJsonObject(string part, string name)
    {
        if (part.Length == 0)
            return (null, $"The {name} part is empty.");

        string json;
        try
        {
            json = Base64Url.DecodeToString(part);
        }
        catch (FormatException)
        {
            return (null, $"The {name} part is not valid base64url.");
        }

        try
        {
            return JsonNode.Parse(json) is JsonObject obj
                ? (obj, null)
                : (null, $"The {name} part does not contain a JSON object.");
        }
        catch (JsonException)
        {
            return (null, $"The {name} part does not contain a JSON object.");
        }
    }
}
