namespace JwtTool.TokenOperations;

/// <summary>
/// The one place that knows how to read a Token's parts from raw input:
/// trims the input, tolerates exactly one trailing dot (a paste artifact),
/// and accepts only the three-part compact form.
/// </summary>
public static class TokenParts
{
    /// <summary>
    /// Returns the Token's three parts, or null when the input is not a
    /// three-part Token (beyond the tolerated single trailing dot).
    /// </summary>
    public static string[]? Of(string input)
    {
        var parts = input.Trim().Split('.');
        if (parts.Length == 4 && parts[3].Length == 0)
            parts = parts[..3]; // a single trailing dot is a paste artifact, not a fourth part
        return parts.Length == 3 ? parts : null;
    }
}
