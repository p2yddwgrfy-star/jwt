using System.Text;

namespace JwtTool.TokenOperations;

/// <summary>Base64url codec for Token parts: unpadded, URL-safe alphabet, tolerant of padding on input.</summary>
internal static class Base64Url
{
    public static string Encode(byte[] bytes)
    {
        var s = Convert.ToBase64String(bytes);
        var end = s.Length;
        while (end > 0 && s[end - 1] == '=') end--;
        Span<char> buf = stackalloc char[end];
        for (var i = 0; i < end; i++)
            buf[i] = s[i] switch { '+' => '-', '/' => '_', var c => c };
        return new string(buf);
    }

    /// <summary>Decodes a base64url part. Padding is accepted; other malformed input throws FormatException.</summary>
    public static byte[] DecodeToBytes(string s)
    {
        var padded = (s.Length % 4) switch
        {
            0 => s,
            2 => s + "==",
            3 => s + "=",
            _ => throw new FormatException("Invalid base64url length."),
        };
        return Convert.FromBase64String(padded.Replace('-', '+').Replace('_', '/'));
    }

    public static string DecodeToString(string s) => Encoding.UTF8.GetString(DecodeToBytes(s));
}
