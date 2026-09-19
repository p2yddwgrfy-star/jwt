using Microsoft.JSInterop;

namespace JwtTool.App;

/// <summary>Writes text to the browser clipboard, reporting failure instead of throwing.</summary>
internal static class Clipboard
{
    /// <summary>Copies the text and returns the user-facing status message.</summary>
    public static async Task<string> CopyAsync(IJSRuntime js, string text)
    {
        try
        {
            await js.InvokeVoidAsync("navigator.clipboard.writeText", text);
            return "Copied.";
        }
        catch (JSException)
        {
            return "Copy failed — your browser blocked clipboard access. Select the text manually.";
        }
    }
}
