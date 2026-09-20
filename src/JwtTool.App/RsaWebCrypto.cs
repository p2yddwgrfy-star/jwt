using System.Security.Cryptography;
using Microsoft.JSInterop;

namespace JwtTool.App;

/// <summary>
/// RS256 signature verification through the browser's Web Crypto.
/// .NET's RSA implementation is unavailable on browser WebAssembly, so the app delegates
/// the RSA operation to crypto.subtle — the browser's audited implementation — which also
/// keeps the key material inside the browser (ADR-0001, ADR-0002).
/// </summary>
internal static class RsaWebCrypto
{
    public static async Task<bool> VerifyAsync(IJSRuntime js, string signingInput, byte[] signature, string pem)
    {
        try
        {
            return await js.InvokeAsync<bool>("jwtRsa.verify", signingInput, signature, pem);
        }
        catch (JSException ex)
        {
            // The library translates this into the friendly "key could not be read" verdict.
            throw new CryptographicException("The browser's Web Crypto could not read this PEM key.", ex);
        }
    }
}
