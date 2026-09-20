using JwtTool.TokenOperations;

namespace JwtTool.App;

/// <summary>
/// The Verify flow: Token and Key in, verdict out (null when there is nothing to judge).
/// Owns the stale-response rule from the glossary: both async flows take a request id and
/// only apply their result if it is still the latest — a stale response is never applied,
/// not even as a clear. The RS256 verifier is injected — the browser app wires it to Web
/// Crypto, because WASM has no RSA (ADR-0002).
/// </summary>
internal sealed class VerifyFlow(RsaSignatureVerifier verifyRsaSignature)
{
    private readonly RsaSignatureVerifier verifyRsa = verifyRsaSignature;
    private readonly RequestSequenceGuard guard = new();

    /// <summary>
    /// Verifies the Token with the Key and hands the verdict to <paramref name="apply"/> —
    /// null when either is empty, nothing to judge yet. A stale response applies nothing.
    /// </summary>
    public async Task VerifyAsync(string token, SignatureAlgorithm algorithm, string key, Action<VerifyResult?> apply)
    {
        // No Key, or no Token (the trailing-dot rule applied): nothing to judge, so the
        // hint keeps rendering instead of a verdict.
        if (token.Trim().Length == 0 || key.Trim().Length == 0 || TokenParts.Of(token) is null)
        {
            apply(null);
            return;
        }

        var requestId = guard.NextRequestId();
        var result = await TokenVerifier.VerifyAsync(token.Trim(), algorithm, key.Trim(), verifyRsa);

        // RS256 verification awaits the browser's Web Crypto; a newer request supersedes
        // this one when the user keeps typing while it is in flight.
        if (guard.IsLatest(requestId))
            apply(result);
    }
}
