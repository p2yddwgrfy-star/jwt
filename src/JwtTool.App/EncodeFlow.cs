using JwtTool.TokenOperations;

namespace JwtTool.App;

/// <summary>
/// The Encode draft: the editable header and payload JSON plus the Key and algorithm
/// to sign with. One value owned by the page, so it survives tab switches (#9).
/// </summary>
public sealed record EncodeDraft(string HeaderJson, string PayloadJson, string Key, SignatureAlgorithm Algorithm);

/// <summary>The outcome of an Encode attempt: the signed Token, or the friendly error.</summary>
internal sealed record EncodeOutcome(string? Token, string? Error)
{
    public static readonly EncodeOutcome NoKey = new(null, null);
}

/// <summary>
/// The Encode flow: header, payload, and Key in, the signed Token applied out — or the
/// friendly error, or nothing while the Key is missing. Owns the stale-response rule from
/// the glossary: a newer request supersedes an older in-flight one, never the reverse.
/// The RS256 signer is injected — the browser app wires it to Web Crypto, because WASM
/// has no RSA (ADR-0002).
/// </summary>
internal sealed class EncodeFlow(RsaSignatureSigner signRsaSignature)
{
    private readonly RsaSignatureSigner signRsa = signRsaSignature;
    private readonly RequestSequenceGuard guard = new();

    /// <summary>
    /// Encodes and signs the draft's Token, handing the outcome to <paramref name="apply"/> —
    /// <see cref="EncodeOutcome.NoKey"/> when the Key is empty, nothing to sign yet.
    /// A stale response applies nothing.
    /// </summary>
    public async Task EncodeAsync(EncodeDraft draft, Action<EncodeOutcome> apply)
    {
        if (draft.Key.Trim().Length == 0)
        {
            apply(EncodeOutcome.NoKey);
            return;
        }

        var requestId = guard.NextRequestId();
        try
        {
            var token = await TokenEncoder.EncodeAsync(draft.HeaderJson, draft.PayloadJson, draft.Algorithm, draft.Key.Trim(), signRsa);
            if (guard.IsLatest(requestId))
                apply(new EncodeOutcome(token, null));
        }
        catch (ArgumentException ex)
        {
            if (guard.IsLatest(requestId))
                apply(new EncodeOutcome(null, ex.Message));
            return;
        }
    }
}
