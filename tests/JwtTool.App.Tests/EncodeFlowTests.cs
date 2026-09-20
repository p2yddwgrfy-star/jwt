using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using JwtTool.App;
using JwtTool.TokenOperations;
using Xunit;

namespace JwtTool.App.Tests;

/// <summary>
/// Pins the Encode flow's public contract at its component seam: header, payload, and
/// Key in, the signed Token applied out (or the friendly error, or nothing while the
/// Key is missing). The RS256 signer delegate is the injectable seam the app wires to
/// Web Crypto; these tests substitute their own. The stale-response rule from the
/// glossary is pinned here: a newer request supersedes an older in-flight one, and a
/// stale response is never applied at all.
/// </summary>
public class EncodeFlowTests
{
    private const string Hs256Header = """{"alg":"HS256","typ":"JWT"}""";

    private static EncodeDraft Draft(string header = Hs256Header, string payload = """{"sub":"a"}""",
        string key = "a secret", SignatureAlgorithm algorithm = SignatureAlgorithm.HS256) =>
        new(header, payload, key, algorithm);

    private static EncodeFlow FlowWithSigner(RsaSignatureSigner signer) => new(signer);

    [Fact]
    public async Task Encoding_with_a_secret_applies_the_signed_token()
    {
        EncodeOutcome? applied = null;
        var flow = FlowWithSigner((_, _) => throw new UnreachableException("HS256 never signs through the RSA signer"));

        await flow.EncodeAsync(Draft(key: "a secret"), o => applied = o);

        Assert.NotNull(applied!.Token);
        Assert.Null(applied.Error);

        // The token is a real HS256 signature: the test computes the expected HMAC over
        // the token's own signing input — an independent truth, not the library's verdict.
        var parts = applied.Token.Split('.');
        Assert.Equal(3, parts.Length);
        var expected = new HMACSHA256(Encoding.UTF8.GetBytes("a secret"))
            .ComputeHash(Encoding.UTF8.GetBytes($"{parts[0]}.{parts[1]}"));
        Assert.Equal(expected, Base64UrlDecode(parts[2]));
    }

    [Fact]
    public async Task An_empty_key_applies_no_token_and_no_error()
    {
        EncodeOutcome? applied = new("old token", null);
        var flow = FlowWithSigner((_, _) => throw new UnreachableException("no key, no signing"));

        await flow.EncodeAsync(Draft(key: ""), o => applied = o);
        Assert.Null(applied!.Token);
        Assert.Null(applied.Error);

        await flow.EncodeAsync(Draft(key: "   "), o => applied = o);
        Assert.Null(applied!.Token);
        Assert.Null(applied.Error);
    }

    [Fact]
    public async Task An_invalid_header_applies_the_friendly_error_not_a_token()
    {
        EncodeOutcome? applied = null;
        var flow = FlowWithSigner((_, _) => throw new UnreachableException("never reached"));

        await flow.EncodeAsync(Draft(header: "not json"), o => applied = o);

        Assert.Null(applied!.Token);
        Assert.NotNull(applied.Error);
        Assert.Contains("Header", applied.Error);
    }

    [Fact]
    public async Task An_rs256_encode_uses_the_injected_signer_and_encodes_its_bytes()
    {
        EncodeOutcome? applied = null;
        string? seenSigningInput = null;
        string? seenPem = null;
        var flow = FlowWithSigner((signingInput, pem) =>
        {
            seenSigningInput = signingInput;
            seenPem = pem;
            return ValueTask.FromResult(new byte[] { 9, 8, 7 });
        });

        await flow.EncodeAsync(Draft(header: """{"alg":"RS256"}""", key: "a pem", algorithm: SignatureAlgorithm.RS256), o => applied = o);

        var headerJson = Encoding.UTF8.GetString(Base64UrlDecode(applied!.Token!.Split('.')[0]));
        Assert.Equal("""{"alg":"RS256"}""", System.Text.Json.Nodes.JsonNode.Parse(headerJson)!.ToJsonString());
        Assert.Equal("a pem", seenPem);
        Assert.Equal(new byte[] { 9, 8, 7 }, Base64UrlDecode(applied.Token.Split('.')[2]));
    }

    [Fact]
    public async Task A_stale_encode_response_is_never_applied()
    {
        var staleGate = new TaskCompletionSource<byte[]>();
        var firstCall = true;
        var flow = FlowWithSigner((_, _) =>
        {
            if (firstCall)
            {
                firstCall = false;
                return new ValueTask<byte[]>(staleGate.Task); // older request hangs in flight
            }
            return ValueTask.FromResult(new byte[] { 1 });
        });

        var rs256Draft = Draft(header: """{"alg":"RS256"}""", key: "a pem", algorithm: SignatureAlgorithm.RS256);
        EncodeOutcome? applied = null;
        var stale = flow.EncodeAsync(rs256Draft, o => applied = o);
        await flow.EncodeAsync(rs256Draft, o => applied = o);

        // The newer request's token is applied immediately…
        Assert.NotNull(applied!.Token);
        var latestToken = applied.Token;
        // …and when the older response finally lands, it applies nothing at all.
        staleGate.SetResult(new byte[] { 2 });
        await stale;
        Assert.Equal(latestToken, applied.Token);
    }

    private static byte[] Base64UrlDecode(string base64Url)
    {
        var base64 = base64Url.Replace('-', '+').Replace('_', '/');
        return Convert.FromBase64String(base64.PadRight(base64.Length + (4 - base64.Length % 4) % 4, '='));
    }
}
