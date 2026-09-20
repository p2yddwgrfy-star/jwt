using System.Security.Cryptography;
using System.Text;
using JwtTool.App;
using JwtTool.TokenOperations;
using Xunit;

namespace JwtTool.App.Tests;

/// <summary>
/// Pins the Verify flow's public contract at its component seam: Token and Key in,
/// verdict applied out. The RS256 verifier delegate is the injectable seam the app wires
/// to Web Crypto; these tests substitute their own. The stale-response rule from the
/// glossary is pinned here: a newer request supersedes an older in-flight one, and a
/// stale response is never applied at all.
/// </summary>
public class VerifyFlowTests
{
    // Canonical jwt.io token signed with "your-256-bit-secret".
    private const string CanonicalToken =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

    private const string CanonicalSecret = "your-256-bit-secret";

    private static VerifyFlow FlowThat(bool verdict) =>
        new((_, _, _) => ValueTask.FromResult(verdict));

    [Fact]
    public async Task A_valid_token_and_secret_apply_a_valid_verdict()
    {
        VerifyResult? applied = null;
        var flow = FlowThat(verdict: false); // HS256 never reaches the RSA verifier

        await flow.VerifyAsync(CanonicalToken, SignatureAlgorithm.HS256, CanonicalSecret, v => applied = v);

        Assert.NotNull(applied);
        Assert.True(applied.IsValid);
    }

    [Fact]
    public async Task A_wrong_secret_applies_an_invalid_verdict()
    {
        VerifyResult? applied = null;
        var flow = FlowThat(verdict: false);

        await flow.VerifyAsync(CanonicalToken, SignatureAlgorithm.HS256, "not the secret", v => applied = v);

        Assert.NotNull(applied);
        Assert.False(applied.IsValid);
        Assert.NotNull(applied.Reason);
    }

    [Fact]
    public async Task An_empty_token_applies_no_verdict()
    {
        VerifyResult? applied = new(false, "stale leftover");
        var flow = FlowThat(verdict: true);

        await flow.VerifyAsync("", SignatureAlgorithm.HS256, CanonicalSecret, v => applied = v);
        await flow.VerifyAsync("   ", SignatureAlgorithm.HS256, CanonicalSecret, v => applied = v);

        Assert.Null(applied);
    }

    [Fact]
    public async Task An_empty_key_applies_no_verdict()
    {
        VerifyResult? applied = new(false, "stale leftover");
        var flow = FlowThat(verdict: true);

        await flow.VerifyAsync(CanonicalToken, SignatureAlgorithm.HS256, "", v => applied = v);
        await flow.VerifyAsync(CanonicalToken, SignatureAlgorithm.HS256, "  \t ", v => applied = v);

        Assert.Null(applied);
    }

    [Fact]
    public async Task A_token_without_three_parts_applies_no_verdict()
    {
        // The strict three-part pre-check keeps Verify from judging non-tokens:
        // no verdict, the hint keeps rendering.
        VerifyResult? applied = new(false, "stale leftover");
        var flow = FlowThat(verdict: false);

        await flow.VerifyAsync("garbage", SignatureAlgorithm.HS256, CanonicalSecret, v => applied = v);
        await flow.VerifyAsync("a.b.c.d", SignatureAlgorithm.HS256, CanonicalSecret, v => applied = v);

        Assert.Null(applied);
    }

    [Fact]
    public async Task An_rs256_verify_reaches_the_injected_verifier_with_the_right_pieces()
    {
        string? seenSigningInput = null;
        byte[]? seenSignature = null;
        string? seenPem = null;
        var flow = new VerifyFlow((signingInput, signature, pem) =>
        {
            seenSigningInput = signingInput;
            seenSignature = signature;
            seenPem = pem;
            return ValueTask.FromResult(true);
        });

        // header {"alg":"RS256"}, payload {"sub":"1"}, signature part "c2ln" ("sig").
        VerifyResult? applied = null;
        await flow.VerifyAsync(
            "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln", SignatureAlgorithm.RS256, "a pem", v => applied = v);

        Assert.True(applied!.IsValid);
        Assert.Equal("eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxIn0", seenSigningInput);
        Assert.Equal(Encoding.ASCII.GetBytes("sig"), seenSignature);
        Assert.Equal("a pem", seenPem);
    }

    [Fact]
    public async Task A_stale_response_is_never_applied()
    {
        // RS256 is the only path that genuinely awaits the verifier (HS256's HMAC is
        // synchronous), so the in-flight request must be an RS256 one.
        var token = MakeRs256Token();
        var staleGate = new TaskCompletionSource<bool>();
        var firstCall = true;
        var flow = new VerifyFlow((_, _, _) =>
        {
            if (firstCall)
            {
                firstCall = false;
                return new ValueTask<bool>(staleGate.Task); // older request hangs in flight
            }
            return ValueTask.FromResult(true);
        });

        VerifyResult? applied = new(false, "from the stale one");
        var stale = flow.VerifyAsync(token, SignatureAlgorithm.RS256, "a pem", v => applied = v);
        await flow.VerifyAsync(token, SignatureAlgorithm.RS256, "a pem", v => applied = v);

        // The newer request's verdict is applied immediately…
        Assert.True(applied!.IsValid);
        // …and when the older response finally lands, it applies nothing at all —
        // the displayed verdict stays exactly what the newest request decided.
        staleGate.SetResult(true);
        await stale;
        Assert.True(applied.IsValid);
    }

    /// <summary>A real RS256 token, signed with BCL crypto independent of the flow under test.</summary>
    private static string MakeRs256Token()
    {
        using var rsa = RSA.Create(2048);
        var header = Base64Url(Encoding.UTF8.GetBytes("""{"alg":"RS256","typ":"JWT"}"""));
        var payload = Base64Url(Encoding.UTF8.GetBytes("""{"sub":"flow"}"""));
        var signingInput = $"{header}.{payload}";
        var signature = rsa.SignData(Encoding.UTF8.GetBytes(signingInput), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return $"{signingInput}.{Base64Url(signature)}";
    }

    private static string Base64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
