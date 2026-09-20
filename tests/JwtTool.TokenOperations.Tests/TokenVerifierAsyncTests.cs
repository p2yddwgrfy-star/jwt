using System.Security.Cryptography;
using System.Text;
using JwtTool.TokenOperations;
using Xunit;

namespace JwtTool.TokenOperations.Tests;

/// <summary>
/// Pins the async Verify seam the browser (Blazor WASM) needs: .NET has no RSA on
/// browser WebAssembly, so the app supplies a Web Crypto-backed RsaSignatureVerifier.
/// The strict pre-checks stay in TokenVerifier — the delegate only decides signatures.
/// </summary>
public class TokenVerifierAsyncTests
{
    private static readonly (string PrivatePem, string PublicPem) KeyPair = MakePemKeyPair();

    [Fact]
    public async Task VerifyAsync_rs256_with_a_verifying_delegate_is_valid()
    {
        var token = SignRs256(KeyPair.PrivatePem);

        var result = await TokenVerifier.VerifyAsync(
            token, SignatureAlgorithm.RS256, KeyPair.PublicPem, (_, _, _) => ValueTask.FromResult(true));

        Assert.True(result.IsValid);
    }

    [Fact]
    public async Task VerifyAsync_rs256_with_a_failing_delegate_is_invalid_with_the_mismatch_reason()
    {
        var token = SignRs256(KeyPair.PrivatePem);

        var result = await TokenVerifier.VerifyAsync(
            token, SignatureAlgorithm.RS256, KeyPair.PublicPem, (_, _, _) => ValueTask.FromResult(false));

        Assert.False(result.IsValid);
        Assert.Contains("does not match", result.Reason);
    }

    [Fact]
    public async Task VerifyAsync_a_throwing_delegate_reports_the_key_problem_not_a_crash()
    {
        var token = SignRs256(KeyPair.PrivatePem);

        var result = await TokenVerifier.VerifyAsync(
            token, SignatureAlgorithm.RS256, "not a pem",
            (_, _, _) => throw new CryptographicException("unreadable"));

        Assert.False(result.IsValid);
        Assert.Contains("PEM", result.Reason);
    }

    [Fact]
    public async Task VerifyAsync_still_cross_checks_the_header_algorithm_before_the_delegate()
    {
        var token = SignRs256(KeyPair.PrivatePem); // header says alg RS256
        var delegateCalled = false;

        var result = await TokenVerifier.VerifyAsync(
            token, SignatureAlgorithm.HS256, "whatever",
            (_, _, _) =>
            {
                delegateCalled = true;
                return ValueTask.FromResult(true);
            });

        Assert.False(result.IsValid);
        Assert.Contains("RS256", result.Reason); // the mismatch names both algorithms
        Assert.False(delegateCalled); // the RSA delegate is never reached
    }

    [Fact]
    public async Task VerifyAsync_hs256_without_a_delegate_verifies_the_signature()
    {
        var token = SignHs256("your-256-bit-secret", """{"sub":"hs"}""");

        var result = await TokenVerifier.VerifyAsync(token, SignatureAlgorithm.HS256, "your-256-bit-secret");

        Assert.True(result.IsValid);
    }

    [Fact]
    public async Task VerifyAsync_with_the_default_verifier_matches_the_sync_Verify_on_this_platform()
    {
        var token = SignRs256(KeyPair.PrivatePem);

        var sync = TokenVerifier.Verify(token, SignatureAlgorithm.RS256, KeyPair.PublicPem);
        var async = await TokenVerifier.VerifyAsync(token, SignatureAlgorithm.RS256, KeyPair.PublicPem);

        Assert.Equal(sync.IsValid, async.IsValid);
        Assert.True(async.IsValid); // BCL RSA works here — the default is a real verification
    }

    /// <summary>Signs with the BCL RSA implementation directly — independent of TokenVerifier.</summary>
    private static string SignRs256(string privatePem)
    {
        using var rsa = RSA.Create();
        rsa.ImportFromPem(privatePem);
        var header = Encode("""{"alg":"RS256","typ":"JWT"}""");
        var payload = Encode("""{"sub":"async-rs256"}""");
        var sig = rsa.SignData(Encoding.UTF8.GetBytes($"{header}.{payload}"),
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return $"{header}.{payload}.{Encode(sig)}";
    }

    private static string SignHs256(string secret, string payloadJson)
    {
        var header = Encode("""{"alg":"HS256","typ":"JWT"}""");
        var payload = Encode(payloadJson);
        var sig = new HMACSHA256(Encoding.UTF8.GetBytes(secret))
            .ComputeHash(Encoding.UTF8.GetBytes($"{header}.{payload}"));
        return $"{header}.{payload}.{Encode(sig)}";
    }

    private static (string PrivatePem, string PublicPem) MakePemKeyPair()
    {
        using var rsa = RSA.Create(2048);
        return (rsa.ExportPkcs8PrivateKeyPem(), rsa.ExportSubjectPublicKeyInfoPem());
    }

    private static string Encode(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static string Encode(string s) => Encode(Encoding.UTF8.GetBytes(s));
}
