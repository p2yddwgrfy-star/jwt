using System.Security.Cryptography;
using System.Text;
using JwtTool.TokenOperations;
using Xunit;

namespace JwtTool.TokenOperations.Tests;

public class TokenVerifierRs256Tests
{
    private static readonly (string PrivatePem, string PublicPem) KeyPair = MakePemKeyPair();
    private static readonly (string PrivatePem, string PublicPem) OtherKeyPair = MakePemKeyPair();

    [Fact]
    public void Verify_rs256_token_with_its_private_key_pem_is_valid()
    {
        var token = SignRs256(KeyPair.PrivatePem, """{"sub":"rsa"}""");

        var result = TokenVerifier.Verify(token, SignatureAlgorithm.RS256, KeyPair.PrivatePem);

        Assert.True(result.IsValid);
        Assert.Null(result.Reason);
    }

    [Fact]
    public void Verify_rs256_token_with_its_public_key_pem_is_valid()
    {
        var token = SignRs256(KeyPair.PrivatePem, """{"sub":"rsa"}""");

        var result = TokenVerifier.Verify(token, SignatureAlgorithm.RS256, KeyPair.PublicPem);

        Assert.True(result.IsValid);
    }

    [Fact]
    public void Verify_rs256_token_with_a_different_key_is_invalid()
    {
        var token = SignRs256(KeyPair.PrivatePem, """{"sub":"rsa"}""");

        var result = TokenVerifier.Verify(token, SignatureAlgorithm.RS256, OtherKeyPair.PrivatePem);

        Assert.False(result.IsValid);
        Assert.NotNull(result.Reason);
    }

    [Fact]
    public void Verify_rs256_with_a_non_pem_key_reports_the_key_problem_not_a_signature_mismatch()
    {
        var token = SignRs256(KeyPair.PrivatePem, """{"sub":"rsa"}""");

        var result = TokenVerifier.Verify(token, SignatureAlgorithm.RS256, "this is not a pem");

        Assert.False(result.IsValid);
        Assert.Contains("PEM", result.Reason);
    }

    /// Signs with the BCL RSA implementation directly — an independent path from TokenVerifier's.
    private static string SignRs256(string privatePem, string payloadJson)
    {
        using var rsa = RSA.Create();
        rsa.ImportFromPem(privatePem);
        var header = Encode("""{"alg":"RS256","typ":"JWT"}""");
        var payload = Encode(payloadJson);
        var sig = rsa.SignData(Encoding.UTF8.GetBytes($"{header}.{payload}"),
            System.Security.Cryptography.HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
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
