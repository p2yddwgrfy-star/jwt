using System.Security.Cryptography;
using JwtTool.TokenOperations;
using Xunit;

namespace JwtTool.TokenOperations.Tests;

public class TokenEncoderRs256KeyGuardTests
{
    [Fact]
    public void Encode_rs256_with_a_public_key_pem_throws_a_friendly_error()
    {
        using var rsa = RSA.Create(2048);
        var publicPem = rsa.ExportSubjectPublicKeyInfoPem();

        var ex = Assert.Throws<ArgumentException>(
            () => TokenEncoder.Encode("""{"alg":"RS256","typ":"JWT"}""", """{"sub":"a"}""", SignatureAlgorithm.RS256, publicPem));

        Assert.Contains("private key", ex.Message);
    }

    [Fact]
    public void Encode_rs256_with_a_private_key_pem_still_signs()
    {
        using var rsa = RSA.Create(2048);
        var privatePem = rsa.ExportPkcs8PrivateKeyPem();

        var token = TokenEncoder.Encode("""{"alg":"RS256","typ":"JWT"}""", """{"sub":"a"}""", SignatureAlgorithm.RS256, privatePem);

        Assert.Equal(3, token.Split('.').Length);
    }
}
