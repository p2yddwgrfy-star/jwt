using System.Security.Cryptography;
using JwtTool.App;
using Microsoft.JSInterop;
using Xunit;

namespace JwtTool.App.Tests;

/// <summary>
/// Pins the interop boundary RsaWebCrypto owns: the browser's raw JSException becomes the
/// friendly CryptographicException the library translates into verdicts/errors — the seam
/// where the #31 deserialization failure hid behind the catch. Values pass through
/// unchanged (bool for verify, byte[] for sign); anything that is not a JSException
/// propagates unwrapped.
/// </summary>
public class RsaWebCryptoTests
{
    [Fact]
    public async Task VerifyAsync_translates_a_JSException_into_the_friendly_CryptographicException()
    {
        var js = ThrowingJs("jwtRsa.verify", new JSException("boom"));

        var ex = await Assert.ThrowsAsync<CryptographicException>(
            () => RsaWebCrypto.VerifyAsync(js, "a.b", [1, 2, 3], "pem"));

        Assert.Contains("Web Crypto", ex.Message);
        Assert.Contains("PEM", ex.Message);
    }

    [Fact]
    public async Task SignAsync_translates_a_JSException_into_the_friendly_CryptographicException()
    {
        var js = ThrowingJs("jwtRsa.sign", new JSException("boom"));

        var ex = await Assert.ThrowsAsync<CryptographicException>(
            () => RsaWebCrypto.SignAsync(js, "a.b", "pem"));

        Assert.Contains("Web Crypto", ex.Message);
        Assert.Contains("signing", ex.Message);
    }

    [Fact]
    public async Task VerifyAsync_passes_the_browser_verdict_through_unchanged()
    {
        var js = StubJs("jwtRsa.verify", true);

        Assert.True(await RsaWebCrypto.VerifyAsync(js, "a.b", [1, 2, 3], "pem"));
    }

    [Fact]
    public async Task SignAsync_passes_the_signature_bytes_through_unchanged()
    {
        var signature = new byte[] { 9, 8, 7 };
        var js = StubJs("jwtRsa.sign", signature);

        Assert.Equal(signature, await RsaWebCrypto.SignAsync(js, "a.b", "pem"));
    }

    [Fact]
    public async Task A_non_JS_exception_is_not_swallowed_into_the_friendly_message()
    {
        // If the catch is ever widened, a programming error would masquerade as a key
        // problem — the exact failure mode #31 punished. The mapping must stay narrow.
        var js = ThrowingJs("jwtRsa.sign", new InvalidOperationException("a bug"));

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => RsaWebCrypto.SignAsync(js, "a.b", "pem"));
        Assert.Equal("a bug", ex.Message);
    }

    /// <summary>An IJSRuntime stub that records the identifier and returns a fixed result.</summary>
    private sealed class StubRuntime(string expectedId, object? result) : IJSRuntime
    {
        public ValueTask<TValue> InvokeAsync<TValue>(string identifier, CancellationToken cancellationToken, object?[]? args)
        {
            Assert.Equal(expectedId, identifier);
            return ValueTask.FromResult((TValue)result!);
        }

        public ValueTask<TValue> InvokeAsync<TValue>(string identifier, object?[]? args) =>
            InvokeAsync<TValue>(identifier, CancellationToken.None, args);
    }

    /// <summary>An IJSRuntime stub whose invocation throws the given exception.</summary>
    private sealed class ThrowingRuntime(string expectedId, Exception exception) : IJSRuntime
    {
        public ValueTask<TValue> InvokeAsync<TValue>(string identifier, CancellationToken cancellationToken, object?[]? args)
        {
            Assert.Equal(expectedId, identifier);
            throw exception;
        }

        public ValueTask<TValue> InvokeAsync<TValue>(string identifier, object?[]? args) =>
            InvokeAsync<TValue>(identifier, CancellationToken.None, args);
    }

    private static IJSRuntime StubJs(string id, object? result) => new StubRuntime(id, result);

    private static IJSRuntime ThrowingJs(string id, Exception exception) => new ThrowingRuntime(id, exception);
}
