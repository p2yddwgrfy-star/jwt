using JwtTool.TokenOperations;
using Xunit;

namespace JwtTool.TokenOperations.Tests;

/// <summary>
/// The Base64Url codec, tested directly: it is internal (this project sees it through
/// InternalsVisibleTo), a pure function, and its only public-API caller always encodes
/// non-empty bytes — so the empty-input branch is reachable only at this seam.
/// </summary>
public class Base64UrlTests
{
    [Fact]
    public void Encoding_empty_input_yields_an_empty_string()
    {
        // The missing condition combo of the padding-strip loop: nothing to strip,
        // nothing to emit.
        Assert.Equal("", Base64Url.Encode(Array.Empty<byte>()));
        Assert.Empty(Base64Url.DecodeToBytes(""));
    }

    [Fact]
    public void Encoding_a_single_byte_yields_two_unpadded_characters()
    {
        // 0xFB encodes to "+w==" with standard base64; unpadded and URL-safe: "-w".
        Assert.Equal("-w", Base64Url.Encode(new byte[] { 0xFB }));
    }

    [Fact]
    public void Encoding_swaps_the_url_unsafe_alphabet_and_strips_padding()
    {
        // 0xFF,0xEF,0xBF -> 6-bit groups 63,62,62,63 -> "/++/" in standard base64,
        // with '/'->'_' and '+'->'-'.
        Assert.Equal("_--_", Base64Url.Encode(new byte[] { 0xFF, 0xEF, 0xBF }));
    }

    [Theory]
    [InlineData(new byte[0])]
    [InlineData(new byte[] { 0xFB })]
    [InlineData(new byte[] { 0x66, 0x6F })]
    [InlineData(new byte[] { 0xFF, 0xEF, 0xBF })]
    [InlineData(new byte[] { 1, 2, 3 })]
    public void Encoding_then_decoding_round_trips_the_exact_bytes(byte[] bytes)
    {
        Assert.Equal(bytes, Base64Url.DecodeToBytes(Base64Url.Encode(bytes)));
    }

    [Fact]
    public void Decoding_accepts_padded_input()
    {
        Assert.Equal(new byte[] { 0xFB }, Base64Url.DecodeToBytes("-w=="));
    }

    [Fact]
    public void Decoding_input_with_an_invalid_length_throws()
    {
        // A 1-mod-4 length cannot be padded back to a valid base64 block.
        Assert.Throws<FormatException>(() => Base64Url.DecodeToBytes("A"));
    }
}
