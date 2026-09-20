using JwtTool.TokenOperations;
using Xunit;

namespace JwtTool.TokenOperations.Tests;

public class TokenPartsTests
{
    [Fact]
    public void Of_a_three_part_token_returns_the_parts()
    {
        var parts = TokenParts.Of("h.p.s");

        Assert.Equal(["h", "p", "s"], parts);
    }

    [Fact]
    public void Of_tolerates_exactly_one_trailing_dot()
    {
        var parts = TokenParts.Of("h.p.s.");

        Assert.Equal(["h", "p", "s"], parts);
    }

    [Fact]
    public void Of_rejects_two_part_input()
    {
        Assert.Null(TokenParts.Of("h.p"));
    }

    [Fact]
    public void Of_rejects_a_fourth_nonempty_part()
    {
        Assert.Null(TokenParts.Of("h.p.s.x"));
    }

    [Fact]
    public void Of_rejects_more_than_one_trailing_dot()
    {
        Assert.Null(TokenParts.Of("h.p.s.."));
    }

    [Fact]
    public void Of_trims_surrounding_whitespace()
    {
        // Paste artifacts carry leading/trailing spaces and newlines.
        var parts = TokenParts.Of("  h.p.s\r\n");

        Assert.Equal(["h", "p", "s"], parts);
    }

    [Fact]
    public void Of_leaves_inner_whitespace_in_place()
    {
        // Only the input's edges are trimmed; the parts themselves are untouched.
        var parts = TokenParts.Of("h . p . s");

        Assert.Equal(["h ", " p ", " s"], parts);
    }

    [Fact]
    public void Split_returns_the_parts_and_their_count_for_a_valid_token()
    {
        var split = TokenParts.Split("h.p.s");

        Assert.Equal(["h", "p", "s"], split.Parts);
        Assert.Equal(3, split.RawPartCount);
    }

    [Fact]
    public void Split_reports_the_raw_part_count_for_invalid_input()
    {
        var twoParts = TokenParts.Split("h.p");
        Assert.Null(twoParts.Parts);
        Assert.Equal(2, twoParts.RawPartCount);

        var fourParts = TokenParts.Split("h.p.s.x");
        Assert.Null(fourParts.Parts);
        Assert.Equal(4, fourParts.RawPartCount);

        // The tolerated single trailing dot collapses before counting:
        var trailingDot = TokenParts.Split("h.p.s.");
        Assert.Equal(new[] { "h", "p", "s" }, trailingDot.Parts);
        Assert.Equal(3, trailingDot.RawPartCount);
    }
}
