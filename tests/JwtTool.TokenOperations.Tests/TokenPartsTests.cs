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
}
