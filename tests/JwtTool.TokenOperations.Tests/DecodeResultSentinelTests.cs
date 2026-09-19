using JwtTool.TokenOperations;
using Xunit;

namespace JwtTool.TokenOperations.Tests;

public class DecodeResultSentinelTests
{
    [Fact]
    public void The_Unparseable_sentinel_reports_itself_as_unparseable()
    {
        Assert.True(DecodeResult.Unparseable.IsUnparseable);
        Assert.NotNull(DecodeResult.Unparseable.ParseError);
    }
}
