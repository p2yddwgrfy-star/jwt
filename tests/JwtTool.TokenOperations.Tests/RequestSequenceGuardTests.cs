using JwtTool.TokenOperations;
using Xunit;

namespace JwtTool.TokenOperations.Tests;

public class RequestSequenceGuardTests
{
    [Fact]
    public void Latest_request_id_stays_current_when_older_requests_finish_later()
    {
        var guard = new RequestSequenceGuard();

        var first = guard.NextRequestId();
        var second = guard.NextRequestId();

        Assert.True(guard.IsLatest(second));
        Assert.False(guard.IsLatest(first));
    }
}
