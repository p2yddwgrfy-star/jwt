namespace JwtTool.TokenOperations;

public sealed class RequestSequenceGuard
{
    private int latestRequestId;

    public int NextRequestId() => ++latestRequestId;

    public bool IsLatest(int requestId) => requestId == latestRequestId;
}
