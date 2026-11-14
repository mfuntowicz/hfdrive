namespace HfDrive.Protocol;

/// <summary>Event stream contract: one ordered stream of decoded events.</summary>
public interface IProtocolEventStream
{
    /// <summary>
    /// Reads events in order. Implementations re-issue
    /// <c>subscribe_status</c> automatically after a sequence gap and yield the
    /// resulting snapshot event. The stream ends when the connection closes.
    /// </summary>
    IAsyncEnumerable<ProtocolEvent> ReadEventsAsync(CancellationToken cancellationToken = default);
}
