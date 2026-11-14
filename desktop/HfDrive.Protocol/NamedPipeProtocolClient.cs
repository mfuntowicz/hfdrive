using System.Collections.Concurrent;
using System.IO.Pipes;
using System.Runtime.CompilerServices;
using System.Threading.Channels;

namespace HfDrive.Protocol;

/// <summary>
/// Server peer validation hook. The client runs this immediately after the
/// pipe connects and <b>before any byte is written</b> (including the hello
/// request and any secret material). The desktop interop layer implements the
/// provider PID/token/package checks here.
/// </summary>
public interface IServerAuthenticator
{
    /// <summary>
    /// Validates the connected server process. Throwing aborts the connection
    /// before any protocol data is sent.
    /// </summary>
    ValueTask AuthenticateAsync(NamedPipeClientStream connection, CancellationToken cancellationToken);
}

/// <summary>Configuration for <see cref="NamedPipeProtocolClient"/>.</summary>
public sealed record NamedPipeProtocolClientOptions
{
    /// <summary>Named pipe name (without the \\.\pipe\ prefix).</summary>
    public required string PipeName { get; init; }

    /// <summary>
    /// When true (default), an <see cref="IServerAuthenticator"/> must be
    /// supplied and must succeed before any byte is written.
    /// </summary>
    public bool RequireServerAuthentication { get; init; } = true;

    /// <summary>Bound on concurrently pending requests (default 128).</summary>
    public int MaxPendingRequests { get; init; } = ProtocolConstants.DefaultMaxPendingRequests;

    /// <summary>Bound on buffered events awaiting the single consumer.</summary>
    public int EventChannelCapacity { get; init; } = 4096;

    /// <summary>Pipe connect timeout (default 30 s).</summary>
    public TimeSpan ConnectTimeout { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>Per-request timeout; <see cref="TimeSpan.Zero"/> disables it.</summary>
    public TimeSpan RequestTimeout { get; init; } = TimeSpan.FromSeconds(60);

    /// <summary>Client build version announced in hello.</summary>
    public string BuildVersion { get; init; } = "0.1.0";

    /// <summary>Client role announced in hello.</summary>
    public ClientRole Role { get; init; } = ClientRole.Desktop;
}

/// <summary>
/// A real named-pipe IPC client for the HF Drive provider: strict envelope
/// codec, request/response correlation by <c>request_id</c>, cancellation
/// support, a bounded pending-request table and a single ordered status-event
/// stream with automatic resubscribe after sequence gaps.
/// </summary>
public sealed class NamedPipeProtocolClient : IProtocolEventStream, IAsyncDisposable
{
    private readonly NamedPipeProtocolClientOptions _options;
    private readonly ConcurrentDictionary<Guid, TaskCompletionSource<Envelope>> _pending = new();
    private readonly SemaphoreSlim _sendLock = new(1, 1);
    private readonly Channel<ProtocolEvent> _events;
    private readonly CancellationTokenSource _lifetime = new();

    private Stream? _stream;
    private Task? _readerLoop;
    private volatile bool _ready;
    private volatile bool _helloSent;
    private volatile bool _eventGap;
    private long _pendingCount;

    /// <summary>Creates a client for the given options.</summary>
    public NamedPipeProtocolClient(NamedPipeProtocolClientOptions options)
    {
        _options = options;
        _events = Channel.CreateBounded<ProtocolEvent>(new BoundedChannelOptions(Math.Max(1, options.EventChannelCapacity))
        {
            SingleReader = true,
            SingleWriter = true,
            FullMode = BoundedChannelFullMode.Wait,
        });
    }

    /// <summary>True once the pipe is connected and server-validated.</summary>
    public bool IsConnected => _stream is not null && !_lifetime.IsCancellationRequested;

    /// <summary>True once the hello exchange completed successfully.</summary>
    public bool IsReady => _ready;

    /// <summary>
    /// Connects the pipe, runs the server authenticator (before any byte is
    /// written) and starts the response/event reader loop.
    /// </summary>
    public async Task ConnectAsync(IServerAuthenticator? authenticator, CancellationToken cancellationToken = default)
    {
        if (_stream is not null)
        {
            throw new InvalidOperationException("client is already connected");
        }
        if (_options.RequireServerAuthentication && authenticator is null)
        {
            throw new InvalidOperationException("server authentication is required but no authenticator was supplied");
        }

        var pipe = new NamedPipeClientStream(
            serverName: ".",
            pipeName: _options.PipeName,
            direction: PipeDirection.InOut,
            options: PipeOptions.Asynchronous);

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _lifetime.Token);
        timeout.CancelAfter(_options.ConnectTimeout);
        try
        {
            await pipe.ConnectAsync(timeout.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            await pipe.DisposeAsync().ConfigureAwait(false);
            throw new ProtocolException(ProtocolErrorCode.Timeout, "timed out connecting to the provider pipe");
        }

        if (authenticator is not null)
        {
            try
            {
                await authenticator.AuthenticateAsync(pipe, timeout.Token).ConfigureAwait(false);
            }
            catch
            {
                await pipe.DisposeAsync().ConfigureAwait(false);
                throw;
            }
        }

        _stream = pipe;
        _readerLoop = Task.Run(() => ReaderLoopAsync(_lifetime.Token), CancellationToken.None);
    }

    /// <summary>
    /// Connects over an already-authenticated bidirectional stream. The caller
    /// is responsible for peer validation before invoking this (used by the
    /// Windows adapter's authenticated pipe streams and by in-memory tests);
    /// the client still writes nothing before <c>hello</c>.
    /// </summary>
    public Task ConnectAsync(Stream transport, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(transport);
        if (!transport.CanRead || !transport.CanWrite)
        {
            throw new ArgumentException("transport must be readable and writable", nameof(transport));
        }
        if (_stream is not null)
        {
            throw new InvalidOperationException("client is already connected");
        }
        _stream = transport;
        _readerLoop = Task.Run(() => ReaderLoopAsync(_lifetime.Token), CancellationToken.None);
        return Task.CompletedTask;
    }

    /// <summary>
    /// Performs the mandatory hello exchange (the first command on a
    /// connection). Passing null uses the options' role and build version.
    /// </summary>
    public Task<HelloResult> HelloAsync(HelloRequest? request = null, CancellationToken cancellationToken = default)
    {
        request ??= new HelloRequest
        {
            ProtocolMajor = ProtocolConstants.ProtocolMajor,
            ProtocolMinor = ProtocolConstants.ProtocolMinor,
            Role = _options.Role,
            BuildVersion = _options.BuildVersion,
        };
        return SendCoreAsync<HelloRequest, HelloResult>(
            Commands.Hello.Method, request, allowBeforeHello: true, cancellationToken);
    }

    /// <summary>Sends a typed command and returns its typed result.</summary>
    public Task<TResult> SendAsync<TRequest, TResult>(
        CommandSpec<TRequest, TResult> spec, TRequest request, CancellationToken cancellationToken = default)
        where TRequest : notnull =>
        SendCoreAsync<TRequest, TResult>(spec.Method, request, allowBeforeHello: false, cancellationToken);

    /// <summary>
    /// Requests cancellation of an in-flight request. The caller's own task is
    /// also cancelled independently; this only notifies the provider.
    /// </summary>
    public Task<CancelRequestResult> CancelAsync(Guid targetRequestId, CancellationToken cancellationToken = default) =>
        SendCoreAsync<CancelRequestRequest, CancelRequestResult>(
            Commands.CancelRequest.Method,
            new CancelRequestRequest { TargetRequestId = targetRequestId },
            allowBeforeHello: false,
            cancellationToken);

    private async Task<TResult> SendCoreAsync<TRequest, TResult>(
        string method, TRequest request, bool allowBeforeHello, CancellationToken cancellationToken)
        where TRequest : notnull
    {
        var stream = _stream ?? throw new ProtocolException(ProtocolErrorCode.Closed, "client is not connected");
        if (!allowBeforeHello && !_helloSent)
        {
            throw new InvalidOperationException("hello must be the first command on a connection");
        }
        if (_helloSent && allowBeforeHello)
        {
            throw new InvalidOperationException("hello was already sent");
        }
        if (Interlocked.Increment(ref _pendingCount) > _options.MaxPendingRequests)
        {
            Interlocked.Decrement(ref _pendingCount);
            throw new ProtocolException(ProtocolErrorCode.Busy, "too many pending requests");
        }

        Guid requestId = Guid.Empty;

        try
        {
            requestId = Guid.NewGuid();
            var envelope = Envelope.Request(requestId, method, request);
            var completion = new TaskCompletionSource<Envelope>(TaskCreationOptions.RunContinuationsAsynchronously);
            if (!_pending.TryAdd(requestId, completion))
            {
                throw new ProtocolException(ProtocolErrorCode.Internal, "request id collision");
            }
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _lifetime.Token);
            if (_options.RequestTimeout > TimeSpan.Zero)
            {
                timeout.CancelAfter(_options.RequestTimeout);
            }
            var payload = envelope.ToCanonicalBytes();
            await _sendLock.WaitAsync(timeout.Token).ConfigureAwait(false);
            try
            {
                await FrameCodec.WriteFrameAsync(stream, payload, timeout.Token).ConfigureAwait(false);
            }
            catch (Exception writeFailure) when (writeFailure is not OperationCanceledException)
            {
                // A failed write may have emitted a partial frame: the stream
                // can no longer be trusted, close the connection.
                await CloseAsync().ConfigureAwait(false);
                throw new ProtocolException(ProtocolErrorCode.Closed, "connection lost while sending");
            }
            catch (OperationCanceledException)
            {
                // A cancelled write may have emitted a partial frame too: the
                // frame boundary is unknown, close the connection.
                await CloseAsync().ConfigureAwait(false);
                throw;
            }
            finally
            {
                _sendLock.Release();
            }

            Envelope response;
            try
            {
                response = await completion.Task.WaitAsync(timeout.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                // Cancelling the caller stops this request's work; notify the
                // provider on a best-effort basis so it can stop the operation.
                _ = TrySendCancelAsync(requestId);
                throw;
            }
            catch (OperationCanceledException) when (_lifetime.IsCancellationRequested)
            {
                throw new ProtocolException(ProtocolErrorCode.Closed, "connection closed");
            }
            catch (OperationCanceledException)
            {
                _ = TrySendCancelAsync(requestId);
                throw new ProtocolException(ProtocolErrorCode.Timeout, $"request {method} timed out");
            }

            if (response.Method != method)
            {
                throw new ProtocolException(ProtocolErrorCode.MalformedFrame, "response method does not match the request");
            }
            if (response.Kind != EnvelopeKind.Response)
            {
                throw new ProtocolException(ProtocolErrorCode.MalformedFrame, "unexpected envelope kind");
            }
            if (response.Body.TryGetProperty("error", out _))
            {
                throw new ProtocolException(response.GetError());
            }
            var result = response.GetResult<TResult>();
            if (method == Commands.Hello.Method)
            {
                _helloSent = true;
                _ready = true;
            }
            return result;
        }
        finally
        {
            if (_pending.TryRemove(requestId, out var stale))
            {
                stale.TrySetCanceled(CancellationToken.None);
            }
            // Only the sending operation releases admission, including encoding failures.
            Interlocked.Decrement(ref _pendingCount);
        }
    }

    private async Task TrySendCancelAsync(Guid targetRequestId)
    {
        try
        {
            var envelope = Envelope.Request(
                Guid.NewGuid(),
                Commands.CancelRequest.Method,
                new CancelRequestRequest { TargetRequestId = targetRequestId });
            var payload = envelope.ToCanonicalBytes();
            if (_sendLock.Wait(0))
            {
                try
                {
                    if (_stream is { } stream)
                    {
                        await FrameCodec.WriteFrameAsync(stream, payload, _lifetime.Token).ConfigureAwait(false);
                    }
                }
                finally
                {
                    _sendLock.Release();
                }
            }
        }
        catch
        {
            // Best effort only: the connection may be closing.
        }
    }

    private async Task ReaderLoopAsync(CancellationToken cancellationToken)
    {
        Exception? failure = null;
        try
        {
            while (!cancellationToken.IsCancellationRequested && _stream is { } pipe)
            {
                var payload = await FrameCodec.ReadFrameAsync(pipe, cancellationToken).ConfigureAwait(false);
                if (payload is null)
                {
                    break;
                }
                Dispatch(Envelope.Parse(payload));
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
        catch (Exception error)
        {
            failure = error;
        }
        finally
        {
            _ready = false;
            FailAllPending(failure ?? new ProtocolException(ProtocolErrorCode.Closed, "provider closed the connection"));
            _events.Writer.TryComplete(failure);
            _lifetime.Cancel();
        }
    }

    private void Dispatch(Envelope envelope)
    {
        switch (envelope.Kind)
        {
            case EnvelopeKind.Response:
                if (_pending.TryRemove(envelope.RequestId, out var completion))
                {
                    completion.TrySetResult(envelope);
                }
                // Late responses to cancelled requests are dropped.
                break;

            case EnvelopeKind.Event:
                var decoded = DecodeEvent(envelope);
                if (decoded is not null && !_events.Writer.TryWrite(decoded))
                {
                    // Consumer is behind: remember the gap so the stream
                    // resubscribes for a full snapshot.
                    _eventGap = true;
                }
                break;

            default:
                throw new ProtocolException(ProtocolErrorCode.MalformedFrame, "unexpected envelope kind from the provider");
        }
    }

    private static ProtocolEvent? DecodeEvent(Envelope envelope)
    {
        var eventId = envelope.RequestId;
        switch (envelope.Method)
        {
            case "status_changed":
                var status = envelope.GetEventPayload<StatusChangedEvent>();
                return new StatusChangedProtocolEvent { EventId = eventId, Sequence = status.Sequence, Data = status };
            case "activity_changed":
                var activity = envelope.GetEventPayload<ActivityChangedEvent>();
                return new ActivityChangedProtocolEvent { EventId = eventId, Sequence = activity.Sequence, Data = activity };
            case "conflicts_changed":
                var conflicts = envelope.GetEventPayload<ConflictsChangedEvent>();
                return new ConflictsChangedProtocolEvent { EventId = eventId, Sequence = conflicts.Sequence, Data = conflicts };
            default:
                return null; // unknown events from a future minor are ignored
        }
    }

    private void FailAllPending(Exception error)
    {
        foreach (var entry in _pending)
        {
            if (_pending.TryRemove(entry.Key, out var completion))
            {
                completion.TrySetException(error);
            }
        }
    }

    /// <summary>
    /// Reads the single ordered event stream. A detected sequence gap (or a
    /// locally dropped event) triggers an automatic <c>subscribe_status</c>
    /// resubscription whose snapshot is yielded as a
    /// <see cref="StatusChangedProtocolEvent"/> with <c>Snapshot = true</c>.
    /// Only one consumer may read at a time.
    /// </summary>
    public async IAsyncEnumerable<ProtocolEvent> ReadEventsAsync([EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        ulong lastSequence = 0;
        var haveSequence = false;

        await foreach (var protocolEvent in _events.Reader.ReadAllAsync(cancellationToken).ConfigureAwait(false))
        {
            var isSnapshot = protocolEvent is StatusChangedProtocolEvent status && status.Data.Snapshot;
            if (haveSequence && !isSnapshot && protocolEvent.Sequence != lastSequence + 1)
            {
                _eventGap = true;
            }

            if (_eventGap)
            {
                _eventGap = false;
                var snapshot = await ResubscribeAsync(cancellationToken).ConfigureAwait(false);
                lastSequence = snapshot.Sequence;
                haveSequence = true;
                yield return snapshot;
                continue;
            }

            lastSequence = protocolEvent.Sequence;
            haveSequence = true;
            yield return protocolEvent;
        }
    }

    private async Task<StatusChangedProtocolEvent> ResubscribeAsync(CancellationToken cancellationToken)
    {
        var result = await SendAsync(
            Commands.SubscribeStatus,
            new SubscribeStatusRequest { LastSequence = null },
            cancellationToken).ConfigureAwait(false);
        return new StatusChangedProtocolEvent
        {
            EventId = Guid.NewGuid(),
            Sequence = result.Snapshot.Sequence,
            Data = new StatusChangedEvent
            {
                Sequence = result.Snapshot.Sequence,
                Snapshot = true,
                Account = result.Snapshot.Account,
                Changes = result.Snapshot.Connections,
                RemovedConnectionIds = Array.Empty<Guid>(),
            },
        };
    }

    /// <summary>Closes the connection and releases all resources.</summary>
    public async ValueTask DisposeAsync()
    {
        await CloseAsync().ConfigureAwait(false);
        _sendLock.Dispose();
        _lifetime.Dispose();
    }

    private async Task CloseAsync()
    {
        _lifetime.Cancel();
        _events.Writer.TryComplete();
        FailAllPending(new ProtocolException(ProtocolErrorCode.Closed, "connection closed"));
        if (_stream is { } stream)
        {
            await stream.DisposeAsync().ConfigureAwait(false);
        }
        if (_readerLoop is { } loop)
        {
            try
            {
                await loop.ConfigureAwait(false);
            }
            catch
            {
                // The reader loop reports failures through pending requests.
            }
        }
    }
}
