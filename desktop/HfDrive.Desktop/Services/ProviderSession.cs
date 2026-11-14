using System.Reflection;
using HfDrive.Protocol;

namespace HfDrive.Desktop.Services;

public enum ProviderConnectionState
{
    Disconnected,
    Connecting,
    Ready,
    Failed,
}

/// <summary>
/// The desktop's single connection to the HF Drive provider over the local
/// authenticated named pipe. This class only speaks the typed IPC contract from
/// HfDrive.Protocol; it holds no credentials, no database and no sync state.
/// Every displayed value comes from an observed provider response — there is no
/// synthetic account or sync data anywhere in this surface.
/// </summary>
public sealed class ProviderSession : IAsyncDisposable
{
    private readonly SemaphoreSlim _gate = new(1, 1);
    private NamedPipeProtocolClient? _client;
    private CancellationTokenSource? _eventLifetime;
    private Task? _eventTask;
    private long _generation;
    private int _disposed;

    public long Generation => Interlocked.Read(ref _generation);
    public event Action<long, StatusChangedEvent>? StatusChanged;

    public ProviderConnectionState State { get; private set; } = ProviderConnectionState.Disconnected;

    /// <summary>Nonsecret description of the current connection state or failure.</summary>
    public string StatusText { get; private set; } = "Not connected";

    /// <summary>Observed error detail from the last failed connection or request.</summary>
    public string? LastError { get; private set; }

    /// <summary>Result of the last successful peer verification of the provider process.</summary>
    public string? PeerVerificationDetail { get; private set; }

    /// <summary>Hello result from the provider (version and supported features), when connected.</summary>
    public HelloResult? Hello { get; private set; }

    public event EventHandler? StateChanged;

    public static string BuildVersion { get; } =
        Assembly.GetExecutingAssembly().GetName().Version?.ToString() ?? "0.0.0";

    /// <summary>
    /// Connects to the provider, verifies the server process identity before any
    /// protocol byte is written, and performs the Hello handshake. Idempotent:
    /// an already-open connection is reused.
    /// </summary>
    public async Task ConnectAsync(CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
            if (_client is { IsReady: true })
            {
                return;
            }

            await DisposeClientCoreAsync().ConfigureAwait(false);
            long generation = Interlocked.Increment(ref _generation);
            SetState(ProviderConnectionState.Connecting, "Connecting to the HF Drive provider…");

            var authenticator = new ServerPeerAuthenticator();
            var client = new NamedPipeProtocolClient(new NamedPipeProtocolClientOptions
            {
                PipeName = ProviderPipeName.Value,
                RequireServerAuthentication = true,
            });

            try
            {
                await client.ConnectAsync(authenticator, cancellationToken).ConfigureAwait(false);
                PeerVerificationDetail = authenticator.LastResult?.Detail;

                HelloResult hello = await client.HelloAsync(new HelloRequest
                {
                    ProtocolMajor = ProtocolConstants.ProtocolMajor,
                    ProtocolMinor = ProtocolConstants.ProtocolMinor,
                    Role = ClientRole.Desktop,
                    BuildVersion = BuildVersion,
                }, cancellationToken).ConfigureAwait(false);
                SubscribeStatusResult subscription = await client.SendAsync(
                    Commands.SubscribeStatus, new SubscribeStatusRequest(), cancellationToken).ConfigureAwait(false);

                _client = client;
                Hello = hello;
                LastError = null;
                SetState(
                    ProviderConnectionState.Ready,
                    $"Connected — provider {hello.ProviderVersion} (protocol {hello.ProtocolMajor}.{hello.ProtocolMinor})");
                StatusChanged?.Invoke(generation, new StatusChangedEvent
                {
                    Sequence = subscription.Snapshot.Sequence,
                    Snapshot = true,
                    Account = subscription.Snapshot.Account,
                    Changes = subscription.Snapshot.Connections,
                });
                _eventLifetime = new CancellationTokenSource();
                _eventTask = PumpEventsAsync(client, generation, _eventLifetime.Token);
            }
            catch (Exception ex)
            {
                await client.DisposeAsync().ConfigureAwait(false);
                throw new InvalidOperationException(
                    $"Provider connection failed: {ex.Message} {authenticator.LastResult?.Detail}".Trim(),
                    ex);
            }
        }
        catch (Exception ex)
        {
            LastError = ex.Message;
            SetState(ProviderConnectionState.Failed, "Provider connection failed");
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>Capture the authenticated client without serializing independent requests.</summary>
    public Task<TResult> SendAsync<TRequest, TResult>(
        CommandSpec<TRequest, TResult> command, TRequest request, CancellationToken cancellationToken)
        where TRequest : notnull
    {
        var client = Volatile.Read(ref _client);
        if (client is not { IsReady: true })
            throw new ProtocolException(ProtocolErrorCode.Closed, "The provider is not connected.");
        return client.SendAsync(command, request, cancellationToken);
    }

    private async Task PumpEventsAsync(NamedPipeProtocolClient client, long generation, CancellationToken cancellationToken)
    {
        try
        {
            await foreach (ProtocolEvent message in client.ReadEventsAsync(cancellationToken).ConfigureAwait(false))
            {
                if (message is StatusChangedProtocolEvent status)
                    StatusChanged?.Invoke(generation, status.Data);
            }
            if (!cancellationToken.IsCancellationRequested && ReferenceEquals(client, _client))
            {
                LastError = "The provider disconnected. Reconnect to load its current state.";
                SetState(ProviderConnectionState.Disconnected, "Provider disconnected");
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { }
        catch (Exception ex)
        {
            if (!cancellationToken.IsCancellationRequested && ReferenceEquals(client, _client))
            {
                LastError = ex is ProtocolException protocol
                    ? $"Provider error {protocol.Error.Code}: {protocol.Error.Message}"
                    : ex.Message;
                SetState(ProviderConnectionState.Failed, "Provider event stream failed");
            }
        }
    }

    private void SetState(ProviderConnectionState state, string statusText)
    {
        State = state;
        StatusText = statusText;
        StateChanged?.Invoke(this, EventArgs.Empty);
    }

    private async Task DisposeClientCoreAsync()
    {
        _eventLifetime?.Cancel();
        var client = Interlocked.Exchange(ref _client, null);
        if (client is not null)
            await client.DisposeAsync().ConfigureAwait(false);
        if (_eventTask is not null)
            await _eventTask.ConfigureAwait(false);
        _eventTask = null;
        _eventLifetime?.Dispose();
        _eventLifetime = null;
    }

    public async ValueTask DisposeAsync()
    {
        await _gate.WaitAsync().ConfigureAwait(false);
        if (Interlocked.Exchange(ref _disposed, 1) != 0) { _gate.Release(); return; }
        Interlocked.Increment(ref _generation);
        try
        {
            await DisposeClientCoreAsync().ConfigureAwait(false);
        }
        finally
        {
            _gate.Release();
        }
    }
}
