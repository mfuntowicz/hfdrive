using System.IO.Pipes;
using Xunit;

namespace HfDrive.Protocol.Tests;

/// <summary>Protocol behavior over isolated asynchronous Windows named pipes.</summary>
public sealed class ClientBehaviorTests
{
    private sealed class PipePair : IAsyncDisposable
    {
        private readonly CancellationTokenSource _deadline = new(TimeSpan.FromSeconds(10));
        private readonly NamedPipeClientStream _transport;
        internal NamedPipeServerStream Server { get; }
        internal NamedPipeProtocolClient Client { get; }

        private PipePair(TimeSpan? requestTimeout)
        {
            string name = $"HFDrive.Protocol.Tests.{Guid.NewGuid():N}";
            Server = new NamedPipeServerStream(name, PipeDirection.InOut, 1,
                PipeTransmissionMode.Byte, PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
            _transport = new NamedPipeClientStream(".", name, PipeDirection.InOut, PipeOptions.Asynchronous);
            Client = new NamedPipeProtocolClient(new NamedPipeProtocolClientOptions
            {
                PipeName = name,
                RequireServerAuthentication = false,
                RequestTimeout = requestTimeout ?? TimeSpan.FromSeconds(5),
                MaxPendingRequests = 2,
            });
        }

        internal static async Task<PipePair> CreateAsync(TimeSpan? requestTimeout = null)
        {
            var pair = new PipePair(requestTimeout);
            try
            {
                var accept = pair.Server.WaitForConnectionAsync(pair._deadline.Token);
                await pair._transport.ConnectAsync(pair._deadline.Token);
                await accept;
                await pair.Client.ConnectAsync(pair._transport);
                return pair;
            }
            catch
            {
                await pair.DisposeAsync();
                throw;
            }
        }

        internal async Task<Envelope> ReadAsync()
        {
            var bytes = await FrameCodec.ReadFrameAsync(Server, _deadline.Token);
            return Envelope.Parse(bytes ?? throw new EndOfStreamException());
        }

        internal ValueTask SendAsync(Envelope envelope) =>
            FrameCodec.WriteFrameAsync(Server, envelope.ToCanonicalBytes(), _deadline.Token);

        internal async Task HelloAsync()
        {
            var pending = Client.HelloAsync();
            var request = await ReadAsync();
            Assert.Equal("hello", request.Method);
            await SendAsync(Envelope.Response(request.RequestId, "hello", new HelloResult
            {
                ProtocolMajor = 1,
                ProtocolMinor = 0,
                ProviderVersion = "0.1.0",
                SupportedFeatures = new[] { "get_status", "subscribe_status", "cancel_request" },
                SupportedMinProtocolMinor = 0,
            }));
            await pending;
        }

        public async ValueTask DisposeAsync()
        {
            await Client.DisposeAsync();
            await _transport.DisposeAsync();
            await Server.DisposeAsync();
            _deadline.Dispose();
        }
    }

    [Fact]
    public async Task Hello_Must_Precede_Other_Commands()
    {
        await using var pair = await PipePair.CreateAsync();
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => pair.Client.SendAsync(Commands.GetStatus, new GetStatusRequest()));
    }

    [Fact]
    public async Task RequireServerAuthentication_Demands_An_Authenticator_Before_Any_Byte()
    {
        await using var client = new NamedPipeProtocolClient(new NamedPipeProtocolClientOptions
        {
            PipeName = $"HFDrive.Tests.Missing.{Guid.NewGuid():N}",
            RequireServerAuthentication = true,
        });
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => client.ConnectAsync((IServerAuthenticator?)null));
    }

    [Fact]
    public async Task Requests_Correlate_By_RequestId_And_Result_Typed()
    {
        await using var pair = await PipePair.CreateAsync();
        await pair.HelloAsync();
        var first = pair.Client.SendAsync(Commands.GetStatus, new GetStatusRequest());
        var firstRequest = await pair.ReadAsync();
        var second = pair.Client.SendAsync(Commands.GetStatus, new GetStatusRequest());
        var secondRequest = await pair.ReadAsync();
        Assert.NotEqual(firstRequest.RequestId, secondRequest.RequestId);
        await pair.SendAsync(Envelope.Response(secondRequest.RequestId, "get_status",
            new GetStatusResult { EventSequence = 6, Account = AccountStatus.SignedOut }));
        await pair.SendAsync(Envelope.Response(firstRequest.RequestId, "get_status",
            new GetStatusResult { EventSequence = 5, Account = AccountStatus.SignedOut }));
        Assert.Equal(5ul, (await first).EventSequence);
        Assert.Equal(6ul, (await second).EventSequence);
    }

    [Fact]
    public async Task Bounded_Pending_Requests_Reject_Overflow_And_Fail_On_Peer_Close()
    {
        await using var pair = await PipePair.CreateAsync();
        await pair.HelloAsync();
        var first = pair.Client.SendAsync(Commands.GetStatus, new GetStatusRequest());
        var second = pair.Client.SendAsync(Commands.GetStatus, new GetStatusRequest());
        await pair.ReadAsync();
        await pair.ReadAsync();
        var overflow = await Assert.ThrowsAsync<ProtocolException>(
            () => pair.Client.SendAsync(Commands.GetStatus, new GetStatusRequest()));
        Assert.Equal(ProtocolErrorCode.Busy, overflow.Error.Code);
        await pair.Server.DisposeAsync();
        var failures = await Task.WhenAll(
            Assert.ThrowsAsync<ProtocolException>(() => first),
            Assert.ThrowsAsync<ProtocolException>(() => second));
        Assert.All(failures, failure => Assert.Equal(ProtocolErrorCode.Closed, failure.Error.Code));
    }

    [Fact]
    public async Task Wire_Error_Results_Throw_ProtocolException()
    {
        await using var pair = await PipePair.CreateAsync();
        await pair.HelloAsync();
        var pending = pair.Client.SendAsync(Commands.StartLogin, new StartLoginRequest
        {
            OperationId = Guid.NewGuid(),
            Flow = LoginFlow.Pkce,
            Purpose = LoginPurpose.Signin,
        });
        var request = await pair.ReadAsync();
        await pair.SendAsync(Envelope.ResponseError(request.RequestId, "start_login",
            new ProtocolError
            {
                Code = ProtocolErrorCode.OAuthClientNotConfigured,
                Message = "client id is not configured",
            }));
        var failure = await Assert.ThrowsAsync<ProtocolException>(() => pending);
        Assert.Equal(ProtocolErrorCode.OAuthClientNotConfigured, failure.Error.Code);
    }

    [Fact]
    public async Task Event_Stream_Delivers_Ordered_Events_And_Resubscribes_On_Gap()
    {
        await using var pair = await PipePair.CreateAsync();
        await pair.HelloAsync();
        var subscribe = pair.Client.SendAsync(Commands.SubscribeStatus, new SubscribeStatusRequest());
        var request = await pair.ReadAsync();
        await pair.SendAsync(Envelope.Response(request.RequestId, "subscribe_status",
            new SubscribeStatusResult
            {
                Subscribed = true,
                Snapshot = new StatusSnapshot { Sequence = 1, Account = AccountStatus.SignedOut, Connections = Array.Empty<ConnectionStatus>() },
            }));
        await subscribe;

        ValueTask SendEventAsync(ulong sequence) =>
            pair.SendAsync(Envelope.Event(Guid.NewGuid(), "status_changed", new StatusChangedEvent
            {
                Sequence = sequence,
                Snapshot = false,
                Account = AccountStatus.SignedOut,
                Changes = Array.Empty<ConnectionStatus>(),
                RemovedConnectionIds = Array.Empty<Guid>(),
            }));

        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        await using var events = pair.Client.ReadEventsAsync(deadline.Token).GetAsyncEnumerator();
        var firstPending = events.MoveNextAsync().AsTask();
        await SendEventAsync(2);
        Assert.True(await firstPending);
        var first = Assert.IsType<StatusChangedProtocolEvent>(events.Current);
        Assert.False(first.Data.Snapshot);
        Assert.Equal(2ul, first.Sequence);

        var nextPending = events.MoveNextAsync().AsTask();
        await SendEventAsync(4);
        var resubscribe = await pair.ReadAsync();
        Assert.Equal("subscribe_status", resubscribe.Method);
        await pair.SendAsync(Envelope.Response(resubscribe.RequestId, "subscribe_status",
            new SubscribeStatusResult
            {
                Subscribed = true,
                Snapshot = new StatusSnapshot { Sequence = 4, Account = AccountStatus.SignedOut, Connections = Array.Empty<ConnectionStatus>() },
            }));
        Assert.True(await nextPending);
        var snapshot = Assert.IsType<StatusChangedProtocolEvent>(events.Current);
        Assert.True(snapshot.Data.Snapshot);
        Assert.Equal(4ul, snapshot.Sequence);
    }

    [Fact]
    public async Task Cancellation_Stops_The_Request_And_Notifies_Its_Exact_Id()
    {
        await using var pair = await PipePair.CreateAsync();
        await pair.HelloAsync();
        using var cancellation = new CancellationTokenSource();
        var pending = pair.Client.SendAsync(Commands.GetStatus, new GetStatusRequest(), cancellation.Token);
        var request = await pair.ReadAsync();
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => pending);
        var cancel = await pair.ReadAsync();
        Assert.Equal("cancel_request", cancel.Method);
        Assert.Equal(request.RequestId, cancel.GetRequestBody<CancelRequestRequest>().TargetRequestId);
    }

    [Fact]
    public async Task Request_Timeout_Reports_Timeout_Code()
    {
        await using var pair = await PipePair.CreateAsync(TimeSpan.FromMilliseconds(250));
        var pending = pair.Client.HelloAsync();
        await pair.ReadAsync();
        var failure = await Assert.ThrowsAsync<ProtocolException>(() => pending);
        Assert.Equal(ProtocolErrorCode.Timeout, failure.Error.Code);
    }
}
