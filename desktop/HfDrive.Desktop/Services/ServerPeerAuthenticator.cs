using System.IO.Pipes;
using HfDrive.Desktop.Interop;
using HfDrive.Protocol;

namespace HfDrive.Desktop.Services;

/// <summary>
/// Peer authenticator for the provider connection: verifies the server process
/// identity (same user, same session, integrity at least medium, allowed provider
/// image) through CsWin32 bindings before a single protocol byte is written.
/// </summary>
public sealed class ServerPeerAuthenticator : IServerAuthenticator
{
    public PeerVerificationResult? LastResult { get; private set; }

    public ValueTask AuthenticateAsync(NamedPipeClientStream connection, CancellationToken cancellationToken)
    {
        PeerVerificationResult result = PeerVerification.VerifyProvider(connection);
        LastResult = result;
        if (!result.Succeeded)
        {
            // Any exception here aborts the connection before Hello is sent; no
            // request, credential, or protocol frame is written to an
            // unauthenticated server. Details are nonsecret by construction.
            throw new InvalidOperationException($"Provider verification failed: {result.Detail}");
        }

        return ValueTask.CompletedTask;
    }
}
