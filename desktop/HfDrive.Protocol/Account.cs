using System.Security.Cryptography;

namespace HfDrive.Protocol;

/// <summary>Provider-owned native authorization state, independent of pipe connectivity.</summary>
public enum AuthenticationState { SignedOut, SigningIn, SignedIn, NeedsSignIn }

/// <summary>Public progress for an explicit interactive authorization attempt.</summary>
public enum LoginPhase { Pending, Completed, Cancelled, Expired, Denied, Failed }

/// <summary>Verified public userinfo. No bearer credential or ID token.</summary>
public sealed record AccountProfile
{
    public required string AccountKey { get; init; }
    public required string Issuer { get; init; }
    public required string Subject { get; init; }
    public required string Namespace { get; init; }
    public required string DisplayName { get; init; }
    /// <summary>
    /// Verified public avatar URL for display only (HTTPS huggingface.co or a subdomain,
    /// no embedded credentials). Null when unknown or rejected; never a credential.
    /// </summary>
    public string? AvatarUrl { get; init; }
    /// <summary>Actual returned grants; null means unknown, not known empty.</summary>
    public IReadOnlyList<string>? GrantedScopes { get; init; }
}

/// <summary>Terminal attempt identity survives event coalescing and reconnects.</summary>
public sealed record LoginProgress
{
    public required Guid SessionId { get; init; }
    public required LoginFlow Flow { get; init; }
    public required LoginPurpose Purpose { get; init; }
    public required LoginPhase Phase { get; init; }
    public required string ExpiresAt { get; init; }
}

/// <summary>Complete account snapshot. A known profile is not itself active authorization.</summary>
public sealed record AccountStatus
{
    public required AuthenticationState State { get; init; }
    public AccountProfile? Profile { get; init; }
    public LoginProgress? Login { get; init; }
    public ProtocolError? LastError { get; init; }
    public static AccountStatus SignedOut { get; } = new() { State = AuthenticationState.SignedOut };
}

/// <summary>Bucket and prefix before a workspace identity has been discovered.</summary>
public sealed record RemoteLocation
{
    public required string OwnerNamespace { get; init; }
    public required string OwnerId { get; init; }
    public required OwnerKind OwnerKind { get; init; }
    public required string Bucket { get; init; }
    public required string BucketId { get; init; }
    public required string Prefix { get; init; }
}

/// <summary>Canonical JSON plus operation UUID RFC bytes is hashed for DPAPI IPC entropy.</summary>
public sealed record PublicationProtectionContext
{
    public required Guid ConnectionId { get; init; }
    public required string AccountKey { get; init; }
    public required string Issuer { get; init; }
    public required string Subject { get; init; }
    public required string OwnerId { get; init; }
    public required OwnerKind OwnerKind { get; init; }
    public required string BucketId { get; init; }
    public required Guid WorkspaceId { get; init; }
    public required string Prefix { get; init; }

    /// <summary>Hash exact context and network-order UUID bytes; never Guid's mixed-endian default.</summary>
    public byte[] Entropy(Guid operationId)
    {
        if (operationId == Guid.Empty)
            throw new ArgumentException("An operation identity is required.", nameof(operationId));
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(ProtocolJson.SerializeCanonical(this));
        Span<byte> operationBytes = stackalloc byte[16];
        operationId.TryWriteBytes(operationBytes, bigEndian: true, out _);
        hash.AppendData(operationBytes);
        return hash.GetHashAndReset();
    }
}

/// <summary>Reserve an exact setup binding; initialization still requires final Connect.</summary>
public sealed record BeginSetupRequest
{
    public required Guid OperationId { get; init; }
    public required string AccountKey { get; init; }
    public required RemoteBinding Binding { get; init; }
    public required bool Initialize { get; init; }
    public Guid? BucketCreationOperationId { get; init; }
}

/// <summary>A durable draft is not yet an Explorer registration.</summary>
public sealed record BeginSetupResult
{
    public required Guid SetupId { get; init; }
    public required Guid ConnectionId { get; init; }
    public required RemoteBinding Binding { get; init; }
    public required PublicationProtectionContext ProtectionContext { get; init; }
}

/// <summary>Complete counts even when representative preview paths are bounded.</summary>
public sealed record CollisionCategorySummary
{
    public required CollisionKind Kind { get; init; }
    public required ulong Count { get; init; }
}
