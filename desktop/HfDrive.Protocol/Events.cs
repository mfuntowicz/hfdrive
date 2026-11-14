namespace HfDrive.Protocol;

/// <summary>status_changed event payload.</summary>
public sealed record StatusChangedEvent
{
    /// <summary>Monotonically increasing event sequence (decimal string on the wire).</summary>
    public required ulong Sequence { get; init; }

    /// <summary>True when this is a full snapshot (subscription start or gap recovery).</summary>
    public required bool Snapshot { get; init; }

    /// <summary>Complete account state, even when connection records are deltas.</summary>
    public required AccountStatus Account { get; init; }

    /// <summary>Changed connection records.</summary>
    public IReadOnlyList<ConnectionStatus> Changes { get; init; } = Array.Empty<ConnectionStatus>();

    /// <summary>Connections removed since the previous event.</summary>
    public IReadOnlyList<Guid> RemovedConnectionIds { get; init; } = Array.Empty<Guid>();
}

/// <summary>activity_changed event payload.</summary>
public sealed record ActivityChangedEvent
{
    /// <summary>Monotonically increasing event sequence (decimal string on the wire).</summary>
    public required ulong Sequence { get; init; }

    /// <summary>Changed activity records (batched).</summary>
    public IReadOnlyList<ActivityRecord> Changes { get; init; } = Array.Empty<ActivityRecord>();
}

/// <summary>conflicts_changed event payload.</summary>
public sealed record ConflictsChangedEvent
{
    /// <summary>Monotonically increasing event sequence (decimal string on the wire).</summary>
    public required ulong Sequence { get; init; }

    /// <summary>Changed conflict records.</summary>
    public IReadOnlyList<ConflictRecord> Changes { get; init; } = Array.Empty<ConflictRecord>();

    /// <summary>Conflicts resolved/removed since the previous event.</summary>
    public IReadOnlyList<Guid> RemovedConflictIds { get; init; } = Array.Empty<Guid>();
}

/// <summary>Base type for decoded events.</summary>
public abstract record ProtocolEvent
{
    /// <summary>Event identifier (carried in the envelope request_id).</summary>
    public required Guid EventId { get; init; }

    /// <summary>Monotonically increasing event sequence.</summary>
    public required ulong Sequence { get; init; }

    /// <summary>Wire event name.</summary>
    public abstract string Method { get; }
}

/// <summary>A decoded status_changed event.</summary>
public sealed record StatusChangedProtocolEvent : ProtocolEvent
{
    /// <summary>Typed payload.</summary>
    public required StatusChangedEvent Data { get; init; }

    /// <inheritdoc />
    public override string Method => "status_changed";
}

/// <summary>A decoded activity_changed event.</summary>
public sealed record ActivityChangedProtocolEvent : ProtocolEvent
{
    /// <summary>Typed payload.</summary>
    public required ActivityChangedEvent Data { get; init; }

    /// <inheritdoc />
    public override string Method => "activity_changed";
}

/// <summary>A decoded conflicts_changed event.</summary>
public sealed record ConflictsChangedProtocolEvent : ProtocolEvent
{
    /// <summary>Typed payload.</summary>
    public required ConflictsChangedEvent Data { get; init; }

    /// <inheritdoc />
    public override string Method => "conflicts_changed";
}
