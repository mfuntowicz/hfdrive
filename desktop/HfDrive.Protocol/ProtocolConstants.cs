namespace HfDrive.Protocol;

/// <summary>Wire contract constants for HF Drive IPC 1.0.</summary>
public static class ProtocolConstants
{
    /// <summary>Protocol major implemented by this library (1).</summary>
    public const int ProtocolMajor = 1;

    /// <summary>Protocol minor implemented by this library (0).</summary>
    public const int ProtocolMinor = 0;

    /// <summary>Maximum frame payload in bytes (1 MiB), length prefix excluded.</summary>
    public const int MaxFrameBytes = 1024 * 1024;

    /// <summary>Length prefix size in bytes (4-byte little-endian u32).</summary>
    public const int HeaderLength = 4;

    /// <summary>Maximum records in one page response.</summary>
    public const int MaxPageLimit = 200;

    /// <summary>Default bound on concurrently pending requests per client.</summary>
    public const int DefaultMaxPendingRequests = 128;

    /// <summary>Maximum JSON nesting depth accepted while parsing.</summary>
    public const int MaxJsonDepth = 64;

    /// <summary>Wire name of the hello method (first command on a connection).</summary>
    public const string HelloMethod = "hello";
}
