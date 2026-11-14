using HfDrive.Protocol;

namespace HfDrive.Desktop.ViewModels;

/// <summary>
/// Presentation wrapper for a single connection status observed from the
/// provider. Every property maps 1:1 to observed protocol data; nothing here is
/// fabricated or cached beyond the latest snapshot.
/// </summary>
public sealed partial class ConnectionViewModel
{
    public ConnectionViewModel(ConnectionStatus status)
    {
        Status = status;
    }

    public ConnectionStatus Status { get; }

    public string TitleDisplay
    {
        get
        {
            string owner = string.IsNullOrEmpty(Status.Owner.DisplayName) ? Status.Owner.Namespace ?? Status.Owner.OwnerId : Status.Owner.DisplayName;
            return $"{owner} / {Status.Bucket.Name}";
        }
    }

    public string SummaryDisplay =>
        $"{StatusDisplayText.Get(Status.State)} · {(Status.Mode == ConnectionMode.ReadOnly ? "Read-only" : "Writable")} · {CapabilityText}";

    public string StateText => StatusDisplayText.Get(Status.State);

    public string ModeText => Status.Mode == ConnectionMode.ReadOnly ? "Read-only" : "Writable";

    public string CapabilityText => Status.Capability switch
    {
        CapabilityState.ReadOnly => "Read-only",
        CapabilityState.StorageSetupRequired => "Storage setup required",
        CapabilityState.WriteSyncPaused => "Write sync paused",
        CapabilityState.Writable => "Writable",
        _ => Status.Capability.ToString(),
    };

    public string PinText => Status.Pin switch
    {
        PinState.Unpinned => "Not pinned",
        PinState.Pinned => "Kept offline",
        PinState.Partial => "Partially offline",
        _ => Status.Pin.ToString(),
    };

    public string HydrationText => Status.Hydration switch
    {
        HydrationState.Full => "Fully available offline",
        HydrationState.Partial => "Partially available offline",
        HydrationState.OnlineOnly => "Online-only",
        _ => Status.Hydration.ToString(),
    };

    public string RootPathDisplay => Status.RootPath;

    public string CountsText =>
        $"{Status.PendingFiles} pending · {Status.DirtyFiles} local changes · {Status.ConflictFiles} conflicts · {Status.OnlineOnlyFiles} online-only · {Status.PinnedFiles} pinned";

    public string PendingBytesText => FormatBytes(Status.PendingUploadBytes);

    public bool HasError => Status.LastError is not null;

    public string ErrorText => Status.LastError is null
        ? string.Empty
        : $"Provider error {Status.LastError.Code}: {Status.LastError.Message}";

    public string UpdatedAtText => Status.UpdatedAt;

    internal static string FormatBytes(ulong bytes)
    {
        string[] units = ["B", "KB", "MB", "GB", "TB"];
        double value = bytes;
        int unit = 0;
        while (value >= 1024 && unit < units.Length - 1)
        {
            value /= 1024;
            unit++;
        }

        return unit == 0 ? $"{bytes} B" : $"{value:0.#} {units[unit]}";
    }
}
