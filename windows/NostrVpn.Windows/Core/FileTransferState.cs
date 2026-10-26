namespace NostrVpn.Windows.Core;

public sealed class NativeTransferFileState
{
    public string Name { get; set; } = "";
    public ulong SizeBytes { get; set; }
    public string? LocalPath { get; set; }
}

public sealed class NativeFileTransferState
{
    public string Id { get; set; } = "";
    public string PeerNpub { get; set; } = "";
    public string PeerName { get; set; } = "";
    public bool IsSender { get; set; }
    public List<NativeTransferFileState> Files { get; set; } = [];
    public string Status { get; set; } = "";
    public ulong TransferredBytes { get; set; }
    public ulong TotalBytes { get; set; }
    public string? Error { get; set; }
    public string Title => Status == "unavailable" ? "Files unavailable" : Files.Count == 1 ? Files[0].Name : $"{Files.FirstOrDefault()?.Name} + {Math.Max(0, Files.Count - 1)} files";
    public string PeerLabel => string.IsNullOrWhiteSpace(PeerName) ? ShortIdentity(PeerNpub) : PeerName;
    public string StatusLabel => Status switch
    {
        "queued" => "Waiting to send",
        "cancelling" => "Cancelling…",
        "declining" => "Declining…",
        "offered" => IsSender ? "Waiting for acceptance" : "Wants to send you files",
        "preparing" => "Preparing files…",
        "connecting" => "Connecting…",
        "transferring" => IsSender ? "Sending" : "Receiving",
        "paused" => "Paused",
        "completed" => IsSender ? "Sent" : "Received",
        "declined" => "Declined",
        "cancelled" => "Cancelled",
        "failed" => "Could not transfer files",
        _ => "Waiting",
    };
    public string Detail => Status == "unavailable" ? "" : $"{(IsSender ? "To" : "From")} {PeerLabel} · {StatusLabel}\n{FormatSize(TransferredBytes)} of {FormatSize(TotalBytes)}";
    public static string ShortIdentity(string value) => value.Length > 18 ? $"{value[..10]}…{value[^6..]}" : value;
    public static string FormatSize(ulong bytes)
    {
        var units = new[] { "B", "KB", "MB", "GB", "TB" };
        double size = bytes;
        var unit = 0;
        while (size >= 1024 && unit < units.Length - 1) { size /= 1024; unit++; }
        return $"{size:0.#} {units[unit]}";
    }
    public bool ShowsProgress => Status is "preparing" or "connecting" or "transferring" or "paused";
    public bool CanAccept => !IsSender && Status == "offered";
    public bool CanResume => Status == "paused";
    public bool CanCancel => !CanAccept && (Status is "queued" or "offered" or "preparing" or "connecting" or "transferring" or "paused");
    public bool CanShowFiles => !IsSender && Status == "completed" && Files.Any(file => file.LocalPath is not null);
}
