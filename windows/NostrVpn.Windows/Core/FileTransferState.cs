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
    public string Title => Status == "unavailable" ? "Files unavailable" : string.Join(", ", Files.Select(file => file.Name));
    public string Detail => Status == "unavailable" ? "" : $"{(IsSender ? "To" : "From")} {PeerName} · {(Status == "preparing" ? "Preparing…" : Status)} · {TransferredBytes:N0} / {TotalBytes:N0} bytes";
    public bool ShowsProgress => Status is "preparing" or "connecting" or "transferring" or "paused";
    public bool CanAccept => !IsSender && Status == "offered";
    public bool CanResume => Status == "paused";
    public bool CanCancel => Status is "offered" or "preparing" or "connecting" or "transferring" or "paused";
    public bool CanShowFiles => !IsSender && Status == "completed" && Files.Any(file => file.LocalPath is not null);
}
