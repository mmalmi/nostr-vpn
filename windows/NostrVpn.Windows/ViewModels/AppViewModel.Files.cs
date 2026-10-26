using System.IO;
using System.Threading;
using Microsoft.Win32;
using NostrVpn.Windows.Core;

namespace NostrVpn.Windows.ViewModels;

public sealed partial class AppViewModel
{
    private CancellationTokenSource? _filePreparation;
    private string _filePreparationDetail = "";
    public bool PreparingFiles => _filePreparation is not null;
    public string FilePreparationDetail { get => _filePreparationDetail; private set => SetField(ref _filePreparationDetail, value); }
    public event Action<string>? FileTransferRequested;
    public void ShowFileTransfer(string id)
    {
        Page = AppPage.Devices;
        FileTransferRequested?.Invoke(id);
    }
    public void CancelFilePreparation() => _filePreparation?.Cancel();

    public bool SelectedParticipantCanSendFiles => State.VpnActive && ActiveNetwork?.Enabled == true
        && SelectedParticipant is { IsSelf: false, Reachable: true };

    public async Task ChooseFilesAsync()
    {
        var picker = new OpenFileDialog { Multiselect = true, Title = "Send files" };
        if (SelectedParticipantCanSendFiles && picker.ShowDialog() == true)
            await SendFilesAsync(picker.FileNames);
    }

    public Task SendFilesAsync(string[] sources) => SelectedParticipant is { } peer
        ? SendFilesToAsync(peer.Npub, sources) : Task.CompletedTask;

    public async Task SendFilesToAsync(string npub, string[] sources)
    {
        if (PreparingFiles) { Notice = "Finish or cancel the files already being prepared."; return; }
        if (!State.VpnActive || ActionInFlight || !State.Networks.Where(network => network.Enabled)
            .SelectMany(network => network.Participants).Any(peer => peer.Npub == npub && !peer.IsSelf && peer.RosterAccepted && peer.Reachable))
        { Notice = "The device is unavailable. Your files have not been sent."; return; }
        var parent = Path.GetDirectoryName(State.ConfigPath);
        if (parent is null || sources.Length == 0) return;
        var batches = new List<string>();
        using var cancellation = new CancellationTokenSource();
        _filePreparation = cancellation;
        OnPropertyChanged(nameof(PreparingFiles));
        Page = AppPage.Devices;
        var queued = false;
        try
        {
            if (sources.Length > 32) throw new IOException("Choose up to 32 files at a time.");
            FilePreparationDetail = "Preparing files…";
            var progress = new Progress<string>(detail => FilePreparationDetail = detail);
            var paths = await Task.Run(async () =>
            {
                var paths = new List<string>();
                var files = sources.Select(source => new FileInfo(source)).ToArray();
                foreach (var file in files)
                {
                    if (!file.Exists || file.Length > 100L * 1024 * 1024 * 1024 || (file.Attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)
                        throw new IOException("Choose regular files smaller than 100 GB.");
                }
                var total = files.Sum(file => file.Length);
                long copied = 0;
                var lastReport = Environment.TickCount64;
                foreach (var info in files)
                {
                        cancellation.Token.ThrowIfCancellationRequested();
                        var batch = Path.Combine(parent, "file-transfer-outbox", Guid.NewGuid().ToString());
                        Directory.CreateDirectory(batch);
                        batches.Add(batch);
                        var target = Path.Combine(batch, info.Name);
                        using var input = new FileStream(info.FullName, FileMode.Open, FileAccess.Read, FileShare.Read, 65536, true);
                        using var output = new FileStream(target, FileMode.CreateNew, FileAccess.Write, FileShare.None, 65536, true);
                        var buffer = new byte[65536];
                        long fileCopied = 0;
                        while (true)
                        {
                            var count = await input.ReadAsync(buffer.AsMemory(), cancellation.Token);
                            if (count == 0) break;
                            fileCopied += count;
                            if (fileCopied > 100L * 1024 * 1024 * 1024) throw new IOException("Choose files smaller than 100 GB.");
                            await output.WriteAsync(buffer.AsMemory(0, count), cancellation.Token);
                            copied += count;
                            if (Environment.TickCount64 - lastReport >= 150)
                            {
                                ((IProgress<string>)progress).Report($"Preparing {info.Name} · {NativeFileTransferState.FormatSize((ulong)copied)} of {NativeFileTransferState.FormatSize((ulong)total)}");
                                lastReport = Environment.TickCount64;
                            }
                        }
                        paths.Add(target);
                }
                return paths.ToArray();
            }, cancellation.Token);
            cancellation.Token.ThrowIfCancellationRequested();
            queued = await DispatchAsync(AppCoreClient.Action(new { type = "send_files", npub, paths }), "Offering files");
        }
        catch (OperationCanceledException) { Notice = "File preparation cancelled."; }
        catch (Exception error) { Notice = error.Message; }
        finally
        {
            if (!queued) foreach (var batch in batches) { try { Directory.Delete(batch, recursive: true); } catch (IOException) { } catch (UnauthorizedAccessException) { } }
            _filePreparation = null;
            FilePreparationDetail = "";
            OnPropertyChanged(nameof(PreparingFiles));
        }
    }

    public Task FileTransferActionAsync(string action, string id) =>
        DispatchAsync(AppCoreClient.Action(new { type = $"{action}_file_transfer", id }), "Updating transfer");
}
