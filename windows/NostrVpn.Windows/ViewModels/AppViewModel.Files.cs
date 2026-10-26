using System.IO;
using Microsoft.Win32;
using NostrVpn.Windows.Core;

namespace NostrVpn.Windows.ViewModels;

public sealed partial class AppViewModel
{
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
        if (!State.VpnActive || ActionInFlight || !State.Networks.Where(network => network.Enabled)
            .SelectMany(network => network.Participants).Any(peer => peer.Npub == npub && !peer.IsSelf && peer.RosterAccepted && peer.Reachable)) return;
        var parent = Path.GetDirectoryName(State.ConfigPath);
        if (parent is null || sources.Length == 0) return;
        try
        {
            if (sources.Length > 32) throw new IOException("Choose up to 32 files at a time.");
            Notice = "Preparing files";
            var paths = await Task.Run(() =>
            {
                var batches = new List<string>();
                try
                {
                    return sources.Select(source =>
                    {
                        var batch = Path.Combine(parent, "file-transfer-outbox", Guid.NewGuid().ToString());
                        Directory.CreateDirectory(batch);
                        batches.Add(batch);
                        var info = new FileInfo(source);
                        if (!info.Exists || info.Length > 100L * 1024 * 1024 * 1024 || (info.Attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)
                            throw new IOException("Choose regular files to send.");
                        var target = Path.Combine(batch, info.Name);
                        File.Copy(source, target, overwrite: false);
                        return target;
                    }).ToArray();
                }
                catch { foreach (var batch in batches) Directory.Delete(batch, recursive: true); throw; }
            });
            await DispatchAsync(AppCoreClient.Action(new { type = "send_files", npub, paths }), "Offering files");
        }
        catch (Exception error) { Notice = error.Message; }
    }

    public Task FileTransferActionAsync(string action, string id) =>
        DispatchAsync(AppCoreClient.Action(new { type = $"{action}_file_transfer", id }), "Updating transfer");
}
