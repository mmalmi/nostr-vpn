using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;
using Microsoft.Win32;
using NostrVpn.Windows.Core;
using NostrVpn.Windows.Services;

namespace NostrVpn.Windows.ViewModels;

public sealed partial class AppViewModel
{
    private static bool LooksLikeJoinRequest(string value)
    {
        const string prefix = "nvpn://join-request/";
        return value.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) && value.Length > prefix.Length;
    }

    private const string Bech32BodyCharset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

    /// <summary>
    /// A valid device ID is a bech32-encoded npub: "npub1" + 58 bech32 chars.
    /// </summary>
    public static bool IsValidDeviceId(string value)
    {
        if (string.IsNullOrWhiteSpace(value)) return false;
        var trimmed = value.Trim();
        if (trimmed.Length != 63 || !trimmed.StartsWith("npub1", StringComparison.Ordinal)) return false;
        for (var i = 5; i < trimmed.Length; i++)
        {
            if (Bech32BodyCharset.IndexOf(trimmed[i]) < 0) return false;
        }
        return true;
    }

    private async Task ConfirmAndImportJoinRequestAsync(string request)
    {
        var trimmed = request.Trim();
        if (_joinRequestPromptOpen || !LooksLikeJoinRequest(trimmed))
        {
            return;
        }
        var network = ActiveNetwork;
        if (network?.LocalIsAdmin != true)
        {
            return;
        }
        _joinRequestPromptOpen = true;
        try
        {
            var name = string.IsNullOrWhiteSpace(network.Name) ? "this network" : network.Name;
            var result = MessageBox.Show(
                $"Add the device from this join request to {name}?",
                "Add device?",
                MessageBoxButton.YesNo,
                MessageBoxImage.Question);
            if (result != MessageBoxResult.Yes)
            {
                return;
            }
            await DispatchAsync(NativeActions.ImportJoinRequest(trimmed), "Adding device");
            if (string.IsNullOrWhiteSpace(State.Error))
            {
                JoinRequestInput = "";
                Page = AppPage.Devices;
                Notice = "Device added";
            }
        }
        finally
        {
            _joinRequestPromptOpen = false;
        }
    }

    private async Task ImportJoinRequestQrImageAsync()
    {
        var dialog = new OpenFileDialog
        {
            Filter = "Images|*.png;*.jpg;*.jpeg;*.bmp;*.gif|All files|*.*",
            Multiselect = false,
        };
        if (dialog.ShowDialog() != true)
        {
            return;
        }
        var core = _core;
        if (core is null)
        {
            return;
        }
        var result = await Task.Run(() => core.DecodeQrImage(dialog.FileName));
        if (!string.IsNullOrWhiteSpace(result.Error))
        {
            Notice = result.Error;
            return;
        }
        var value = result.Value.Trim();
        if (LooksLikeJoinRequest(value))
        {
            await ConfirmAndImportJoinRequestAsync(value);
            return;
        }
        Notice = "Not a Nostr VPN join request.";
    }

    private async Task ImportWireGuardExitAsync()
    {
        var dialog = new OpenFileDialog
        {
            Filter = "WireGuard configs|*.conf;*.txt|All files|*.*",
            Multiselect = false,
        };
        if (dialog.ShowDialog() != true)
        {
            return;
        }
        try
        {
            var config = await File.ReadAllTextAsync(dialog.FileName);
            if (string.IsNullOrWhiteSpace(config))
            {
                Notice = "Selected WireGuard config is empty.";
                return;
            }
            WireguardExitConfig = config;
            await SaveWireGuardExitAsync();
        }
        catch (Exception error)
        {
            Notice = $"Could not read WireGuard config: {error.Message}";
        }
    }

    private async Task AddParticipantAsync()
    {
        var network = ActiveNetwork;
        if (network?.LocalIsAdmin != true)
        {
            return;
        }
        var participant = ParticipantInput.Trim();
        var alias = ParticipantAliasInput.Trim();
        var added = await DispatchAsync(
            NativeActions.AddParticipant(network.Id, participant, alias.Length == 0 ? null : alias),
            "Adding device");
        CompleteParticipantSubmission(added, network.Id, participant, alias);
    }

    private void CompleteParticipantSubmission(bool added, string networkId, string participant, string alias)
    {
        if (!added)
        {
            return;
        }
        BeginJoinCoordinationRefresh();
        var network = ActiveNetwork;
        if (Page != AppPage.AddDevice || network is null || network.Id != networkId
            || ParticipantInput.Trim() != participant || ParticipantAliasInput.Trim() != alias)
        {
            return;
        }
        ParticipantInput = "";
        ParticipantAliasInput = "";
        Page = AppPage.Devices;
        Notice = network.Participants.Any(item =>
            item.RosterAccepted && string.Equals(item.Npub, participant, StringComparison.Ordinal))
            ? "Device added" : "";
    }

    private async Task AddNetworkAsync()
    {
        if (await DispatchAsync(NativeActions.AddNetwork(NetworkNameInput.Trim()), "Adding network")
            && RuntimeActiveNetwork is { } network)
        {
            SelectShownNetwork(network.Id);
        }
    }

    private async Task ManualAddNetworkAsync()
    {
        var admin = ManualJoinAdminId.Trim();
        var mesh = NormalizeNetworkIdInput(ManualJoinMeshId);
        if (!IsValidDeviceId(admin) || string.IsNullOrWhiteSpace(mesh))
        {
            return;
        }
        if (await DispatchAsync(NativeActions.ManualAddNetwork(admin, mesh), "Adding network"))
        {
            BeginJoinCoordinationRefresh();
            if (RuntimeActiveNetwork is { } network)
            {
                SelectShownNetwork(network.Id);
            }
            ManualJoinAdminId = "";
            ManualJoinMeshId = "";
            SetNetworkSetupMode("");
            Page = AppPage.Devices;
        }
    }

    private async Task CreateNetworkAsync()
    {
        var name = string.IsNullOrWhiteSpace(NetworkNameInput) ? "My Network" : NetworkNameInput.Trim();
        if (!await DispatchAsync(NativeActions.AddNetwork(name), "Creating network"))
        {
            return;
        }
        NetworkNameInput = "";
        if (RuntimeActiveNetwork is { } network)
        {
            SelectShownNetwork(network.Id);
        }
        // Land on the new network's Devices view. Add Network may have
        // been the active page (or we may have been showing the
        // pre-network setup card); either way, Devices is the next
        // meaningful destination.
        SetNetworkSetupMode("");
        Page = AppPage.Devices;
    }

    private Task ActivateInactiveNetworkAsync(string? networkId)
    {
        if (string.IsNullOrWhiteSpace(networkId))
        {
            return Task.CompletedTask;
        }
        return DispatchAsync(NativeActions.SetNetworkEnabled(networkId, true), "Switching network");
    }
}
