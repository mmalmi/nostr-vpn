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
    public bool ThemeIsSystem
    {
        get => _themeService.Preference == ThemeService.System;
        set => SetThemePreference(ThemeService.System, value);
    }

    public bool ThemeIsLight
    {
        get => _themeService.Preference == ThemeService.Light;
        set => SetThemePreference(ThemeService.Light, value);
    }

    public bool ThemeIsDark
    {
        get => _themeService.Preference == ThemeService.Dark;
        set => SetThemePreference(ThemeService.Dark, value);
    }

    private void SetThemePreference(string theme, bool selected)
    {
        if (!selected)
        {
            return;
        }
        try
        {
            _themeService.SetPreference(theme);
        }
        catch (Exception error)
        {
            Notice = error.Message;
        }
    }

    private void OnThemeApplied()
    {
        OnPropertyChanged(nameof(ShownNetworkStatusBrush));
        OnPropertyChanged(nameof(VpnStatusBrush));
    }

    private Task SaveNodeAsync()
    {
        ushort? port = ushort.TryParse(ListenPort.Trim(), out var parsed) ? parsed : null;
        return DispatchAsync(NativeActions.UpdateSettings(new SettingsPatch
        {
            NodeName = NodeName,
            Endpoint = Endpoint,
            TunnelIp = TunnelIp,
            ListenPort = port,
            FipsHostInboundTcpPorts = FipsHostInboundTcpPorts,
        }), "Saving device");
    }

    private Task SaveRelaysAsync()
    {
        var relays = RelaysDraft
            .Split(new[] { '\r', '\n', ',', ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .ToList();
        return DispatchAsync(NativeActions.UpdateSettings(new SettingsPatch
        {
            Relays = relays,
        }), "Saving relays");
    }

    private Task AddRelayAsync()
    {
        var url = NormalizeRelayUrl(RelayInput);
        if (url is null) return Task.CompletedTask;

        var (enabled, disabled) = RelayLists();
        disabled.RemoveAll(relay => relay == url);
        if (!enabled.Contains(url)) enabled.Add(url);
        RelayInput = "";
        return SaveRelayListsAsync(enabled, disabled);
    }

    public Task SetRelayEnabledAsync(NativeRelayState relay, bool enabledValue)
    {
        var url = NormalizeRelayUrl(relay.Url);
        if (url is null) return Task.CompletedTask;

        var (enabled, disabled) = RelayLists();
        enabled.RemoveAll(relayUrl => relayUrl == url);
        disabled.RemoveAll(relayUrl => relayUrl == url);
        if (enabledValue)
        {
            enabled.Add(url);
        }
        else
        {
            disabled.Add(url);
        }
        return SaveRelayListsAsync(enabled, disabled);
    }

    public Task RemoveRelayAsync(NativeRelayState relay)
    {
        var url = NormalizeRelayUrl(relay.Url);
        if (url is null) return Task.CompletedTask;

        var (enabled, disabled) = RelayLists();
        enabled.RemoveAll(relayUrl => relayUrl == url);
        disabled.RemoveAll(relayUrl => relayUrl == url);
        return SaveRelayListsAsync(enabled, disabled);
    }

    private (List<string> Enabled, List<string> Disabled) RelayLists()
    {
        var enabled = UniqueRelays(State.Relays.Where(relay => relay.Enabled).Select(relay => relay.Url));
        var disabled = UniqueRelays(State.Relays.Where(relay => !relay.Enabled).Select(relay => relay.Url));
        disabled.RemoveAll(relay => enabled.Contains(relay));
        return (enabled, disabled);
    }

    private Task SaveRelayListsAsync(List<string> enabledInput, List<string> disabledInput)
    {
        var enabled = UniqueRelays(enabledInput);
        var disabled = UniqueRelays(disabledInput);
        disabled.RemoveAll(relay => enabled.Contains(relay));
        return DispatchAsync(NativeActions.UpdateSettings(new SettingsPatch
        {
            Relays = enabled,
            DisabledRelays = disabled,
        }), "Saving relays");
    }

    private static string? NormalizeRelayUrl(string value)
    {
        var trimmed = value.Trim();
        if (string.IsNullOrWhiteSpace(trimmed)) return null;
        return trimmed.StartsWith("ws://", StringComparison.OrdinalIgnoreCase)
            || trimmed.StartsWith("wss://", StringComparison.OrdinalIgnoreCase)
            ? trimmed
            : $"wss://{trimmed}";
    }

    private static List<string> UniqueRelays(IEnumerable<string> values)
    {
        var seen = new HashSet<string>();
        return values
            .Select(NormalizeRelayUrl)
            .Where(relay => relay is not null && seen.Add(relay))
            .Select(relay => relay!)
            .ToList();
    }

    private Task SaveWireGuardExitAsync()
    {
        return DispatchAsync(NativeActions.UpdateSettings(new SettingsPatch
        {
            WireguardExitConfig = WireguardExitConfig,
        }), "Saving WireGuard");
    }

    private Task SaveExitDnsAsync()
    {
        return DispatchAsync(NativeActions.UpdateSettings(new SettingsPatch
        {
            ExitDnsMode = ExitDnsMode,
            ExitDnsDohProvider = ExitDnsDohProvider,
            ExitDnsCustomDohUrl = ExitDnsCustomDohUrl,
            ExitDnsCustomDohBootstrapIps = ExitDnsCustomDohBootstrapIps,
            ExitDnsThroughExitServers = ExitDnsThroughExitServers,
        }), "Saving Exit DNS");
    }
}
