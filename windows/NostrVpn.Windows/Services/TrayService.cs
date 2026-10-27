using System.Drawing;
using System.Drawing.Drawing2D;
using System.Runtime.InteropServices;
using System.Text;
using System.Windows.Forms;
using NostrVpn.Windows.Core;
using NostrVpn.Windows.ViewModels;

namespace NostrVpn.Windows.Services;

public sealed class TrayService : IDisposable
{
    private readonly NotifyIcon _notifyIcon;
    private readonly Icon _normalIcon;
    private readonly Icon _blockedIcon;
    private AppViewModel? _viewModel;
    private Action? _showWindow;
    private Action? _quit;
    private string _menuSignature = string.Empty;
    private bool _menuDirty;

    public TrayService()
    {
        _normalIcon = LoadIcon();
        _blockedIcon = CreateBlockedIcon(_normalIcon);
        _notifyIcon = new NotifyIcon
        {
            Icon = _normalIcon,
            Text = "Nostr VPN",
            Visible = true,
        };
        _notifyIcon.DoubleClick += (_, _) => _showWindow?.Invoke();
    }

    public void Attach(AppViewModel viewModel, Action showWindow, Action quit)
    {
        _viewModel = viewModel;
        _showWindow = showWindow;
        _quit = quit;
        viewModel.PropertyChanged += (_, _) => Update();
        RebuildMenu();
        UpdateIndicator();
    }

    public void Update()
    {
        if (_viewModel is null)
        {
            return;
        }

        UpdateIndicator();
        var signature = MenuSignature(_viewModel);
        if (signature == _menuSignature)
        {
            return;
        }
        if (_notifyIcon.ContextMenuStrip is { Visible: true })
        {
            // Rebuilding an open menu destroys it under the cursor and turns
            // pending clicks into no-ops, so defer until it closes.
            _menuDirty = true;
            return;
        }
        RebuildMenu();
    }

    public void Dispose()
    {
        _notifyIcon.Visible = false;
        _notifyIcon.ContextMenuStrip?.Dispose();
        _notifyIcon.Dispose();
        _normalIcon.Dispose();
        _blockedIcon.Dispose();
    }

    private void UpdateIndicator()
    {
        if (_viewModel is null)
        {
            return;
        }
        _notifyIcon.Text = TruncateTrayText(TrayText(_viewModel));
        _notifyIcon.Icon = _viewModel.State.ExitNodeBlocked ? _blockedIcon : _normalIcon;
    }

    private void RebuildMenu()
    {
        if (_viewModel is null)
        {
            return;
        }
        _menuSignature = MenuSignature(_viewModel);
        var oldMenu = _notifyIcon.ContextMenuStrip;
        var menu = BuildMenu(_viewModel);
        menu.Closed += (_, _) =>
        {
            if (_menuDirty)
            {
                _menuDirty = false;
                Update();
            }
        };
        _notifyIcon.ContextMenuStrip = menu;
        oldMenu?.Dispose();
    }

    /// <summary>
    /// Everything the context menu renders. Rebuild only when this changes so
    /// the per-second state ticks don't churn (and never destroy) the menu.
    /// </summary>
    private static string MenuSignature(AppViewModel viewModel)
    {
        var state = viewModel.State;
        var signature = new StringBuilder();
        signature.Append(viewModel.VpnStatusText).Append('|')
            .Append(state.VpnEnabled).Append(state.VpnControlSupported).Append(viewModel.ActionInFlight).Append('|')
            .Append(state.SelfMagicDnsName).Append('|').Append(state.NodeName).Append('|')
            .Append(state.TunnelIp).Append('|').Append(state.OwnNpub).Append('|')
            .Append(state.ExitNodeStatusText).Append('|').Append(state.AdvertiseExitNode).Append('|')
            .Append(state.InternetSource).Append('|').Append(state.ExitNode).Append('|')
            .Append(viewModel.PaidRouteMarketVisible ? 1 : 0).Append('|').Append(state.WireguardExitConfigured).Append('|');
        if (viewModel.ActiveNetwork is { } network)
        {
            signature.Append(network.Id).Append('|').Append(network.Name).Append('|')
                .Append(network.Participants.Count).Append('|');
            foreach (var participant in network.Participants)
            {
                signature.Append(participant.Npub).Append('~').Append(participant.TunnelIp).Append('~')
                    .Append(participant.MagicDnsName).Append('~').Append(participant.Alias).Append('~')
                    .Append(participant.OffersExitNode).Append('~').Append(participant.IsSelf).Append(';');
            }
        }
        return signature.ToString();
    }

    private ContextMenuStrip BuildMenu(AppViewModel viewModel)
    {
        // 1. VPN toggle (first), 2. device-name section, 3. network/exit
        // submenus, 4. open/quit. See macOS TrayController.swift for the
        // canonical layout shared across platforms.
        var menu = new ContextMenuStrip();

        var vpnToggle = Item("Nostr VPN", async (_, _) => await viewModel.ToggleVpnAsync(),
            viewModel.State.VpnControlSupported && !viewModel.ActionInFlight);
        vpnToggle.Checked = viewModel.State.VpnEnabled;
        menu.Items.Add(vpnToggle);
        // Status subtitle right below the toggle, mirrors the macOS row's
        // second line and reuses the same VpnStatusText that the header
        // shows in the main window.
        menu.Items.Add(Item(viewModel.VpnStatusText, (_, _) => { }, false));

        menu.Items.Add(new ToolStripSeparator());

        // Device-name section header + Copy Device ID.
        menu.Items.Add(Item(DeviceDisplayName(viewModel), (_, _) => { }, false));
        var copyDeviceId = Item("Copy Device ID",
            (_, _) => viewModel.CopyText(viewModel.State.OwnNpub),
            !string.IsNullOrWhiteSpace(viewModel.State.OwnNpub));
        menu.Items.Add(copyDeviceId);

        menu.Items.Add(new ToolStripSeparator());

        var network = viewModel.ActiveNetwork;
        if (network is not null)
        {
            var devices = new ToolStripMenuItem(string.IsNullOrWhiteSpace(network.Name) ? "Network Devices" : network.Name);
            foreach (var participant in network.Participants)
            {
                devices.DropDownItems.Add(Item(ParticipantMenuTitle(participant), (_, _) => viewModel.CopyText(participant.Npub)));
            }
            menu.Items.Add(devices);

            var exitNodes = new ToolStripMenuItem("Internet Source");
            if (!string.IsNullOrWhiteSpace(viewModel.State.ExitNodeStatusText))
            {
                exitNodes.DropDownItems.Add(Item(viewModel.State.ExitNodeStatusText, (_, _) => { }, false));
            }
            var offerExit = Item("Share This Device",
                async (_, _) => await viewModel.SetAdvertiseExitNodeAsync(!viewModel.State.AdvertiseExitNode));
            offerExit.Checked = viewModel.State.AdvertiseExitNode;
            exitNodes.DropDownItems.Add(offerExit);
            exitNodes.DropDownItems.Add(new ToolStripSeparator());
            var noExit = Item("This device", async (_, _) => await viewModel.SelectDirectExitAsync());
            noExit.Checked = viewModel.State.InternetSource == "direct";
            exitNodes.DropDownItems.Add(noExit);
            if (viewModel.PaidRouteMarketVisible)
            {
                var paidAutomatic = Item("Paid · Automatic · Experimental", async (_, _) => await viewModel.SelectPaidAutomaticExitAsync());
                paidAutomatic.Checked = viewModel.State.InternetSource == "paid_automatic";
                exitNodes.DropDownItems.Add(paidAutomatic);
                var paidManual = Item("Paid · Choose manually", async (_, _) => await viewModel.SelectPaidManualExitAsync());
                paidManual.Checked = viewModel.State.InternetSource == "paid_manual";
                exitNodes.DropDownItems.Add(paidManual);
            }
            var wireGuard = Item("WireGuard VPN", async (_, _) => await viewModel.SelectWireGuardUpstreamExitAsync(), viewModel.State.WireguardExitConfigured);
            wireGuard.Checked = viewModel.State.InternetSource == "wireguard";
            exitNodes.DropDownItems.Add(wireGuard);
            foreach (var participant in network.Participants.Where(participant => participant.OffersExitNode && !participant.IsSelf))
            {
                var item = Item(DeviceName(participant), async (_, _) => await viewModel.SelectPeerExitAsync(participant.Npub));
                item.Checked = viewModel.State.InternetSource == "private_vpn" && viewModel.State.ExitNode == participant.Npub;
                exitNodes.DropDownItems.Add(item);
            }
            menu.Items.Add(exitNodes);
        }

        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add(Item("Open Nostr VPN", (_, _) => _showWindow?.Invoke()));
        menu.Items.Add(Item("Quit", (_, _) => _quit?.Invoke()));
        return menu;
    }

    private static string DeviceDisplayName(AppViewModel viewModel)
    {
        var state = viewModel.State;
        if (!string.IsNullOrWhiteSpace(state.SelfMagicDnsName))
        {
            return state.SelfMagicDnsName;
        }
        if (!string.IsNullOrWhiteSpace(state.NodeName))
        {
            return state.NodeName;
        }
        var tunnelIp = state.TunnelIp?.Trim();
        if (!string.IsNullOrEmpty(tunnelIp) && tunnelIp != "-")
        {
            return tunnelIp;
        }
        return "This Device";
    }

    private static ToolStripMenuItem Item(string text, EventHandler onClick, bool enabled = true)
    {
        var item = new ToolStripMenuItem(text) { Enabled = enabled };
        item.Click += onClick;
        return item;
    }

    private static Icon LoadIcon()
    {
        foreach (var filename in new[] { "nostr-vpn-tray.ico", "nostr-vpn.ico" })
        {
            var iconPath = Path.Combine(AppContext.BaseDirectory, "Assets", filename);
            if (File.Exists(iconPath))
            {
                return new Icon(iconPath);
            }
        }

        return (Icon)SystemIcons.Application.Clone();
    }

    private static Icon CreateBlockedIcon(Icon baseIcon)
    {
        using var bitmap = baseIcon.ToBitmap();
        using var graphics = Graphics.FromImage(bitmap);
        graphics.SmoothingMode = SmoothingMode.AntiAlias;
        var diameter = Math.Max(6, Math.Min(bitmap.Width, bitmap.Height) / 3);
        var x = bitmap.Width - diameter - 1;
        var y = 1;
        using var brush = new SolidBrush(Color.FromArgb(220, 38, 38));
        graphics.FillEllipse(brush, x, y, diameter, diameter);
        var handle = bitmap.GetHicon();
        try
        {
            return (Icon)Icon.FromHandle(handle).Clone();
        }
        finally
        {
            DestroyIcon(handle);
        }
    }

    private static string TrayText(AppViewModel viewModel)
    {
        var status = !string.IsNullOrWhiteSpace(viewModel.State.ExitNodeStatusText)
            ? viewModel.State.ExitNodeStatusText
            : viewModel.State.VpnStatus;
        return $"Nostr VPN - {status}";
    }

    private static string TruncateTrayText(string value)
    {
        return value.Length <= 63 ? value : value[..60] + "...";
    }

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool DestroyIcon(IntPtr handle);

    private static string ParticipantMenuTitle(NativeParticipantState participant)
    {
        var name = DeviceName(participant);
        return string.IsNullOrWhiteSpace(participant.TunnelIp) || participant.TunnelIp == "-"
            ? name
            : $"{name} ({participant.TunnelIp})";
    }

    private static string DeviceName(NativeParticipantState participant)
    {
        if (!string.IsNullOrWhiteSpace(participant.MagicDnsName))
        {
            return participant.MagicDnsName;
        }
        if (!string.IsNullOrWhiteSpace(participant.Alias))
        {
            return participant.Alias;
        }
        return participant.Npub.Length > 16
            ? $"{participant.Npub[..10]}...{participant.Npub[^6..]}"
            : participant.Npub;
    }
}
