using System.Drawing;
using System.Drawing.Drawing2D;
using System.Runtime.InteropServices;
using System.Windows.Forms;
using NostrVpn.Windows.Core;
using NostrVpn.Windows.ViewModels;

namespace NostrVpn.Windows.Services;

public sealed class TrayService : IDisposable
{
    private readonly NotifyIcon _notifyIcon;
    private readonly Icon _normalIcon;
    private readonly Icon _connectingIcon;
    private readonly Icon _connectedIcon;
    private readonly Icon _attentionIcon;
    private AppViewModel? _viewModel;
    private Action? _showWindow;
    private Action? _quit;
    private readonly Dictionary<string, string> _transferStatuses = [];
    private bool _transfersInitialized;
    private string _notificationTransferId = "";

    public TrayService()
    {
        _normalIcon = LoadIcon();
        _connectingIcon = CreateBadgeIcon(_normalIcon, ConnectingColor);
        _connectedIcon = CreateBadgeIcon(_normalIcon, ConnectedColor);
        _attentionIcon = CreateBadgeIcon(_normalIcon, AttentionColor);
        _notifyIcon = new NotifyIcon
        {
            Icon = _normalIcon,
            Text = "Nostr VPN",
            Visible = true,
        };
        _notifyIcon.DoubleClick += (_, _) => _showWindow?.Invoke();
        _notifyIcon.BalloonTipClicked += (_, _) => ShowTransfer(_notificationTransferId);
    }

    public void Attach(AppViewModel viewModel, Action showWindow, Action quit)
    {
        _viewModel = viewModel;
        _showWindow = showWindow;
        _quit = quit;
        viewModel.PropertyChanged += (_, _) => Update();
        Update();
    }

    public void Update()
    {
        if (_viewModel is null)
        {
            return;
        }

        _notifyIcon.Text = TruncateTrayText(TrayText(_viewModel));
        _notifyIcon.Icon = TrayIndicator(_viewModel.State) switch
        {
            Indicator.Attention => _attentionIcon,
            Indicator.Connected => _connectedIcon,
            Indicator.Connecting => _connectingIcon,
            _ => _normalIcon,
        };
        _notifyIcon.ContextMenuStrip?.Dispose();
        _notifyIcon.ContextMenuStrip = BuildMenu(_viewModel);
        UpdateFileNotifications(_viewModel.State.FileTransfers);
    }

    private void ShowTransfer(string id)
    {
        _showWindow?.Invoke();
        _viewModel?.ShowFileTransfer(id);
    }

    private void UpdateFileNotifications(IReadOnlyList<NativeFileTransferState> transfers)
    {
        NativeFileTransferState? latest = null;
        foreach (var transfer in transfers.Where(transfer => !transfer.IsSender))
        {
            _transferStatuses.TryGetValue(transfer.Id, out var previous);
            if (previous != transfer.Status && (transfer.Status == "offered" || (_transfersInitialized && previous is not null && transfer.Status == "completed"))) latest = transfer;
            _transferStatuses[transfer.Id] = transfer.Status;
        }
        var liveIds = transfers.Select(transfer => transfer.Id).ToHashSet();
        foreach (var id in _transferStatuses.Keys.Where(id => !liveIds.Contains(id)).ToArray()) _transferStatuses.Remove(id);
        _transfersInitialized = true;
        if (latest is null) return;
        _notificationTransferId = latest.Id;
        _notifyIcon.ShowBalloonTip(8000,
            latest.Status == "offered" ? $"Files from {latest.PeerLabel}" : "Files received",
            $"{latest.Title} · {NativeFileTransferState.FormatSize(latest.TotalBytes)}\n{(latest.Status == "offered" ? "Open to accept or decline." : "Open to show your files.")}", ToolTipIcon.Info);
    }

    public void Dispose()
    {
        _notifyIcon.Visible = false;
        _notifyIcon.Dispose();
        _normalIcon.Dispose();
        _connectingIcon.Dispose();
        _connectedIcon.Dispose();
        _attentionIcon.Dispose();
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

        var state = viewModel.State;
        var network = viewModel.ActiveNetwork;
        if (network is not null)
        {
            var devices = new ToolStripMenuItem(string.IsNullOrWhiteSpace(network.Name) ? "Network Devices" : network.Name);
            foreach (var participant in network.Participants)
            {
                devices.DropDownItems.Add(Item(ParticipantMenuTitle(participant), (_, _) => viewModel.CopyText(participant.Npub)));
            }
            menu.Items.Add(devices);
        }

        // Where this device's internet comes from.
        var exits = network?.Participants.Where(participant => participant.OffersExitNode && !participant.IsSelf).ToArray() ?? [];
        var internet = new ToolStripMenuItem($"Internet · {InternetTitle(state, exits)}") { Image = DotImage(InternetIndicator(state)) };
        internet.DropDownItems.Add(Item(InternetStatus(viewModel), (_, _) => { }, false));
        internet.DropDownItems.Add(new ToolStripSeparator());
        var direct = Item("This Device", async (_, _) => await viewModel.SelectDirectExitAsync());
        direct.Checked = state.InternetSource == "direct";
        internet.DropDownItems.Add(direct);
        if (viewModel.PaidRouteMarketVisible)
        {
            var paidAutomatic = Item("Paid Internet · Automatic · Experimental", async (_, _) => await viewModel.SelectPaidAutomaticExitAsync());
            paidAutomatic.Checked = state.InternetSource == "paid_automatic";
            internet.DropDownItems.Add(paidAutomatic);
            var paidManual = Item("Paid Internet · Manual", async (_, _) => await viewModel.SelectPaidManualExitAsync());
            paidManual.Checked = state.InternetSource == "paid_manual";
            internet.DropDownItems.Add(paidManual);
        }
        var wireGuard = Item("WireGuard", async (_, _) => await viewModel.SelectWireGuardUpstreamExitAsync(), state.WireguardExitConfigured);
        wireGuard.Checked = state.InternetSource == "wireguard";
        internet.DropDownItems.Add(wireGuard);
        if (exits.Length > 0)
        {
            internet.DropDownItems.Add(new ToolStripSeparator());
        }
        foreach (var participant in exits)
        {
            var item = Item(DeviceName(participant), async (_, _) => await viewModel.SelectPeerExitAsync(participant.Npub));
            item.Checked = state.InternetSource == "private_vpn" && state.ExitNode == participant.Npub;
            internet.DropDownItems.Add(item);
        }
        menu.Items.Add(internet);

        // Private sharing and public selling stay apart so it is clear who
        // can use this device's connection.
        menu.Items.Add(new ToolStripSeparator());
        var networkName = string.IsNullOrWhiteSpace(network?.Name) ? null : network!.Name;
        var share = Item($"Share Internet with {networkName ?? "Trusted Devices"}",
            async (_, _) => await viewModel.SetAdvertiseExitNodeAsync(!state.AdvertiseExitNode));
        share.Checked = state.AdvertiseExitNode;
        share.ToolTipText = $"Only devices in {networkName ?? "this network"} can use this device's internet. Nothing is offered publicly.";
        menu.Items.Add(share);
        if (viewModel.PaidExitSellerVisible)
        {
            var seller = state.PaidExitSeller;
            var sell = new ToolStripMenuItem("Sell Internet Publicly") { Image = DotImage(SellingIndicator(state)) };
            sell.DropDownItems.Add(Item("Anyone can pay to use this connection", (_, _) => { }, false));
            sell.DropDownItems.Add(Item(SellerStatus(seller), (_, _) => { }, false));
            sell.DropDownItems.Add(Item($"Uplink: {(string.IsNullOrWhiteSpace(seller.InternetText) ? "This device" : seller.InternetText)}", (_, _) => { }, false));
            sell.DropDownItems.Add(new ToolStripSeparator());
            sell.DropDownItems.Add(Item("Settings…", (_, _) =>
            {
                _showWindow?.Invoke();
                viewModel.ShowSellAccessCommand.Execute(null);
            }));
            menu.Items.Add(sell);
        }

        menu.Items.Add(new ToolStripSeparator());
        var incoming = viewModel.State.FileTransfers.Where(transfer => transfer.CanAccept).ToArray();
        var files = new ToolStripMenuItem(incoming.Length == 0 ? "Files" : $"Files · {incoming.Length} waiting");
        files.DropDownItems.Add(Item("Show files", (_, _) => ShowTransfer(incoming.FirstOrDefault()?.Id ?? "")));
        foreach (var transfer in incoming.Take(3))
        {
            var request = new ToolStripMenuItem($"From {transfer.PeerLabel} · {NativeFileTransferState.FormatSize(transfer.TotalBytes)}");
            request.DropDownItems.Add(Item("Accept", async (_, _) => await viewModel.FileTransferActionAsync("accept", transfer.Id), viewModel.State.VpnActive));
            request.DropDownItems.Add(Item("Decline", async (_, _) => await viewModel.FileTransferActionAsync("decline", transfer.Id)));
            files.DropDownItems.Add(request);
        }
        menu.Items.Add(files);
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

    private enum Indicator { Hidden, Connecting, Connected, Attention }

    // Same states and colors as macOS InternetExitIndicator.
    private static readonly Color ConnectingColor = Color.FromArgb(255, 149, 0);
    private static readonly Color ConnectedColor = Color.FromArgb(52, 199, 89);
    private static readonly Color AttentionColor = Color.FromArgb(255, 59, 48);

    private static Color? IndicatorColor(Indicator indicator) => indicator switch
    {
        Indicator.Connecting => ConnectingColor,
        Indicator.Connected => ConnectedColor,
        Indicator.Attention => AttentionColor,
        _ => null,
    };

    private static Indicator InternetIndicator(NativeAppState state)
    {
        if (!state.VpnEnabled || state.InternetSource == "direct") return Indicator.Hidden;
        if (state.ExitNodeNeedsAttention || state.ExitNodeBlocked) return Indicator.Attention;
        return state.ExitNodeActive ? Indicator.Connected : Indicator.Connecting;
    }

    private static Indicator SellingIndicator(NativeAppState state) =>
        !state.PaidExitSeller.Enabled ? Indicator.Hidden
        : state.PaidExitSeller.Ready ? Indicator.Connected
        : Indicator.Connecting;

    private static Indicator TrayIndicator(NativeAppState state)
    {
        var connection = InternetIndicator(state);
        var selling = SellingIndicator(state);
        if (connection == Indicator.Attention) return Indicator.Attention;
        if (connection == Indicator.Connecting || selling == Indicator.Connecting || (state.VpnEnabled && !state.VpnActive))
        {
            return Indicator.Connecting;
        }
        if (connection == Indicator.Connected || selling == Indicator.Connected || (state.VpnEnabled && state.VpnActive))
        {
            return Indicator.Connected;
        }
        return Indicator.Hidden;
    }

    private static string InternetTitle(NativeAppState state, IEnumerable<NativeParticipantState> exits) => state.InternetSource switch
    {
        "wireguard" => "WireGuard",
        "private_vpn" => exits.FirstOrDefault(participant => participant.Npub == state.ExitNode) is { } exit ? DeviceName(exit) : "Private VPN",
        "paid_automatic" => "Automatic",
        "paid_manual" => "Paid VPN",
        _ => "Direct",
    };

    private static string InternetStatus(AppViewModel viewModel)
    {
        var state = viewModel.State;
        if (!string.IsNullOrWhiteSpace(state.ExitNodeStatusText)) return state.ExitNodeStatusText;
        return state.InternetSource == "direct" ? "Using device internet" : viewModel.VpnStatusText;
    }

    private static string SellerStatus(NativePaidExitSellerState seller)
    {
        if (!seller.Enabled) return "Off";
        if (!string.IsNullOrWhiteSpace(seller.StatusText)) return seller.StatusText;
        return seller.Ready ? "Ready" : "Waiting";
    }

    private static Bitmap? DotImage(Indicator indicator)
    {
        if (IndicatorColor(indicator) is not { } color) return null;
        var bitmap = new Bitmap(12, 12);
        using var graphics = Graphics.FromImage(bitmap);
        graphics.SmoothingMode = SmoothingMode.AntiAlias;
        using var brush = new SolidBrush(color);
        graphics.FillEllipse(brush, 2, 2, 8, 8);
        return bitmap;
    }

    // Status dot in the bottom-right corner, with a transparent ring that
    // separates it from the logo on light and dark taskbars.
    private static Icon CreateBadgeIcon(Icon baseIcon, Color color)
    {
        using var bitmap = baseIcon.ToBitmap();
        using var graphics = Graphics.FromImage(bitmap);
        graphics.SmoothingMode = SmoothingMode.AntiAlias;
        var size = Math.Min(bitmap.Width, bitmap.Height);
        var diameter = Math.Max(6, (int)Math.Round(size * 0.4));
        var gap = Math.Max(1, size / 16);
        var x = bitmap.Width - diameter;
        var y = bitmap.Height - diameter;
        graphics.CompositingMode = CompositingMode.SourceCopy;
        using (var clear = new SolidBrush(Color.Transparent))
        {
            graphics.FillEllipse(clear, x - gap, y - gap, diameter + gap * 2, diameter + gap * 2);
        }
        graphics.CompositingMode = CompositingMode.SourceOver;
        using var brush = new SolidBrush(color);
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
        var state = viewModel.State;
        var exits = viewModel.ActiveNetwork?.Participants.Where(participant => participant.OffersExitNode && !participant.IsSelf) ?? [];
        return $"Nostr VPN · {viewModel.VpnStatusText}\nInternet: {InternetTitle(state, exits)}";
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
