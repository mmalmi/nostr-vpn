using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;
using Microsoft.Win32;
using NostrVpn.Windows.Core;
using NostrVpn.Windows.Services;

namespace NostrVpn.Windows.ViewModels;

public enum AppPage
{
    Devices,
    AddNetwork,
    AddDevice,
    Internet,
    PublicExits,
    Wallet,
    SellAccess,
    Settings,
}

public sealed partial class AppViewModel : INotifyPropertyChanged, IDisposable
{
    private readonly AppCoreClient _core;
    private readonly DispatcherTimer _refreshTimer;
    private readonly DispatcherTimer _updateTimer;
    private readonly UpdateService _updateService = new();
    private NativeAppState _state = new();
    private AppPage _page = AppPage.Devices;
    private string _selectedParticipantKey = "";
    private string _shownNetworkId = "";
    private bool _actionInFlight;
    private readonly NativeCoreCallGate _nativeCoreCallGate = new();
    private string _notice = "";
    private string _joinRequestInput = "";
    private string _participantInput = "";
    private string _participantAliasInput = "";
    private string _manualJoinAdminId = "";
    private string _manualJoinMeshId = "";
    private string _networkNameInput = "";
    private string _networkNameDraft = "";
    private string _networkMeshIdDraft = "";
    private string _nodeName = "";
    private string _endpoint = "";
    private string _tunnelIp = "";
    private string _listenPort = "";
    private string _relayInput = "";
    private string _relaysDraft = "";
    private string _fipsHostInboundTcpPorts = "";
    private string _advertisedRoutes = "";
    private string _wireguardExitConfig = "";
    private string _exitDnsMode = "automatic";
    private string _exitDnsDohProvider = "cloudflare";
    private string _exitDnsCustomDohUrl = "";
    private string _exitDnsCustomDohBootstrapIps = "";
    private string _exitDnsThroughExitServers = "";
    private string _paidRouteMintUrl = "";
    private string _paidRouteTopUpAmount = "";
    private string _paidRouteSendAmount = "";
    private string _paidRouteReceiveToken = "";
    private string _paidRouteWithdrawInvoice = "";
    private string _manualPaidExitProvider = "";
    private string _paidRouteFilterCountryCode = "";
    private string _paidRouteFilterSort = "quality";
    private bool _paidRouteFilterRequireIpv4;
    private bool _paidRouteFilterRequireIpv6;
    private bool _paidRouteFilterEditing;
    private string _paidExitPriceMsatPerGb = "0";
    private string? _lastSyncedManualPaidExitProvider;
    private ulong? _lastSyncedPaidExitPriceMsatPerGb;
    private string _networkSetupMode = "";
    private string _updateStatus = "";
    private Uri? _updateAssetUrl;
    private bool _updateUsesCoreDownload;
    private bool _updateChecking;
    private bool _updateInstalling;
    private bool _updateAvailable;
    private bool _autoInstallUpdates;
    private string _updateVersion = "";
    private QrMatrix _joinRequestQr = new();
    private QrMatrix _paidRouteWalletInvoiceQr = new();
    private bool _joinRequestPromptOpen;
    private DateTimeOffset _joinCoordinationRefreshUntil;
    private static readonly TimeSpan IdleRefreshInterval = TimeSpan.FromSeconds(15);
    private static readonly TimeSpan JoinCoordinationRefreshInterval = TimeSpan.FromSeconds(1);
    private static readonly TimeSpan JoinCoordinationRefreshWindow = TimeSpan.FromSeconds(20);
    private static readonly TimeSpan UpdatePollInterval = LoadUpdatePollInterval();
    private static readonly Brush HeaderDangerBrush = new SolidColorBrush(Color.FromRgb(220, 38, 38));
    private static readonly Brush TextSecondaryBrush = new SolidColorBrush(Color.FromRgb(104, 113, 124));
    private static readonly Brush ActiveNetworkBrush = new SolidColorBrush(Color.FromRgb(22, 163, 74));
    private static readonly Brush InactiveNetworkBrush = new SolidColorBrush(Color.FromRgb(156, 163, 175));

    public AppViewModel()
    {
        var version = Assembly.GetExecutingAssembly().GetName().Version?.ToString(3) ?? "";
        var dataDir = Environment.GetEnvironmentVariable("NVPN_APP_DATA_DIR");
        if (string.IsNullOrWhiteSpace(dataDir))
        {
            dataDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "Nostr VPN");
        }
        _core = new AppCoreClient(dataDir, version);
        _refreshTimer = new DispatcherTimer { Interval = IdleRefreshInterval };
        _autoInstallUpdates = LoadAutoInstallUpdates();
        ApplyState(_core.State(), syncDrafts: true);
        SyncLaunchOnStartupRegistration();

        ShowDevicesCommand = new RelayCommand(_ => Page = AppPage.Devices);
        ShowAddNetworkCommand = new RelayCommand(_ =>
        {
            SetNetworkSetupMode("");
            Page = AppPage.AddNetwork;
        });
        ShowAddDeviceCommand = new RelayCommand(
            _ => Page = AppPage.AddDevice,
            _ => ActiveNetwork is { LocalIsAdmin: true, Enabled: true });
        ShowInternetCommand = new RelayCommand(_ => Page = AppPage.Internet);
        ShowPublicExitsCommand = new RelayCommand(_ => Page = AppPage.PublicExits, _ => PaidRouteMarketVisible);
        ShowWalletCommand = new RelayCommand(_ => Page = AppPage.Wallet, _ => PaidRouteMarketVisible);
        ShowSellAccessCommand = new RelayCommand(_ => Page = AppPage.SellAccess, _ => PaidExitSellerVisible);
        ShowSettingsCommand = new RelayCommand(_ => Page = AppPage.Settings);
        RefreshCommand = new AsyncRelayCommand(_ => RefreshAsync(), _ => !ActionInFlight);
        ToggleVpnCommand = new AsyncRelayCommand(
            _ => ToggleVpnAsync(),
            _ => CanToggleVpn(
                ActionInFlight,
                State.VpnControlSupported,
                RuntimeActiveNetwork is not null,
                State.ServiceSupported,
                State.ServiceInstalled));
        CopyThisDeviceCommand = new RelayCommand(_ => CopyText(ThisDeviceCopyValue), _ => !string.IsNullOrWhiteSpace(ThisDeviceCopyValue));
        CopyPeerCommand = new RelayCommand(parameter => CopyText(parameter as string ?? ""));
        ImportJoinRequestQrImageCommand = new AsyncRelayCommand(_ => ImportJoinRequestQrImageAsync(), _ => !ActionInFlight && ActiveNetwork?.LocalIsAdmin == true);
        AddParticipantCommand = new AsyncRelayCommand(_ => AddParticipantAsync(), _ => !ActionInFlight && ActiveNetwork is { LocalIsAdmin: true, Enabled: true } && !string.IsNullOrWhiteSpace(ParticipantInput) && !ParticipantInputInvalid);
        SaveNodeCommand = new AsyncRelayCommand(_ => SaveNodeAsync(), _ => !ActionInFlight);
        AddRelayCommand = new AsyncRelayCommand(_ => AddRelayAsync(), _ => !ActionInFlight && !string.IsNullOrWhiteSpace(RelayInput));
        SaveRelaysCommand = new AsyncRelayCommand(_ => SaveRelaysAsync(), _ => !ActionInFlight);
        ImportWireGuardExitCommand = new AsyncRelayCommand(_ => ImportWireGuardExitAsync(), _ => !ActionInFlight);
        SaveWireGuardExitCommand = new AsyncRelayCommand(_ => SaveWireGuardExitAsync(), _ => !ActionInFlight);
        SaveExitDnsCommand = new AsyncRelayCommand(_ => SaveExitDnsAsync(), _ => !ActionInFlight);
        CreateNetworkCommand = new AsyncRelayCommand(_ => CreateNetworkAsync(), _ => !ActionInFlight);
        ShowCreateNetworkSetupCommand = new RelayCommand(_ => SetNetworkSetupMode("create"));
        ShowJoinNetworkSetupCommand = new RelayCommand(_ => SetNetworkSetupMode("join"));
        BackToNetworkSetupChoicesCommand = new RelayCommand(_ => SetNetworkSetupMode(""));
        AddNetworkCommand = new AsyncRelayCommand(_ => AddNetworkAsync(), _ => !ActionInFlight && !string.IsNullOrWhiteSpace(NetworkNameInput));
        ManualAddNetworkCommand = new AsyncRelayCommand(
            _ => ManualAddNetworkAsync(),
            _ => !ActionInFlight && CanSubmitManualJoin);
        ActivateInactiveNetworkCommand = new AsyncRelayCommand(
            parameter => ActivateInactiveNetworkAsync(parameter as string),
            parameter => !ActionInFlight && parameter is string id && !string.IsNullOrWhiteSpace(id));
        SaveNetworkNameCommand = new AsyncRelayCommand(_ => RenameActiveNetworkAsync(), _ => !ActionInFlight && ActiveNetwork?.LocalIsAdmin == true && !string.IsNullOrWhiteSpace(NetworkNameDraft));
        SaveNetworkMeshIdCommand = new AsyncRelayCommand(_ => SaveActiveNetworkMeshIdAsync(), _ => !ActionInFlight && ActiveNetwork?.LocalIsAdmin == true && !string.IsNullOrWhiteSpace(NetworkMeshIdDraft));
        CopyNetworkIdCommand = new RelayCommand(_ => CopyText(ActiveNetwork?.NetworkId ?? ""), _ => !string.IsNullOrWhiteSpace(ActiveNetwork?.NetworkId));
        InstallServiceCommand = new AsyncRelayCommand(_ => DispatchAsync(NativeActions.InstallSystemService(), "Installing service"), _ => !ActionInFlight && State.ServiceSupported);
        EnableServiceCommand = new AsyncRelayCommand(_ => DispatchAsync(NativeActions.EnableSystemService(), "Enabling service"), _ => !ActionInFlight && State.ServiceEnablementSupported);
        DisableServiceCommand = new AsyncRelayCommand(_ => DispatchAsync(NativeActions.DisableSystemService(), "Disabling service"), _ => !ActionInFlight && State.ServiceEnablementSupported);
        InstallCliCommand = new AsyncRelayCommand(_ => DispatchAsync(NativeActions.InstallCli(), "Installing CLI"), _ => !ActionInFlight && State.CliInstallSupported);
        CheckUpdatesCommand = new AsyncRelayCommand(_ => CheckUpdatesAsync(), _ => !UpdateChecking && !UpdateInstalling);
        InstallUpdateCommand = new AsyncRelayCommand(_ => InstallUpdateAsync(), _ => UpdateInstallEnabled);

        StartupService.RegisterDeepLinkProtocol();

        _refreshTimer.Tick += async (_, _) => await RefreshAsync();
        _refreshTimer.Start();
        _ = CheckUpdatesAsync(manual: false);

        _updateTimer = new DispatcherTimer { Interval = UpdatePollInterval };
        _updateTimer.Tick += async (_, _) => await CheckUpdatesAsync(manual: false);
        _updateTimer.Start();
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    public NativeAppState State
    {
        get => _state;
        private set
        {
            _state = value;
            if (!PageIsVisible(_page))
            {
                _page = AppPage.Devices;
                OnPropertyChanged(nameof(Page));
            }
            OnPropertyChanged();
            RaiseDerivedStateChanged();
        }
    }

    public AppPage Page
    {
        get => _page;
        set
        {
            var nextPage = PageIsVisible(value) ? value : AppPage.Devices;
            if (_page == nextPage)
            {
                return;
            }
            if (_page == AppPage.AddNetwork && nextPage != AppPage.AddNetwork)
            {
                SetNetworkSetupMode("");
            }
            _page = nextPage;
            OnPropertyChanged();
        }
    }

    public bool ActionInFlight
    {
        get => _actionInFlight;
        private set
        {
            _actionInFlight = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(PublicFipsRoutingEnabled));
            RaisePaidRouteWalletInputStateChanged();
            CommandManager.InvalidateRequerySuggested();
        }
    }

    public string Notice
    {
        get => _notice;
        private set
        {
            _notice = value;
            OnPropertyChanged();
        }
    }

    public string JoinRequestInput
    {
        get => _joinRequestInput;
        set
        {
            if (!SetField(ref _joinRequestInput, value))
            {
                return;
            }
            CommandManager.InvalidateRequerySuggested();
            var trimmed = (value ?? string.Empty).Trim();
            if (!ActionInFlight && ActiveNetwork?.LocalIsAdmin == true && LooksLikeJoinRequest(trimmed))
            {
                _ = ConfirmAndImportJoinRequestAsync(trimmed);
            }
        }
    }
    public string ParticipantInput
    {
        get => _participantInput;
        set
        {
            if (SetField(ref _participantInput, value))
            {
                OnPropertyChanged(nameof(ParticipantInputInvalid));
                OnPropertyChanged(nameof(ParticipantInputErrorVisibility));
                CommandManager.InvalidateRequerySuggested();
            }
        }
    }
    public string ParticipantAliasInput { get => _participantAliasInput; set => SetField(ref _participantAliasInput, value); }
    public bool ParticipantInputInvalid
    {
        get
        {
            var trimmed = (_participantInput ?? string.Empty).Trim();
            return trimmed.Length > 0 && !IsValidDeviceId(trimmed);
        }
    }
    public Visibility ParticipantInputErrorVisibility => ParticipantInputInvalid ? Visibility.Visible : Visibility.Collapsed;

    public string ManualJoinAdminId
    {
        get => _manualJoinAdminId;
        set
        {
            if (SetField(ref _manualJoinAdminId, value))
            {
                OnPropertyChanged(nameof(ManualJoinAdminInvalid));
                OnPropertyChanged(nameof(ManualJoinAdminErrorVisibility));
                OnPropertyChanged(nameof(CanSubmitManualJoin));
                CommandManager.InvalidateRequerySuggested();
            }
        }
    }
    public string ManualJoinMeshId
    {
        get => _manualJoinMeshId;
        set
        {
            if (SetField(ref _manualJoinMeshId, value))
            {
                OnPropertyChanged(nameof(CanSubmitManualJoin));
                CommandManager.InvalidateRequerySuggested();
            }
        }
    }
    public bool ManualJoinAdminInvalid =>
        !string.IsNullOrWhiteSpace(_manualJoinAdminId) && !IsValidDeviceId(_manualJoinAdminId.Trim());
    public Visibility ManualJoinAdminErrorVisibility => ManualJoinAdminInvalid ? Visibility.Visible : Visibility.Collapsed;
    public bool CanSubmitManualJoin =>
        !string.IsNullOrWhiteSpace(_manualJoinAdminId)
        && !string.IsNullOrWhiteSpace(NormalizeNetworkIdInput(_manualJoinMeshId))
        && !ManualJoinAdminInvalid;

    public string NetworkNameInput { get => _networkNameInput; set => SetField(ref _networkNameInput, value); }
    public string NetworkNameDraft
    {
        get => _networkNameDraft;
        set
        {
            if (SetField(ref _networkNameDraft, value))
            {
                CommandManager.InvalidateRequerySuggested();
            }
        }
    }
    public string NetworkMeshIdDraft
    {
        get => _networkMeshIdDraft;
        set
        {
            if (SetField(ref _networkMeshIdDraft, value))
            {
                CommandManager.InvalidateRequerySuggested();
            }
        }
    }
    public string NodeName { get => _nodeName; set => SetField(ref _nodeName, value); }
    public string Endpoint { get => _endpoint; set => SetField(ref _endpoint, value); }
    public string TunnelIp { get => _tunnelIp; set => SetField(ref _tunnelIp, value); }
    public string ListenPort { get => _listenPort; set => SetField(ref _listenPort, value); }
    public string RelayInput
    {
        get => _relayInput;
        set
        {
            if (SetField(ref _relayInput, value))
            {
                CommandManager.InvalidateRequerySuggested();
            }
        }
    }
    public string RelaysDraft { get => _relaysDraft; set => SetField(ref _relaysDraft, value); }
    public string FipsHostInboundTcpPorts { get => _fipsHostInboundTcpPorts; set => SetField(ref _fipsHostInboundTcpPorts, value); }
    public string AdvertisedRoutes { get => _advertisedRoutes; set => SetField(ref _advertisedRoutes, value); }
    public string WireguardExitConfig { get => _wireguardExitConfig; set => SetField(ref _wireguardExitConfig, value); }
    public string ExitDnsMode
    {
        get => _exitDnsMode;
        set
        {
            if (SetField(ref _exitDnsMode, value))
            {
                OnPropertyChanged(nameof(ExitDnsEncryptedSelected));
                OnPropertyChanged(nameof(ExitDnsThroughExitSelected));
            }
        }
    }
    public string ExitDnsDohProvider
    {
        get => _exitDnsDohProvider;
        set
        {
            if (SetField(ref _exitDnsDohProvider, value))
            {
                OnPropertyChanged(nameof(ExitDnsCustomSelected));
            }
        }
    }
    public string ExitDnsCustomDohUrl { get => _exitDnsCustomDohUrl; set => SetField(ref _exitDnsCustomDohUrl, value); }
    public string ExitDnsCustomDohBootstrapIps { get => _exitDnsCustomDohBootstrapIps; set => SetField(ref _exitDnsCustomDohBootstrapIps, value); }
    public string ExitDnsThroughExitServers { get => _exitDnsThroughExitServers; set => SetField(ref _exitDnsThroughExitServers, value); }
    public bool ExitDnsEncryptedSelected => ExitDnsMode == "encrypted";
    public bool ExitDnsCustomSelected => ExitDnsEncryptedSelected && ExitDnsDohProvider == "custom";
    public bool ExitDnsThroughExitSelected => ExitDnsMode == "through_exit";


    public bool UpdateChecking
    {
        get => _updateChecking;
        private set
        {
            if (SetField(ref _updateChecking, value))
            {
                OnPropertyChanged(nameof(UpdateInstallEnabled));
                CommandManager.InvalidateRequerySuggested();
            }
        }
    }

    public bool UpdateInstalling
    {
        get => _updateInstalling;
        private set
        {
            if (SetField(ref _updateInstalling, value))
            {
                OnPropertyChanged(nameof(UpdateInstallEnabled));
                CommandManager.InvalidateRequerySuggested();
            }
        }
    }

    public bool UpdateAvailable
    {
        get => _updateAvailable;
        private set
        {
            if (SetField(ref _updateAvailable, value))
            {
                OnPropertyChanged(nameof(UpdateStripeText));
                OnPropertyChanged(nameof(UpdateInstallEnabled));
                CommandManager.InvalidateRequerySuggested();
            }
        }
    }

    public string UpdateVersion
    {
        get => _updateVersion;
        private set
        {
            if (SetField(ref _updateVersion, value))
            {
                OnPropertyChanged(nameof(UpdateStripeText));
            }
        }
    }

    public string UpdateStatus
    {
        get => _updateStatus;
        private set => SetField(ref _updateStatus, value);
    }

    public bool AutoInstallUpdates
    {
        get => _autoInstallUpdates;
        set
        {
            if (!SetField(ref _autoInstallUpdates, value))
            {
                return;
            }
            SaveAutoInstallUpdates(value);
            if (value && UpdateInstallEnabled)
            {
                _ = InstallUpdateAsync();
            }
        }
    }

    public bool UpdateInstallEnabled => UpdateAvailable && _updateUsesCoreDownload && !UpdateChecking && !UpdateInstalling;

    public string UpdateStripeText => string.IsNullOrWhiteSpace(State.AppVersion)
        ? $"Update available: {UpdateVersion}"
        : $"Update available: {UpdateVersion} (you're on {State.AppVersion})";

    public QrMatrix JoinRequestQr
    {
        get => _joinRequestQr;
        private set => SetField(ref _joinRequestQr, value);
    }

    public QrMatrix PaidRouteWalletInvoiceQr
    {
        get => _paidRouteWalletInvoiceQr;
        private set => SetField(ref _paidRouteWalletInvoiceQr, value);
    }

    public string JoinRequestQrCodeOrLink => State.JoinRequestQrCodeOrLink;
    public bool ShowNetworkSetupChoices => string.IsNullOrWhiteSpace(_networkSetupMode);
    public bool ShowNetworkSetupCreate => _networkSetupMode == "create";
    public bool ShowNetworkSetupJoin => _networkSetupMode == "join";

    private void SetNetworkSetupMode(string mode)
    {
        if (_networkSetupMode == mode)
        {
            return;
        }
        _networkSetupMode = mode;
        OnPropertyChanged(nameof(ShowNetworkSetupChoices));
        OnPropertyChanged(nameof(ShowNetworkSetupCreate));
        OnPropertyChanged(nameof(ShowNetworkSetupJoin));
    }

    private NativeNetworkState? RuntimeActiveNetwork => State.Networks.FirstOrDefault(network => network.Enabled);
    public bool HasEnabledNetwork => RuntimeActiveNetwork is not null;
    public NativeNetworkState? ActiveNetwork =>
        State.Networks.FirstOrDefault(network => network.Id == _shownNetworkId)
        ?? RuntimeActiveNetwork
        ?? State.Networks.FirstOrDefault();
    public bool HasActiveNetwork => ActiveNetwork is not null;
    public bool ShowJoinRequestQr => !HasEnabledNetwork && !string.IsNullOrWhiteSpace(State.JoinRequestQrCodeOrLink);
    public string OfferExitNodeLabel
    {
        get
        {
            var name = string.IsNullOrWhiteSpace(ActiveNetwork?.Name) ? "this network" : ActiveNetwork!.Name;
            return $"Share this device's internet in {name}";
        }
    }
    public IEnumerable<NativeNetworkState> InactiveNetworks => State.Networks.Where(network => !network.Enabled);
    public NativeParticipantState? SelectedParticipant
    {
        get
        {
            var network = ActiveNetwork;
            return network is null ? null : ResolveSelectedParticipant(network);
        }
        set
        {
            var nextKey = value is null ? "" : ParticipantKey(value);
            SetSelectedParticipantKey(nextKey, ignoreTransientClear: true);
        }
    }
    public string SelectedParticipantKey
    {
        get => _selectedParticipantKey;
        set => SetSelectedParticipantKey(value, ignoreTransientClear: true);
    }
    public bool SelectedParticipantCanRename => ActiveNetwork?.LocalIsAdmin == true
        && SelectedParticipant is not null;
    public bool SelectedParticipantCanManage => ActiveNetwork?.LocalIsAdmin == true
        && SelectedParticipant is { IsSelf: false };
    public string ActiveNetworkName => DisplayNetworkName(ActiveNetwork);
    public string PublicFipsAddress => string.IsNullOrWhiteSpace(State.OwnNpub) ? "" : $"{State.OwnNpub}.fips";
    public bool PublicFipsRoutingEnabled => State.FipsHostTunnelEnabled && !ActionInFlight;
    public Brush ShownNetworkStatusBrush => ActiveNetwork?.Enabled == true ? ActiveNetworkBrush : InactiveNetworkBrush;
    public bool ShowNetworkStatusDot => State.Networks.Count > 1;
    public bool ShowLinkDeviceCard => ActiveNetwork?.Enabled == true;
    public string ActiveNetworkDisplayNetworkId => DisplayNetworkId(ActiveNetwork?.NetworkId ?? "");
    public string HeroSubtitle => $"{State.ConnectedPeerCount} of {State.ExpectedPeerCount} connected";
    public string VpnButtonText => State.VpnEnabled ? "On" : "Off";
    /// Mirrors `AppManager.vpnStatusText` on macOS so the header and the tray
    /// surface the same status string across platforms.
    public string VpnStatusText
    {
        get
        {
            if (!string.IsNullOrWhiteSpace(State.Error))
            {
                return State.Error;
            }
            if (State.ExitNodeBlocked)
            {
                return string.IsNullOrWhiteSpace(State.ExitNodeStatusText)
                    ? "Internet blocked"
                    : State.ExitNodeStatusText;
            }
            if (State.ExitNodeActive && !string.IsNullOrWhiteSpace(State.ExitNodeStatusText))
            {
                return State.ExitNodeStatusText;
            }
            if (State.VpnActive)
            {
                return string.IsNullOrWhiteSpace(State.VpnStatus) ? "VPN on" : State.VpnStatus;
            }
            if (State.VpnEnabled)
            {
                return string.IsNullOrWhiteSpace(State.VpnStatus) ? "Turning on" : State.VpnStatus;
            }
            if (DaemonStarting(State))
            {
                return State.VpnStatus;
            }
            return "Off";
        }
    }
    public Brush VpnStatusBrush => State.ExitNodeBlocked ? HeaderDangerBrush : TextSecondaryBrush;

    private static bool DaemonStarting(NativeAppState state) =>
        string.IsNullOrWhiteSpace(state.Error)
        && state.ServiceRunning
        && string.Equals(
            state.VpnStatus.Trim(),
            "Background service starting",
            StringComparison.Ordinal);

    public string ThisDeviceCopyValue => !string.IsNullOrWhiteSpace(State.OwnNpub) ? State.OwnNpub : State.TunnelIp;

    private static string FormatRemaining(ulong seconds)
    {
        if (seconds == 0)
        {
            return "off";
        }
        var days = seconds / 86_400;
        if (days > 0)
        {
            var hours = seconds % 86_400 / 3_600;
            return hours == 0 ? $"{days}d" : $"{days}d {hours}h";
        }
        var hoursOnly = seconds / 3_600;
        if (hoursOnly > 0)
        {
            var minutesOnly = seconds % 3_600 / 60;
            return minutesOnly == 0 ? $"{hoursOnly}h" : $"{hoursOnly}h {minutesOnly}m";
        }
        var minutes = seconds / 60;
        if (minutes == 0)
        {
            return $"{seconds}s";
        }
        var remSecs = seconds % 60;
        return remSecs == 0 ? $"{minutes}m" : $"{minutes}m{remSecs:D2}s";
    }

    private static string FormatPaidRouteMsat(ulong msat)
    {
        if (msat == 0)
        {
            return "0 sat";
        }
        var whole = msat / 1_000;
        var remainder = msat % 1_000;
        return remainder == 0 ? $"{whole} sat" : $"{whole}.{remainder:D3} sat";
    }

    private static bool PaidRouteSessionCanSignPayment(NativePaidRouteSessionState session) =>
        session.CanPay;
    public string ServiceSummary => State.ServiceInstalled ? "Service installed" : "Service missing";
    public string CliSummary => State.CliInstalled ? "CLI installed" : "CLI missing";
    public string SystemVersionLabel
    {
        get
        {
            var app = State.AppVersion.Trim();
            var daemon = State.DaemonBinaryVersion.Trim();
            return (string.IsNullOrEmpty(app), string.IsNullOrEmpty(daemon)) switch
            {
                (true, true) => "",
                (false, true) => $"gui v{app}",
                (true, false) => $"daemon v{daemon}",
                (false, false) when app == daemon => $"v{app}",
                _ => $"gui v{app} · daemon v{daemon}",
            };
        }
    }
    public string DiagnosticsInterface => string.IsNullOrWhiteSpace(State.Network.DefaultInterface) ? "unknown" : State.Network.DefaultInterface;
    public string DiagnosticsIpv4 => string.IsNullOrWhiteSpace(State.Network.PrimaryIpv4) ? "-" : State.Network.PrimaryIpv4;
    public string DiagnosticsIpv6 => string.IsNullOrWhiteSpace(State.Network.PrimaryIpv6) ? "-" : State.Network.PrimaryIpv6;
    public string DiagnosticsGateway => FirstNonEmpty(State.Network.GatewayIpv4, State.Network.GatewayIpv6, "unknown");
    public string DiagnosticsMapping => string.IsNullOrWhiteSpace(State.PortMapping.ActiveProtocol) ? "none" : State.PortMapping.ActiveProtocol;
    public string DiagnosticsExternal => string.IsNullOrWhiteSpace(State.PortMapping.ExternalEndpoint) ? "stun/direct" : State.PortMapping.ExternalEndpoint;
    public string DiagnosticsPeers => $"{State.ConnectedPeerCount}/{State.ExpectedPeerCount}";
    public string DiagnosticsFips => $"{State.FipsConnectedPeerCount}/{State.FipsRosterPeerCount} direct";
    public string DiagnosticsOtherFips => $"{State.NonFipsRosterPeerCount}";
    public ICommand ShowDevicesCommand { get; }
    public ICommand ShowAddNetworkCommand { get; }
    public ICommand ShowAddDeviceCommand { get; }
    public ICommand ShowInternetCommand { get; }
    public ICommand ShowPublicExitsCommand { get; }
    public ICommand ShowWalletCommand { get; }
    public ICommand ShowSellAccessCommand { get; }
    public ICommand ShowSettingsCommand { get; }
    public ICommand RefreshCommand { get; }
    public ICommand ToggleVpnCommand { get; }
    public ICommand CopyThisDeviceCommand { get; }
    public ICommand CopyPeerCommand { get; }
    public ICommand ImportJoinRequestQrImageCommand { get; }
    public ICommand AddParticipantCommand { get; }
    public ICommand SaveNodeCommand { get; }
    public ICommand AddRelayCommand { get; }
    public ICommand SaveRelaysCommand { get; }
    public ICommand ImportWireGuardExitCommand { get; }
    public ICommand SaveWireGuardExitCommand { get; }
    public ICommand SaveExitDnsCommand { get; }
    public ICommand CreateNetworkCommand { get; }
    public ICommand ShowCreateNetworkSetupCommand { get; }
    public ICommand ShowJoinNetworkSetupCommand { get; }
    public ICommand BackToNetworkSetupChoicesCommand { get; }
    public ICommand AddNetworkCommand { get; }
    public ICommand ManualAddNetworkCommand { get; }
    public ICommand ActivateInactiveNetworkCommand { get; }
    public ICommand SaveNetworkNameCommand { get; }
    public ICommand SaveNetworkMeshIdCommand { get; }
    public ICommand CopyNetworkIdCommand { get; }
    public ICommand InstallServiceCommand { get; }
    public ICommand EnableServiceCommand { get; }
    public ICommand DisableServiceCommand { get; }
    public ICommand InstallCliCommand { get; }
    public ICommand CheckUpdatesCommand { get; }
    public ICommand InstallUpdateCommand { get; }

    public async Task RefreshAsync()
    {
        using var nativeCall = _nativeCoreCallGate.TryEnterRefresh();
        if (nativeCall is null)
        {
            return;
        }
        try
        {
            var state = await Task.Run(_core.Refresh);
            ApplyState(state, syncDrafts: false);
        }
        catch (Exception error)
        {
            Notice = error.Message;
        }
    }

    public Task ToggleVpnAsync()
    {
        if (!State.VpnEnabled && State.ServiceSupported && !State.ServiceInstalled)
        {
            return DispatchAsync(NativeActions.InstallSystemService(), "Installing service");
        }
        return DispatchAsync(
            State.VpnEnabled ? NativeActions.DisconnectVpn() : NativeActions.ConnectVpn(),
            State.VpnEnabled ? "Turning VPN off" : "Turning VPN on");
    }

    internal static bool CanToggleVpn(
        bool actionInFlight,
        bool vpnControlSupported,
        bool hasRuntimeActiveNetwork,
        bool serviceSupported,
        bool serviceInstalled) =>
        !actionInFlight
        && vpnControlSupported
        && (hasRuntimeActiveNetwork || (serviceSupported && !serviceInstalled));

    public Task SetLaunchOnStartupAsync(bool enabled)
    {
        try
        {
            StartupService.SetLaunchOnStartup(enabled);
        }
        catch (Exception error)
        {
            Notice = error.Message;
            return Task.CompletedTask;
        }
        return DispatchAsync(
            NativeActions.UpdateSettings(new SettingsPatch { LaunchOnStartup = enabled }),
            "Saving startup");
    }

    private void SyncLaunchOnStartupRegistration()
    {
        try
        {
            StartupService.SyncLaunchOnStartup(State.StartupSettingsSupported && State.LaunchOnStartup);
        }
        catch (Exception error)
        {
            Notice = error.Message;
        }
    }

    public Task SetCloseToTrayAsync(bool enabled)
    {
        return DispatchAsync(
            NativeActions.UpdateSettings(new SettingsPatch { CloseToTrayOnClose = enabled }),
            "Saving tray behavior");
    }

    public Task SetAutoconnectAsync(bool enabled)
    {
        return DispatchAsync(
            NativeActions.UpdateSettings(new SettingsPatch { Autoconnect = enabled }),
            "Saving VPN option");
    }

    public Task SetFipsHostTunnelAsync(bool enabled)
    {
        return DispatchAsync(
            NativeActions.UpdateSettings(new SettingsPatch { FipsHostTunnelEnabled = enabled }),
            "Saving FIPS option");
    }

    public Task SetConnectToNonRosterFipsPeersAsync(bool enabled)
    {
        return DispatchAsync(
            NativeActions.UpdateSettings(new SettingsPatch { ConnectToNonRosterFipsPeers = enabled }),
            "Saving FIPS option");
    }

    public Task SetFipsNostrDiscoveryEnabledAsync(bool enabled)
    {
        return DispatchAsync(
            NativeActions.UpdateSettings(new SettingsPatch { FipsNostrDiscoveryEnabled = enabled }),
            "Saving FIPS option");
    }

    public Task SetFipsBootstrapEnabledAsync(bool enabled)
    {
        return DispatchAsync(
            NativeActions.UpdateSettings(new SettingsPatch { FipsBootstrapEnabled = enabled }),
            "Saving FIPS option");
    }


    public void CopyText(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return;
        }
        Clipboard.SetText(value);
        Notice = "Copied";
    }

    public async Task CheckUpdatesAsync(bool manual = true)
    {
        if (UpdateChecking || UpdateInstalling)
        {
            return;
        }
        UpdateChecking = true;
        if (manual)
        {
            UpdateStatus = "Checking for updates";
        }
        try
        {
            var result = await _updateService.CheckAsync(State.AppVersion, State.ConfigPath);
            UpdateAvailable = result.Available;
            UpdateVersion = result.Tag;
            _updateAssetUrl = result.Available ? result.AssetUrl : null;
            _updateUsesCoreDownload = result.Available && result.UseCoreDownload;
            OnPropertyChanged(nameof(UpdateInstallEnabled));
            CommandManager.InvalidateRequerySuggested();
            if (result.Available)
            {
                UpdateStatus = result.Message;
                if (AutoInstallUpdates && result.UseCoreDownload)
                {
                    await InstallUpdateAsync();
                }
            }
            else if (manual)
            {
                UpdateStatus = result.Message;
            }
            else
            {
                UpdateStatus = "";
            }
        }
        catch (Exception error)
        {
            _updateAssetUrl = null;
            _updateUsesCoreDownload = false;
            OnPropertyChanged(nameof(UpdateInstallEnabled));
            CommandManager.InvalidateRequerySuggested();
            if (manual)
            {
                UpdateStatus = error.Message;
            }
        }
        finally
        {
            UpdateChecking = false;
        }
    }

    private async Task InstallUpdateAsync()
    {
        if (!_updateUsesCoreDownload || UpdateInstalling)
        {
            return;
        }
        UpdateInstalling = true;
        UpdateStatus = $"Downloading {UpdateVersion}";
        try
        {
            var path = await _updateService.DownloadWithCoreAsync(State.AppVersion, State.ConfigPath);
            UpdateStatus = $"Downloaded {Path.GetFileName(path)}";
            if (!UpdateService.SkipOpen)
            {
                _ = Process.Start(new ProcessStartInfo(path) { UseShellExecute = true });
            }
        }
        catch (Exception error)
        {
            UpdateStatus = error.Message;
        }
        finally
        {
            UpdateInstalling = false;
        }
    }

    public void Dispose()
    {
        _refreshTimer.Stop();
        _updateTimer.Stop();
        _core.Dispose();
    }

    private async Task<bool> DispatchAsync(string actionJson, string status)
    {
        if (ActionInFlight)
        {
            return false;
        }
        var succeeded = false;
        ActionInFlight = true;
        // Defer the in-progress notice so fast actions (broadcast/listen toggle,
        // copy, etc.) never flash the notice card. The card collapses when empty,
        // so showing it for ~50ms shifts the entire content below — that's what
        // looked like a flicker on the Share page when toggling broadcast/listen.
        using var noticeCts = new CancellationTokenSource();
        if (SynchronizationContext.Current is not null)
        {
            _ = Task.Delay(TimeSpan.FromMilliseconds(250), noticeCts.Token).ContinueWith(
                _ => Notice = status,
                CancellationToken.None,
                TaskContinuationOptions.OnlyOnRanToCompletion,
                TaskScheduler.FromCurrentSynchronizationContext());
        }
        try
        {
            using var nativeCall = await _nativeCoreCallGate.EnterDispatchAsync();
            var state = await Task.Run(() => _core.Dispatch(actionJson));
#if DEBUG
            DebugRosterE2eTrace($"dispatch completed: {state.Error}");
#endif
            noticeCts.Cancel();
            ApplyState(state, syncDrafts: true);
            Notice = string.IsNullOrWhiteSpace(state.Error) ? "" : state.Error;
            succeeded = string.IsNullOrWhiteSpace(state.Error);
        }
        catch (Exception error)
        {
#if DEBUG
            DebugRosterE2eTrace($"dispatch threw: {error}");
#endif
            noticeCts.Cancel();
            Notice = error.Message;
        }
        finally
        {
            ActionInFlight = false;
        }
        return succeeded;
    }



}
