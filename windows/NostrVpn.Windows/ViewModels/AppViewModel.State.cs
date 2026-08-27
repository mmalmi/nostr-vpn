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
    private void ApplyState(NativeAppState state, bool syncDrafts)
    {
        TagSelfParticipants(state);
        NormalizeSelectedParticipant(state);
        State = state;
        JoinRequestQr = string.IsNullOrWhiteSpace(state.JoinRequestQrCodeOrLink)
            ? new QrMatrix()
            : _core.QrMatrix(state.JoinRequestQrCodeOrLink);
        var invoice = state.PaidRouteMarket.Wallet.LastAction.PaymentRequest;
        PaidRouteWalletInvoiceQr = string.IsNullOrWhiteSpace(invoice)
            ? new QrMatrix()
            : _core.QrMatrix(invoice);
        _refreshTimer.Interval = RefreshIntervalForState(
            state,
            DateTimeOffset.UtcNow < _joinCoordinationRefreshUntil);
        if (syncDrafts)
        {
            SyncDrafts(state);
        }
        CommandManager.InvalidateRequerySuggested();
    }

    private void BeginJoinCoordinationRefresh()
    {
        _joinCoordinationRefreshUntil = DateTimeOffset.UtcNow + JoinCoordinationRefreshWindow;
        _refreshTimer.Interval = JoinCoordinationRefreshInterval;
    }

    internal static TimeSpan RefreshIntervalForState(
        NativeAppState state,
        bool joinCoordinationActive)
    {
        if (joinCoordinationActive)
        {
            return JoinCoordinationRefreshInterval;
        }
        return state.PaidRouteMarket.Wallet.LastAction.Kind == "topup"
            ? TimeSpan.FromSeconds(2)
            : IdleRefreshInterval;
    }

    private static void TagSelfParticipants(NativeAppState state)
    {
        var ownNpub = state.OwnNpub;
        foreach (var network in state.Networks)
        {
            foreach (var participant in network.Participants)
            {
                participant.IsSelf =
                    string.Equals(participant.MeshState, "local", StringComparison.OrdinalIgnoreCase)
                    || (!string.IsNullOrEmpty(ownNpub) && participant.Npub == ownNpub);
            }
        }
    }

    private void SyncDrafts(NativeAppState state)
    {
        var active = state.Networks.FirstOrDefault(network => network.Id == _shownNetworkId)
            ?? state.Networks.FirstOrDefault(network => network.Enabled)
            ?? state.Networks.FirstOrDefault();
        NodeName = state.NodeName;
        Endpoint = state.Endpoint;
        TunnelIp = state.TunnelIp;
        ListenPort = state.ListenPort.ToString();
        RelaysDraft = string.Join(Environment.NewLine, state.Relays.Select(relay => relay.Url));
        FipsHostInboundTcpPorts = state.FipsHostInboundTcpPorts;
        WireguardExitConfig = state.WireguardExitConfig;
        ExitDnsMode = state.ExitDnsMode;
        ExitDnsDohProvider = state.ExitDnsDohProvider;
        ExitDnsCustomDohUrl = state.ExitDnsCustomDohUrl;
        ExitDnsCustomDohBootstrapIps = state.ExitDnsCustomDohBootstrapIps;
        ExitDnsThroughExitServers = state.ExitDnsThroughExitServers;
        if (string.IsNullOrWhiteSpace(PaidRouteMintUrl))
        {
            PaidRouteMintUrl = state.PaidRouteMarket.Wallet.DefaultMint;
        }
        if (_lastSyncedManualPaidExitProvider != state.PaidRouteMarket.ManualProviderLink)
        {
            if (_lastSyncedManualPaidExitProvider is null
                || ManualPaidExitProvider == _lastSyncedManualPaidExitProvider)
            {
                ManualPaidExitProvider = state.PaidRouteMarket.ManualProviderLink;
            }
            _lastSyncedManualPaidExitProvider = state.PaidRouteMarket.ManualProviderLink;
        }
        if (_lastSyncedPaidExitPriceMsatPerGb != state.PaidExitSeller.PriceMsatPerGb)
        {
            if (_lastSyncedPaidExitPriceMsatPerGb is null
                || PaidExitPriceMsatPerGb == _lastSyncedPaidExitPriceMsatPerGb.Value.ToString())
            {
                PaidExitPriceMsatPerGb = state.PaidExitSeller.PriceMsatPerGb.ToString();
            }
            _lastSyncedPaidExitPriceMsatPerGb = state.PaidExitSeller.PriceMsatPerGb;
        }
        NetworkNameDraft = active?.Name ?? "";
        NetworkMeshIdDraft = DisplayNetworkId(active?.NetworkId ?? "");
    }

    private static string NormalizeNetworkIdInput(string value)
    {
        var trimmed = (value ?? string.Empty).Trim();
        var compact = new string(trimmed.Where(ch => !char.IsWhiteSpace(ch) && ch != '-').ToArray());
        if (compact.Length == 0 && trimmed.All(ch => char.IsWhiteSpace(ch) || ch == '-'))
        {
            return "";
        }
        return compact.Length > 0 && compact.All(Uri.IsHexDigit) ? compact.ToLowerInvariant() : trimmed;
    }

    private static string DisplayNetworkId(string value)
    {
        var trimmed = (value ?? string.Empty).Trim();
        if (trimmed.Length <= 4 || trimmed.Any(ch => !Uri.IsHexDigit(ch)))
        {
            return trimmed;
        }
        return string.Join("-", Enumerable.Range(0, (trimmed.Length + 3) / 4)
            .Select(index => trimmed.Substring(index * 4, Math.Min(4, trimmed.Length - index * 4))));
    }

    private static string DisplayNetworkName(NativeNetworkState? network)
    {
        if (network is null)
        {
            return "Nostr VPN";
        }
        return string.IsNullOrWhiteSpace(network.Name) ? "Private network" : network.Name;
    }

    private bool PageIsVisible(AppPage page) =>
        page switch
        {
            AppPage.PublicExits or AppPage.Wallet => PaidRouteMarketVisible,
            AppPage.SellAccess => PaidExitSellerVisible,
            _ => true,
        };

    private void RaiseDerivedStateChanged()
    {
        if (!string.IsNullOrWhiteSpace(_shownNetworkId)
            && State.Networks.All(network => network.Id != _shownNetworkId))
        {
            _shownNetworkId = "";
        }
        OnPropertyChanged(nameof(ActiveNetwork));
        OnPropertyChanged(nameof(ExitNodeParticipants));
        OnPropertyChanged(nameof(HasActiveNetwork));
        OnPropertyChanged(nameof(HasEnabledNetwork));
        OnPropertyChanged(nameof(ShowJoinRequestQr));
        OnPropertyChanged(nameof(OfferExitNodeLabel));
        OnPropertyChanged(nameof(InactiveNetworks));
        OnPropertyChanged(nameof(SelectedParticipantKey));
        OnPropertyChanged(nameof(SelectedParticipant));
        RaiseSelectedParticipantChanged();
        OnPropertyChanged(nameof(ActiveNetworkName));
        OnPropertyChanged(nameof(ShownNetworkStatusBrush));
        OnPropertyChanged(nameof(ShowNetworkStatusDot));
        OnPropertyChanged(nameof(ShowLinkDeviceCard));
        OnPropertyChanged(nameof(JoinRequestQrCodeOrLink));
        OnPropertyChanged(nameof(ShowJoinRequestQr));
        OnPropertyChanged(nameof(ShowNetworkSetupChoices));
        OnPropertyChanged(nameof(ShowNetworkSetupCreate));
        OnPropertyChanged(nameof(ShowNetworkSetupJoin));
        OnPropertyChanged(nameof(ActiveNetworkDisplayNetworkId));
        OnPropertyChanged(nameof(HeroSubtitle));
        OnPropertyChanged(nameof(VpnButtonText));
        OnPropertyChanged(nameof(VpnStatusText));
        OnPropertyChanged(nameof(VpnStatusBrush));
        OnPropertyChanged(nameof(UpdateStripeText));
        OnPropertyChanged(nameof(ThisDeviceCopyValue));
        OnPropertyChanged(nameof(PublicFipsAddress));
        OnPropertyChanged(nameof(PublicFipsRoutingEnabled));
        OnPropertyChanged(nameof(ServiceSummary));
        OnPropertyChanged(nameof(CliSummary));
        OnPropertyChanged(nameof(SystemVersionLabel));
        OnPropertyChanged(nameof(DiagnosticsInterface));
        OnPropertyChanged(nameof(DiagnosticsIpv4));
        OnPropertyChanged(nameof(DiagnosticsIpv6));
        OnPropertyChanged(nameof(DiagnosticsGateway));
        OnPropertyChanged(nameof(DiagnosticsMapping));
        OnPropertyChanged(nameof(DiagnosticsExternal));
        OnPropertyChanged(nameof(DiagnosticsPeers));
        OnPropertyChanged(nameof(DiagnosticsFips));
        OnPropertyChanged(nameof(DiagnosticsOtherFips));
        OnPropertyChanged(nameof(DirectExitMarker));
        OnPropertyChanged(nameof(WireguardExitMarker));
        OnPropertyChanged(nameof(PaidAutomaticExitMarker));
        OnPropertyChanged(nameof(PaidManualExitMarker));
        OnPropertyChanged(nameof(WireguardExitSubtitle));
        OnPropertyChanged(nameof(PaidRouteMarketVisible));
        OnPropertyChanged(nameof(PaidExitSellerVisible));
        OnPropertyChanged(nameof(PaidRouteWalletBalanceText));
        OnPropertyChanged(nameof(PaidRouteWalletInvoiceQr));
        OnPropertyChanged(nameof(PaidRouteWalletInvoiceExpiryText));
        OnPropertyChanged(nameof(HasPaidRouteWalletMint));
        OnPropertyChanged(nameof(WalletNavigationText));
        OnPropertyChanged(nameof(PaidRouteWalletFiatText));
        OnPropertyChanged(nameof(PaidRouteWalletRateText));
        OnPropertyChanged(nameof(PaidRouteMarketStatusText));
        OnPropertyChanged(nameof(PaidExitSellerStatusText));
        OnPropertyChanged(nameof(PaidExitSellerSummary));
        OnPropertyChanged(nameof(PaidExitSellerTrialText));
        OnPropertyChanged(nameof(PaidExitSellerChannelExpiryText));
        OnPropertyChanged(nameof(PaidExitSellerSettlementText));
        OnPropertyChanged(nameof(PaidExitSellerPublicIpText));
        OnPropertyChanged(nameof(PaidExitSellerChannelCreditText));
        OnPropertyChanged(nameof(PaidExitSellerChannelCreditHelpText));
        OnPropertyChanged(nameof(PaidExitSellerPaymentStatusText));
        OnPropertyChanged(nameof(PaidExitSellerMintsText));
        OnPropertyChanged(nameof(PaidExitSellerSessionsText));
        OnPropertyChanged(nameof(PaidRouteWalletMintRows));
        OnPropertyChanged(nameof(PaidRouteWalletMintsStatusText));
        OnPropertyChanged(nameof(PaidRouteHasStreamablePayments));
        RaisePaidRouteWalletInputStateChanged();
    }

    private void RaisePaidRouteWalletInputStateChanged()
    {
        OnPropertyChanged(nameof(CanSetManualPaidExitProvider));
        OnPropertyChanged(nameof(CanSavePaidExitPrice));
        OnPropertyChanged(nameof(CanAddPaidRouteWalletMint));
        OnPropertyChanged(nameof(CanTopUpPaidRouteWallet));
        OnPropertyChanged(nameof(CanSendPaidRouteWalletToken));
        OnPropertyChanged(nameof(CanReceivePaidRouteWalletToken));
        OnPropertyChanged(nameof(CanWithdrawPaidRouteWalletLightning));
    }

    private void RaiseSelectedParticipantChanged()
    {
        OnPropertyChanged(nameof(SelectedParticipantCanRename));
        OnPropertyChanged(nameof(SelectedParticipantCanManage));
    }

    private void NormalizeSelectedParticipant(NativeAppState state)
    {
        var network = state.Networks.FirstOrDefault(network => network.Id == _shownNetworkId)
            ?? state.Networks.FirstOrDefault(network => network.Enabled)
            ?? state.Networks.FirstOrDefault();
        if (network is null || network.Participants.Count == 0)
        {
            _selectedParticipantKey = "";
            return;
        }
        if (!string.IsNullOrWhiteSpace(_selectedParticipantKey)
            && network.Participants.FirstOrDefault(participant => ParticipantMatchesKey(participant, _selectedParticipantKey)) is { } selected)
        {
            _selectedParticipantKey = ParticipantKey(selected);
            return;
        }
        _selectedParticipantKey = SortedParticipants(network).FirstOrDefault() is { } first
            ? ParticipantKey(first)
            : "";
    }

    private NativeParticipantState? ResolveSelectedParticipant(NativeNetworkState network)
    {
        if (!string.IsNullOrWhiteSpace(_selectedParticipantKey))
        {
            var selected = network.Participants.FirstOrDefault(participant => ParticipantMatchesKey(participant, _selectedParticipantKey));
            if (selected is not null)
            {
                return selected;
            }
        }
        return SortedParticipants(network).FirstOrDefault();
    }

    private static IEnumerable<NativeParticipantState> SortedParticipants(NativeNetworkState network)
        => network.Participants
            .OrderBy(participant => !participant.IsSelf)
            .ThenBy(participant => !participant.Reachable)
            .ThenBy(participant => participant.DisplayName, StringComparer.OrdinalIgnoreCase);

    private static string ParticipantKey(NativeParticipantState participant)
        => participant.SelectionKey;

    private static bool ParticipantMatchesKey(NativeParticipantState participant, string key)
    {
        if (string.IsNullOrWhiteSpace(key))
        {
            return false;
        }
        return string.Equals(participant.SelectionKey, key, StringComparison.Ordinal)
            || (!string.IsNullOrWhiteSpace(participant.PubkeyHex)
                && string.Equals(participant.PubkeyHex, key, StringComparison.OrdinalIgnoreCase))
            || (!string.IsNullOrWhiteSpace(participant.Npub)
                && string.Equals(participant.Npub, key, StringComparison.Ordinal));
    }

    private void SetSelectedParticipantKey(string? value, bool ignoreTransientClear)
    {
        var nextKey = (value ?? string.Empty).Trim();
        if (nextKey.Length == 0 && ignoreTransientClear && CurrentSelectedParticipantStillExists())
        {
            return;
        }
        if (_selectedParticipantKey == nextKey)
        {
            return;
        }
        _selectedParticipantKey = nextKey;
        OnPropertyChanged(nameof(SelectedParticipantKey));
        OnPropertyChanged(nameof(SelectedParticipant));
        RaiseSelectedParticipantChanged();
    }

    private bool CurrentSelectedParticipantStillExists()
    {
        var network = ActiveNetwork;
        return network is not null
            && !string.IsNullOrWhiteSpace(_selectedParticipantKey)
            && network.Participants.Any(participant => ParticipantMatchesKey(participant, _selectedParticipantKey));
    }

    private static string FirstNonEmpty(string first, string second, string fallback)
    {
        if (!string.IsNullOrWhiteSpace(first))
        {
            return first;
        }
        return string.IsNullOrWhiteSpace(second) ? fallback : second;
    }

    private static string TextOr(string value, string fallback)
        => string.IsNullOrWhiteSpace(value) ? fallback : value;

    private static string? OptionalTrimmed(string value)
    {
        var trimmed = value.Trim();
        return string.IsNullOrWhiteSpace(trimmed) ? null : trimmed;
    }

    private static ulong? ParsePositiveUInt64(string value)
    {
        return ulong.TryParse(value.Trim(), out var parsed) && parsed > 0
            ? parsed
            : null;
    }

    private static bool LoadAutoInstallUpdates()
    {
        using var key = Registry.CurrentUser.OpenSubKey(@"Software\Nostr VPN");
        return key?.GetValue("AutoInstallUpdates") is int value && value != 0;
    }

    private static void SaveAutoInstallUpdates(bool enabled)
    {
        using var key = Registry.CurrentUser.CreateSubKey(@"Software\Nostr VPN");
        key?.SetValue("AutoInstallUpdates", enabled ? 1 : 0, RegistryValueKind.DWord);
    }

    private static TimeSpan LoadUpdatePollInterval()
    {
        var raw = Environment.GetEnvironmentVariable("NVPN_UPDATE_POLL_SECONDS");
        return double.TryParse(raw, out var seconds) && seconds > 0
            ? TimeSpan.FromSeconds(seconds)
            : TimeSpan.FromHours(6);
    }

    private bool SetField<T>(ref T field, T value, [CallerMemberName] string propertyName = "")
    {
        if (EqualityComparer<T>.Default.Equals(field, value))
        {
            return false;
        }
        field = value;
        OnPropertyChanged(propertyName);
        return true;
    }

    private void OnPropertyChanged([CallerMemberName] string propertyName = "")
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}
