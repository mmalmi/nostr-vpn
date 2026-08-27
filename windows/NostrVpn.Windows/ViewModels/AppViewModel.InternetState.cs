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
    public string ManualPaidExitProvider
    {
        get => _manualPaidExitProvider;
        set
        {
            if (SetField(ref _manualPaidExitProvider, value))
            {
                OnPropertyChanged(nameof(CanSetManualPaidExitProvider));
            }
        }
    }

    public string PaidExitPriceMsatPerGb
    {
        get => _paidExitPriceMsatPerGb;
        set
        {
            if (SetField(ref _paidExitPriceMsatPerGb, value))
            {
                OnPropertyChanged(nameof(CanSavePaidExitPrice));
            }
        }
    }

    public bool CanSetManualPaidExitProvider =>
        PaidRouteMarketVisible && !ActionInFlight && !string.IsNullOrWhiteSpace(ManualPaidExitProvider);

    public string PaidRouteFilterCountryCode
    {
        get => _paidRouteFilterCountryCode;
        set
        {
            var normalized = new string((value ?? "").Where(char.IsLetter).Take(2).ToArray()).ToUpperInvariant();
            if (SetField(ref _paidRouteFilterCountryCode, normalized))
            {
                _paidRouteFilterEditing = true;
            }
        }
    }

    public string PaidRouteFilterSort
    {
        get => _paidRouteFilterSort;
        set
        {
            var normalized = value is "price" or "newest" ? value : "quality";
            if (SetField(ref _paidRouteFilterSort, normalized))
            {
                _paidRouteFilterEditing = true;
            }
        }
    }

    public bool PaidRouteFilterRequireIpv4
    {
        get => _paidRouteFilterRequireIpv4;
        set
        {
            if (SetField(ref _paidRouteFilterRequireIpv4, value))
            {
                _paidRouteFilterEditing = true;
            }
        }
    }

    public bool PaidRouteFilterRequireIpv6
    {
        get => _paidRouteFilterRequireIpv6;
        set
        {
            if (SetField(ref _paidRouteFilterRequireIpv6, value))
            {
                _paidRouteFilterEditing = true;
            }
        }
    }

    public bool CanSavePaidExitPrice =>
        PaidExitSellerVisible && !ActionInFlight && ulong.TryParse(PaidExitPriceMsatPerGb.Trim(), out _);

    public string PaidRouteMintUrl
    {
        get => _paidRouteMintUrl;
        set
        {
            if (SetField(ref _paidRouteMintUrl, value))
            {
                OnPropertyChanged(nameof(CanAddPaidRouteWalletMint));
            }
        }
    }

    public string PaidRouteTopUpAmount
    {
        get => _paidRouteTopUpAmount;
        set
        {
            if (SetField(ref _paidRouteTopUpAmount, value))
            {
                OnPropertyChanged(nameof(CanTopUpPaidRouteWallet));
            }
        }
    }

    public string PaidRouteSendAmount
    {
        get => _paidRouteSendAmount;
        set
        {
            if (SetField(ref _paidRouteSendAmount, value))
            {
                OnPropertyChanged(nameof(CanSendPaidRouteWalletToken));
            }
        }
    }

    public string PaidRouteReceiveToken
    {
        get => _paidRouteReceiveToken;
        set
        {
            if (SetField(ref _paidRouteReceiveToken, value))
            {
                OnPropertyChanged(nameof(CanReceivePaidRouteWalletToken));
            }
        }
    }

    public string PaidRouteWithdrawInvoice
    {
        get => _paidRouteWithdrawInvoice;
        set
        {
            if (SetField(ref _paidRouteWithdrawInvoice, value))
            {
                OnPropertyChanged(nameof(CanWithdrawPaidRouteWalletLightning));
            }
        }
    }

    public bool CanAddPaidRouteWalletMint =>
        PaidRouteMarketVisible
        && !ActionInFlight
        && !string.IsNullOrWhiteSpace(PaidRouteMintUrl);

    public bool CanTopUpPaidRouteWallet =>
        PaidRouteMarketVisible
        && !ActionInFlight
        && HasPaidRouteWalletMint
        && ParsePositiveUInt64(PaidRouteTopUpAmount) is not null;

    public bool CanSendPaidRouteWalletToken =>
        PaidRouteMarketVisible
        && !ActionInFlight
        && HasPaidRouteWalletMint
        && ParsePositiveUInt64(PaidRouteSendAmount) is not null;

    public bool CanReceivePaidRouteWalletToken =>
        PaidRouteMarketVisible
        && !ActionInFlight
        && !string.IsNullOrWhiteSpace(PaidRouteReceiveToken);

    public bool CanWithdrawPaidRouteWalletLightning =>
        PaidRouteMarketVisible
        && !ActionInFlight
        && HasPaidRouteWalletMint
        && !string.IsNullOrWhiteSpace(PaidRouteWithdrawInvoice);

    public bool HasPaidRouteWalletMint =>
        !string.IsNullOrWhiteSpace(State.PaidRouteMarket.Wallet.DefaultMint);

    public bool PaidRouteMarketVisible => State.PaidRouteMarket.Supported;

    public bool PaidExitSellerVisible => State.PaidExitSeller.Supported;

    public IReadOnlyList<NativePaidRouteOfferState> PaidRouteVisibleOffers =>
        State.PaidRouteMarket.HiddenOfferCount > 0 || State.PaidRouteMarket.VisibleOffers.Count > 0
            ? State.PaidRouteMarket.VisibleOffers
            : State.PaidRouteMarket.Offers;

    public string PaidRouteHiddenOffersText => State.PaidRouteMarket.HiddenOfferCount == 0
        ? ""
        : $"{State.PaidRouteMarket.HiddenOfferCount} hidden by filters";

    // Bullet-style radio indicators next to each exit-node row.
    public string DirectExitMarker =>
        State.InternetSource == "direct" ? "●" : "○";

    public string WireguardExitMarker => State.InternetSource == "wireguard" ? "●" : "○";

    public string PaidAutomaticExitMarker => State.InternetSource == "paid_automatic" ? "●" : "○";

    public string PaidManualExitMarker => State.InternetSource == "paid_manual" ? "●" : "○";

    public IEnumerable<NativeParticipantState> ExitNodeParticipants =>
        (ActiveNetwork?.Participants ?? [])
            .Where(participant => participant.OffersExitNode && !participant.IsSelf)
            .OrderBy(participant => participant.DisplayName, StringComparer.OrdinalIgnoreCase);

    public string WireguardExitSubtitle
    {
        get
        {
            if (!State.WireguardExitConfigured)
            {
                return "No WireGuard config saved yet";
            }
            return string.IsNullOrWhiteSpace(State.WireguardExitEndpoint)
                ? "Configured"
                : State.WireguardExitEndpoint;
        }
    }

    public string PaidRouteWalletBalanceText => State.PaidRouteMarket.Wallet.BalanceKnown
        ? TextOr(State.PaidRouteMarket.Wallet.TotalBalanceText, FormatPaidRouteMsat(State.PaidRouteMarket.Wallet.TotalBalanceMsat))
        : "";

    public string PaidRouteWalletInvoiceExpiryText
    {
        get
        {
            var expiry = State.PaidRouteMarket.Wallet.LastAction.ExpiresAtUnix;
            return expiry == 0
                ? ""
                : $"Expires {DateTimeOffset.FromUnixTimeSeconds((long)expiry).ToLocalTime():g}";
        }
    }

    public string WalletNavigationText => string.IsNullOrWhiteSpace(State.PaidRouteMarket.Wallet.NavigationBalanceText)
        ? "Wallet"
        : $"Wallet {State.PaidRouteMarket.Wallet.NavigationBalanceText}";

    public string PaidRouteWalletFiatText => State.PaidRouteMarket.Wallet.FiatBalanceText;

    public string PaidRouteWalletRateText => string.IsNullOrWhiteSpace(State.PaidRouteMarket.Wallet.ExchangeRateText)
        ? ""
        : $"{State.PaidRouteMarket.Wallet.ExchangeRateText} · {State.PaidRouteMarket.Wallet.ExchangeRateSources}";

    public string PaidRouteMarketStatusText => string.IsNullOrWhiteSpace(State.PaidRouteMarket.StatusText)
        ? $"{State.PaidRouteMarket.Offers.Count} internet sellers"
        : State.PaidRouteMarket.StatusText;

    public string PaidExitSellerStatusText
    {
        get
        {
            if (!string.IsNullOrWhiteSpace(State.PaidExitSeller.StatusText))
            {
                return State.PaidExitSeller.StatusText
                    .Replace("Paid exit selling", "Selling internet")
                    .Replace("paid exit selling", "selling internet");
            }
            return State.PaidExitSeller.Supported
                ? "People can pay to use my internet"
                : "This platform cannot sell public internet access";
        }
    }

    public string PaidExitSellerSummary =>
        $"{TextOr(State.PaidExitSeller.CountryCode, "Country unset")} · {State.PaidExitSeller.PriceText}";

    public string PaidExitSellerTrialText =>
        $"Free test: {TextOr(State.PaidExitSeller.FreeProbeText, NativeDisplayText.TrafficUnitText(State.PaidExitSeller.FreeProbeUnits))} · Grace: {TextOr(State.PaidExitSeller.GraceText, NativeDisplayText.TrafficUnitText(State.PaidExitSeller.GraceUnits))}";

    public string PaidExitSellerChannelExpiryText =>
        $"Channel expires: {TextOr(State.PaidExitSeller.ChannelExpiryText, FormatRemaining(State.PaidExitSeller.ChannelExpirySecs))}";

    public string PaidExitSellerSettlementText => State.PaidExitSeller.SettlementText;

    public string PaidExitSellerPublicIpText => string.IsNullOrWhiteSpace(State.PaidExitSeller.PublicIpText)
        ? ""
        : $"Public IP: {State.PaidExitSeller.PublicIpText}";

    public string PaidExitSellerChannelCreditText =>
        $"{TextOr(State.PaidExitSeller.ChannelCreditTitleText, "Pending buyer credit")}: {TextOr(State.PaidExitSeller.ChannelCreditText, FormatPaidRouteMsat(State.PaidExitSeller.ChannelCreditMsat))}";

    public string PaidExitSellerChannelCreditHelpText => TextOr(
        State.PaidExitSeller.ChannelCreditHelpText,
        State.PaidExitSeller.ChannelCreditMsat > 0 ? "Collect to move it into wallet" : ""
    );

    public string PaidExitSellerPaymentStatusText
    {
        get
        {
            var action = State.PaidRouteMarket.LastPaymentAction;
            if (string.IsNullOrWhiteSpace(action.Kind) && string.IsNullOrWhiteSpace(action.StatusText))
            {
                return "";
            }
            return $"Payments: {TextOr(action.StatusText, NativeDisplayText.PaymentActionTitle(action.Kind))}";
        }
    }

    public string PaidExitSellerMintsText => State.PaidExitSeller.AcceptedMints.Count == 0
        ? "No accepted mints configured"
        : $"Accepted mints: {string.Join(", ", State.PaidExitSeller.AcceptedMints)}";

    public string PaidExitSellerSessionsText
    {
        get
        {
            var seller = State.PaidExitSeller;
            var pieces = new List<string>
            {
                $"{seller.CurrentConnectionCount} connected",
                $"{seller.PastConnectionCount} past",
                TextOr(seller.TotalTrafficText, $"{NativeDisplayText.FormatBytes(seller.TotalBillableBytes)} routed"),
                $"{TextOr(seller.TotalPaidText, FormatPaidRouteMsat(seller.TotalPaidMsat))} paid",
                $"{TextOr(seller.TotalDueText, FormatPaidRouteMsat(seller.TotalDueMsat))} due",
            };
            if (seller.TotalUnpaidMsat > 0)
            {
                pieces.Add($"{TextOr(seller.TotalUnpaidText, FormatPaidRouteMsat(seller.TotalUnpaidMsat))} behind");
            }
            return string.Join(" · ", pieces);
        }
    }

    public IEnumerable<string> PaidRouteWalletMintRows => State.PaidRouteMarket.Wallet.Mints.Select(mint =>
    {
        var marker = mint.IsDefault ? "default" : "mint";
        var balance = mint.BalanceKnown
            ? $" · {TextOr(mint.BalanceText, FormatPaidRouteMsat(mint.BalanceMsat))}"
            : "";
        return $"{marker} · {mint.Url}{balance}";
    });

    public string PaidRouteWalletMintsStatusText => State.PaidRouteMarket.Wallet.Mints.Count == 0
        ? "No wallet mints"
        : "";

    public bool PaidRouteHasStreamablePayments =>
        State.PaidRouteMarket.Sessions.Any(PaidRouteSessionCanSignPayment);
}
