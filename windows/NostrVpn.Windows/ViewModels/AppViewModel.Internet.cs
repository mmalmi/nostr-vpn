using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using Microsoft.Win32;
using NostrVpn.Windows.Core;

namespace NostrVpn.Windows.ViewModels;

public sealed partial class AppViewModel
{
    public Task SetAdvertiseExitNodeAsync(bool enabled)
    {
        return DispatchAsync(
            NativeActions.UpdateSettings(new SettingsPatch { AdvertiseExitNode = enabled }),
            "Saving internet sharing");
    }

    public Task SetExitNodeLeakProtectionAsync(bool enabled)
    {
        return DispatchAsync(
            NativeActions.UpdateSettings(new SettingsPatch { ExitNodeLeakProtection = enabled }),
            "Saving internet protection");
    }

    public Task SetWalletFiatEnabledAsync(bool enabled)
    {
        return DispatchAsync(
            NativeActions.UpdateSettings(new SettingsPatch { WalletFiatEnabled = enabled }),
            "Saving wallet display");
    }

    public Task SetWalletFiatCurrencyAsync(string currency)
    {
        return DispatchAsync(
            NativeActions.UpdateSettings(new SettingsPatch { WalletFiatCurrency = currency }),
            "Saving wallet currency");
    }

    public Task SetWireGuardExitEnabledAsync(bool enabled)
    {
        return DispatchAsync(
            NativeActions.UpdateSettings(new SettingsPatch { WireguardExitEnabled = enabled }),
            "Saving WireGuard");
    }

    public Task SetExitNodeAsync(string npub)
    {
        return DispatchAsync(
            NativeActions.UpdateSettings(new SettingsPatch { ExitNode = npub }),
            "Saving internet source");
    }

    public Task SelectDirectExitAsync()
    {
        return DispatchAsync(
            NativeActions.UpdateSettings(new SettingsPatch { InternetSource = "direct" }),
            "Saving internet source");
    }

    public Task SelectWireGuardUpstreamExitAsync()
    {
        return DispatchAsync(
            NativeActions.UpdateSettings(new SettingsPatch { InternetSource = "wireguard" }),
            "Saving internet source");
    }

    public Task SelectPeerExitAsync(string npub)
    {
        return DispatchAsync(
            NativeActions.UpdateSettings(new SettingsPatch
            {
                InternetSource = "private_vpn",
                ExitNode = npub,
            }),
            "Saving internet source");
    }

    public Task SelectPaidAutomaticExitAsync()
    {
        return DispatchAsync(
            NativeActions.UpdateSettings(new SettingsPatch { InternetSource = "paid_automatic" }),
            "Saving internet source");
    }

    public async Task SelectPaidManualExitAsync()
    {
        await DispatchAsync(
            NativeActions.UpdateSettings(new SettingsPatch { InternetSource = "paid_manual" }),
            "Saving internet source");
        Page = AppPage.PublicExits;
    }

    public Task DiscoverPaidRouteOffersAsync() =>
        DispatchAsync(NativeActions.DiscoverPaidRouteOffers(), "Finding sellers");

    public async Task ApplyPaidRouteMarketFilterAsync()
    {
        _paidRouteFilterEditing = false;
        await DispatchAsync(
            NativeActions.SetPaidRouteMarketFilter(
                PaidRouteFilterCountryCode,
                PaidRouteFilterRequireIpv4,
                PaidRouteFilterRequireIpv6,
                PaidRouteFilterSort),
            "Filtering sellers");
        SyncPaidRouteFilterDraft(State.PaidRouteMarket.Filter, force: true);
    }

    public async Task ClearPaidRouteMarketFilterAsync()
    {
        _paidRouteFilterEditing = false;
        await DispatchAsync(
            NativeActions.SetPaidRouteMarketFilter("", false, false, "quality"),
            "Clearing seller filters");
        SyncPaidRouteFilterDraft(State.PaidRouteMarket.Filter, force: true);
    }

    public Task SetManualPaidExitProviderAsync()
    {
        var provider = ManualPaidExitProvider.Trim();
        return string.IsNullOrWhiteSpace(provider)
            ? Task.CompletedTask
            : DispatchAsync(NativeActions.SetManualPaidExitProvider(provider), "Adding provider");
    }

    public async Task ClearManualPaidExitProviderAsync()
    {
        await DispatchAsync(NativeActions.ClearManualPaidExitProvider(), "Clearing provider");
        ManualPaidExitProvider = "";
    }

    public Task RefreshPaidRouteWalletAsync() =>
        DispatchAsync(NativeActions.RefreshPaidRouteWallet(), "Refreshing wallet");

    public Task AddPaidRouteWalletMintAsync()
    {
        var url = PaidRouteMintUrl.Trim();
        return string.IsNullOrWhiteSpace(url)
            ? Task.CompletedTask
            : DispatchAsync(NativeActions.AddPaidRouteWalletMint(url), "Adding mint");
    }

    public Task TopUpPaidRouteWalletAsync()
    {
        var amount = ParsePositiveUInt64(PaidRouteTopUpAmount);
        return amount is null
            ? Task.CompletedTask
            : DispatchAsync(
                NativeActions.TopUpPaidRouteWallet(null, amount.Value),
                "Creating top-up invoice");
    }

    public async Task ReceivePaidRouteWalletTokenAsync()
    {
        var token = PaidRouteReceiveToken.Trim();
        if (string.IsNullOrWhiteSpace(token))
        {
            return;
        }
        PaidRouteReceiveToken = "";
        await PreviewAndConfirmPaidRouteWalletTokenAsync(token);
    }

    public Task AutoReceivePaidRouteWalletTokenAsync()
    {
        return !ActionInFlight && LooksLikeCashuToken(PaidRouteReceiveToken)
            ? ReceivePaidRouteWalletTokenAsync()
            : Task.CompletedTask;
    }

    public async Task ScanPaidRouteWalletTokenAsync()
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
        var result = await Task.Run(() => _core.DecodeQrImage(dialog.FileName));
        if (!string.IsNullOrWhiteSpace(result.Error))
        {
            Notice = result.Error;
            return;
        }
        var token = result.Value.Trim();
        if (!LooksLikeCashuToken(token))
        {
            Notice = "QR does not contain a Cashu token";
            return;
        }
        await PreviewAndConfirmPaidRouteWalletTokenAsync(token);
    }

    private async Task PreviewAndConfirmPaidRouteWalletTokenAsync(string token)
    {
        await DispatchAsync(NativeActions.PreviewPaidRouteWalletToken(token), "Checking token");
        var preview = State.PaidRouteMarket.Wallet.LastAction;
        if (preview.Kind != "preview")
        {
            return;
        }
        var memo = string.IsNullOrWhiteSpace(preview.TokenMemo) ? "" : $"\nMemo: {preview.TokenMemo}";
        var message = $"Amount: {preview.AmountText}\nMint: {preview.MintUrl}{memo}\nStatus: {preview.StatusText}";
        if (!preview.TokenRedeemable)
        {
            MessageBox.Show(message, "Cashu token", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        if (MessageBox.Show(message + "\n\nRedeem this token?", "Redeem token?", MessageBoxButton.YesNo, MessageBoxImage.Question) == MessageBoxResult.Yes)
        {
            await DispatchAsync(NativeActions.ReceivePaidRouteWalletToken(token), "Redeeming token");
            if (!string.IsNullOrWhiteSpace(State.Error))
            {
                MessageBox.Show(State.Error, "Could not redeem token", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
    }

    public Task SendPaidRouteWalletTokenAsync()
    {
        var amount = ParsePositiveUInt64(PaidRouteSendAmount);
        return amount is null
            ? Task.CompletedTask
            : DispatchAsync(
                NativeActions.SendPaidRouteWalletToken(null, amount.Value),
                "Exporting token");
    }

    public Task WithdrawPaidRouteWalletLightningAsync()
    {
        var invoice = PaidRouteWithdrawInvoice.Trim();
        return string.IsNullOrWhiteSpace(invoice)
            ? Task.CompletedTask
            : DispatchAsync(
                NativeActions.WithdrawPaidRouteWalletLightning(null, invoice),
                "Paying invoice");
    }

    private static bool LooksLikeCashuToken(string value)
    {
        var token = value.Trim();
        return token.Length > 12 && token.StartsWith("cashu", StringComparison.OrdinalIgnoreCase);
    }

    public Task BuyPaidRouteOfferAsync(NativePaidRouteOfferState offer) =>
        string.IsNullOrWhiteSpace(offer.Key)
            ? Task.CompletedTask
            : DispatchAsync(NativeActions.BuyPaidRouteOffer(offer.Key), "Connecting");

    public Task SelectPaidRouteSessionAsync(NativePaidRouteSessionState session) =>
        string.IsNullOrWhiteSpace(session.SessionId)
            ? Task.CompletedTask
            : DispatchAsync(NativeActions.SelectPaidRouteSession(session.SessionId, true), "Connecting");

    public Task ProbePaidRouteSessionAsync(NativePaidRouteSessionState session) =>
        string.IsNullOrWhiteSpace(session.SessionId)
            ? Task.CompletedTask
            : DispatchAsync(NativeActions.ProbePaidRouteSession(session.SessionId), "Checking connection");

    public Task OpenPaidRouteChannelAsync(NativePaidRouteSessionState session) =>
        string.IsNullOrWhiteSpace(session.SessionId)
            ? Task.CompletedTask
            : DispatchAsync(NativeActions.OpenPaidRouteChannelFromWallet(session.SessionId), "Funding seller");

    public Task SignPaidRoutePaymentAsync(NativePaidRouteSessionState session) =>
        string.IsNullOrWhiteSpace(session.SessionId)
            ? Task.CompletedTask
            : DispatchAsync(NativeActions.SignPaidRoutePaymentEnvelopeFromWallet(session.SessionId), "Paying seller");

    public Task ClosePaidRouteChannelAsync(NativePaidRouteSessionState session) =>
        string.IsNullOrWhiteSpace(session.SessionId)
            ? Task.CompletedTask
            : DispatchAsync(NativeActions.ClosePaidRouteChannelFromWallet(session.SessionId), "Settling channel");

    public Task SendPaidRoutePaymentEnvelopeAsync()
    {
        var envelope = State.PaidRouteMarket.LastPaymentAction.EnvelopeJson.Trim();
        return string.IsNullOrWhiteSpace(envelope)
            ? Task.CompletedTask
            : DispatchAsync(NativeActions.SendPaidRoutePaymentEnvelope(envelope), "Sending payment");
    }

    public Task StreamPaidRoutePaymentsAsync() =>
        DispatchAsync(NativeActions.StreamPaidRoutePayments(), "Paying for usage");

    public Task SetPaidExitEnabledAsync(bool enabled)
    {
        return DispatchAsync(
            NativeActions.UpdateSettings(new SettingsPatch { PaidExitEnabled = enabled }),
            "Saving listing");
    }

    public Task SavePaidExitPriceAsync()
    {
        return ulong.TryParse(PaidExitPriceMsatPerGb.Trim(), out var price)
            ? DispatchAsync(
                NativeActions.UpdateSettings(new SettingsPatch { PaidExitPriceMsatPerGb = price }),
                "Saving price")
             : Task.CompletedTask;
    }
}
