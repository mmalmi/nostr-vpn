using System.Diagnostics;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Navigation;
using NostrVpn.Windows.Core;
using NostrVpn.Windows.ViewModels;

namespace NostrVpn.Windows;

public partial class MainWindow : Window
{
    public MainWindow(AppViewModel viewModel)
    {
        InitializeComponent();
        DataContext = viewModel;
    }

    private AppViewModel ViewModel => (AppViewModel)DataContext;

    private void OpenHyperlink_RequestNavigate(object sender, RequestNavigateEventArgs e)
    {
        Process.Start(new ProcessStartInfo(e.Uri.AbsoluteUri) { UseShellExecute = true });
        e.Handled = true;
    }

    protected override void OnClosing(System.ComponentModel.CancelEventArgs e)
    {
        if (!App.IsQuitting && ViewModel.State.CloseToTrayOnClose)
        {
            e.Cancel = true;
            Hide();
            return;
        }
        base.OnClosing(e);
    }

    private void CopyPeer_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: string npub })
        {
            ViewModel.CopyText(npub);
        }
    }

    private void NetworkSwitcher_Click(object sender, MouseButtonEventArgs e)
    {
        if (sender is not FrameworkElement anchor)
        {
            return;
        }
        var menu = new ContextMenu
        {
            PlacementTarget = anchor,
            Placement = PlacementMode.Top,
        };
        foreach (var network in ViewModel.State.Networks)
        {
            var item = new MenuItem
            {
                Header = NetworkMenuHeader(network),
            };
            var networkId = network.Id;
            item.Click += (_, _) => ViewModel.SelectShownNetwork(networkId);
            menu.Items.Add(item);
        }
        if (menu.Items.Count > 0)
        {
            menu.Items.Add(new Separator());
        }
        var addItem = new MenuItem { Header = "Add network" };
        addItem.Click += (_, _) => ViewModel.ShowAddNetworkCommand.Execute(null);
        menu.Items.Add(addItem);
        menu.IsOpen = true;
    }

    private StackPanel NetworkMenuHeader(NativeNetworkState network)
    {
        var row = new StackPanel { Orientation = Orientation.Horizontal };
        if (ViewModel.State.Networks.Count > 1)
        {
            row.Children.Add(new TextBlock
            {
                Text = "●",
                Foreground = network.Enabled ? Brushes.SeaGreen : Brushes.DarkGray,
                Margin = new Thickness(0, 0, 6, 0),
                VerticalAlignment = VerticalAlignment.Center,
            });
        }
        row.Children.Add(new TextBlock
        {
            Text = string.IsNullOrWhiteSpace(network.Name) ? "Private network" : network.Name,
            VerticalAlignment = VerticalAlignment.Center,
        });
        return row;
    }

    private async void ToggleAdmin_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: NativeParticipantState participant })
        {
            await ViewModel.ToggleAdminAsync(participant);
        }
    }

    private async void RemoveParticipant_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: NativeParticipantState participant })
        {
            var name = string.IsNullOrWhiteSpace(participant.DisplayName) ? "this device" : participant.DisplayName;
            var result = MessageBox.Show(
                this,
                "This removes the device from the network's roster. They keep the network locally but won't be in this roster anymore.",
                $"Remove {name}?",
                MessageBoxButton.OKCancel,
                MessageBoxImage.Warning,
                MessageBoxResult.Cancel);
            if (result != MessageBoxResult.OK) return;
            await ViewModel.RemoveParticipantAsync(participant);
        }
    }

    private async void SetParticipantAlias_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: NativeParticipantState participant } button
            && FindParent<Grid>(button) is { } row
            && FindChild<TextBox>(row, "AliasInput") is { } aliasInput)
        {
            await ViewModel.SetParticipantAliasAsync(participant, aliasInput.Text);
        }
    }

    private async void SetEndpointHints_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: NativeParticipantState participant } button
            && FindParent<Grid>(button) is { } row
            && FindChild<TextBox>(row, "EndpointHintsInput") is { } hintsInput)
        {
            await ViewModel.SetParticipantEndpointHintsAsync(participant, hintsInput.Text);
        }
    }

    private async void DirectExit_Click(object sender, RoutedEventArgs e)
    {
        await ViewModel.SelectDirectExitAsync();
    }

    private async void SetExitNode_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: string npub })
        {
            await ViewModel.SelectPeerExitAsync(npub);
        }
    }

    private async void AdvertiseExit_Click(object sender, RoutedEventArgs e)
    {
        if (sender is CheckBox checkBox)
        {
            await ViewModel.SetAdvertiseExitNodeAsync(checkBox.IsChecked == true);
        }
    }

    private async void ExitLeakProtection_Click(object sender, RoutedEventArgs e)
    {
        if (sender is CheckBox checkBox)
        {
            await ViewModel.SetExitNodeLeakProtectionAsync(checkBox.IsChecked == true);
        }
    }

    private async void DiscoverPaidRoutes_Click(object sender, RoutedEventArgs e)
    {
        await ViewModel.DiscoverPaidRouteOffersAsync();
    }

    private async void SetManualPaidExitProvider_Click(object sender, RoutedEventArgs e)
    {
        await ViewModel.SetManualPaidExitProviderAsync();
    }

    private async void ClearManualPaidExitProvider_Click(object sender, RoutedEventArgs e)
    {
        await ViewModel.ClearManualPaidExitProviderAsync();
    }

    private async void RefreshPaidRouteWallet_Click(object sender, RoutedEventArgs e)
    {
        await ViewModel.RefreshPaidRouteWalletAsync();
    }

    private async void AddPaidRouteWalletMint_Click(object sender, RoutedEventArgs e)
    {
        await ViewModel.AddPaidRouteWalletMintAsync();
    }

    private async void TopUpPaidRouteWallet_Click(object sender, RoutedEventArgs e)
    {
        await ViewModel.TopUpPaidRouteWalletAsync();
    }

    private async void ReceivePaidRouteWalletToken_Click(object sender, RoutedEventArgs e)
    {
        await ViewModel.ReceivePaidRouteWalletTokenAsync();
    }

    private async void SendPaidRouteWalletToken_Click(object sender, RoutedEventArgs e)
    {
        await ViewModel.SendPaidRouteWalletTokenAsync();
    }

    private async void WithdrawPaidRouteWalletLightning_Click(object sender, RoutedEventArgs e)
    {
        await ViewModel.WithdrawPaidRouteWalletLightningAsync();
    }

    private void CopyWalletValue_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: string value })
        {
            ViewModel.CopyText(value);
        }
    }

    private async void StreamPaidRoutePayments_Click(object sender, RoutedEventArgs e)
    {
        await ViewModel.StreamPaidRoutePaymentsAsync();
    }

    private async void SendPaidRoutePaymentEnvelope_Click(object sender, RoutedEventArgs e)
    {
        await ViewModel.SendPaidRoutePaymentEnvelopeAsync();
    }

    private async void BuyPaidRouteOffer_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: NativePaidRouteOfferState offer })
        {
            await ViewModel.BuyPaidRouteOfferAsync(offer);
        }
    }

    private async void UsePaidRouteSession_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: NativePaidRouteSessionState session })
        {
            await ViewModel.SelectPaidRouteSessionAsync(session);
        }
    }

    private async void ProbePaidRouteSession_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: NativePaidRouteSessionState session })
        {
            await ViewModel.ProbePaidRouteSessionAsync(session);
        }
    }

    private async void OpenPaidRouteChannel_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: NativePaidRouteSessionState session })
        {
            await ViewModel.OpenPaidRouteChannelAsync(session);
        }
    }

    private async void SignPaidRoutePayment_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: NativePaidRouteSessionState session })
        {
            await ViewModel.SignPaidRoutePaymentAsync(session);
        }
    }

    private async void ClosePaidRouteChannel_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: NativePaidRouteSessionState session })
        {
            await ViewModel.ClosePaidRouteChannelAsync(session);
        }
    }

    private async void PaidExitEnabled_Click(object sender, RoutedEventArgs e)
    {
        if (sender is CheckBox checkBox)
        {
            await ViewModel.SetPaidExitEnabledAsync(checkBox.IsChecked == true);
        }
    }

    private async void SavePaidExitPrice_Click(object sender, RoutedEventArgs e)
    {
        await ViewModel.SavePaidExitPriceAsync();
    }
    private async void RelayEnabled_Click(object sender, RoutedEventArgs e)
    {
        if (sender is CheckBox { Tag: NativeRelayState relay } checkBox)
        {
            await ViewModel.SetRelayEnabledAsync(relay, checkBox.IsChecked == true);
        }
    }

    private async void RemoveRelay_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: NativeRelayState relay })
        {
            await ViewModel.RemoveRelayAsync(relay);
        }
    }

    private async void WireguardExit_Click(object sender, RoutedEventArgs e)
    {
        await ViewModel.SelectWireGuardUpstreamExitAsync();
    }

    private async void PaidAutomaticExit_Click(object sender, RoutedEventArgs e)
    {
        await ViewModel.SelectPaidAutomaticExitAsync();
    }

    private async void WalletFiatEnabled_Click(object sender, RoutedEventArgs e)
    {
        if (sender is CheckBox checkBox)
        {
            await ViewModel.SetWalletFiatEnabledAsync(checkBox.IsChecked == true);
        }
    }

    private async void WalletFiatCurrency_Changed(object sender, SelectionChangedEventArgs e)
    {
        if (sender is ComboBox { SelectedItem: ComboBoxItem item }
            && item.Content is string currency
            && !string.Equals(currency, ViewModel.State.WalletFiatCurrency, StringComparison.Ordinal))
        {
            await ViewModel.SetWalletFiatCurrencyAsync(currency);
        }
    }

    private async void PaidManualExit_Click(object sender, RoutedEventArgs e)
    {
        await ViewModel.SelectPaidManualExitAsync();
    }

    private async void Autoconnect_Click(object sender, RoutedEventArgs e)
    {
        if (sender is CheckBox checkBox)
        {
            await ViewModel.SetAutoconnectAsync(checkBox.IsChecked == true);
        }
    }

    private async void FipsHostTunnel_Click(object sender, RoutedEventArgs e)
    {
        if (sender is CheckBox checkBox)
        {
            await ViewModel.SetFipsHostTunnelAsync(checkBox.IsChecked == true);
        }
    }

    private async void ConnectToNonRosterFipsPeers_Click(object sender, RoutedEventArgs e)
    {
        if (sender is CheckBox checkBox)
        {
            await ViewModel.SetConnectToNonRosterFipsPeersAsync(checkBox.IsChecked == true);
        }
    }

    private async void FipsNostrDiscoveryEnabled_Click(object sender, RoutedEventArgs e)
    {
        if (sender is CheckBox checkBox)
        {
            await ViewModel.SetFipsNostrDiscoveryEnabledAsync(checkBox.IsChecked == true);
        }
    }

    private async void FipsBootstrapEnabled_Click(object sender, RoutedEventArgs e)
    {
        if (sender is CheckBox checkBox)
        {
            await ViewModel.SetFipsBootstrapEnabledAsync(checkBox.IsChecked == true);
        }
    }

    private async void LaunchOnStartup_Click(object sender, RoutedEventArgs e)
    {
        if (sender is CheckBox checkBox)
        {
            await ViewModel.SetLaunchOnStartupAsync(checkBox.IsChecked == true);
        }
    }

    private async void CloseToTray_Click(object sender, RoutedEventArgs e)
    {
        if (sender is CheckBox checkBox)
        {
            await ViewModel.SetCloseToTrayAsync(checkBox.IsChecked == true);
        }
    }

    private async void ActivateNetwork_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: string networkId })
        {
            await ViewModel.ActivateNetworkAsync(networkId);
        }
    }

    private async void RemoveNetwork_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: string networkId })
        {
            var network = ViewModel.State.Networks.FirstOrDefault(n => n.Id == networkId);
            var name = string.IsNullOrWhiteSpace(network?.Name) ? "this network" : network!.Name;
            var result = MessageBox.Show(
                this,
                "This deletes the network from this device.",
                $"Remove {name}?",
                MessageBoxButton.OKCancel,
                MessageBoxImage.Warning,
                MessageBoxResult.Cancel);
            if (result != MessageBoxResult.OK) return;
            await ViewModel.RemoveNetworkAsync(networkId);
        }
    }

    private static T? FindParent<T>(DependencyObject child) where T : DependencyObject
    {
        var current = VisualTreeHelper.GetParent(child);
        while (current is not null)
        {
            if (current is T match)
            {
                return match;
            }
            current = VisualTreeHelper.GetParent(current);
        }
        return null;
    }

    private static T? FindChild<T>(DependencyObject parent, string name) where T : FrameworkElement
    {
        for (var index = 0; index < VisualTreeHelper.GetChildrenCount(parent); index++)
        {
            var child = VisualTreeHelper.GetChild(parent, index);
            if (child is T element && element.Name == name)
            {
                return element;
            }
            var nested = FindChild<T>(child, name);
            if (nested is not null)
            {
                return nested;
            }
        }
        return null;
    }
}
