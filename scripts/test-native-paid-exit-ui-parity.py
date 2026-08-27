#!/usr/bin/env python3
"""Keep native paid-exit buyer UI capabilities aligned across supported apps."""

from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


def read(*paths: str) -> str:
    return "\n".join((ROOT / path).read_text(encoding="utf-8") for path in paths)


def require(label: str, text: str, needles: list[str]) -> None:
    missing = [needle for needle in needles if needle not in text]
    if missing:
        raise SystemExit(f"{label} paid-exit UI parity missing: {', '.join(missing)}")


macos = read(
    "macos/Sources/RootViewInternet.swift",
    "macos/Sources/RootViewPaidMarket.swift",
    "macos/Sources/RootViewWallet.swift",
    "macos/Sources/RootViewPaidSeller.swift",
    "macos/Sources/AppManagerPaidExit.swift",
)
linux = read(
    "linux/src/main/exit_nodes_page.rs",
    "linux/src/main/paid_routes_page.rs",
    "linux/src/main/paid_routes_page/wallet.rs",
)
windows = read(
    "windows/NostrVpn.Windows/MainWindow.xaml",
    "windows/NostrVpn.Windows/Core/Models.cs",
    "windows/NostrVpn.Windows/Core/NativeActions.cs",
    "windows/NostrVpn.Windows/ViewModels/AppViewModel.Internet.cs",
    "windows/NostrVpn.Windows/ViewModels/AppViewModel.InternetState.cs",
)
android = read(
    "android/app/src/main/java/org/nostrvpn/app/AndroidInternet.kt",
    "android/app/src/main/java/org/nostrvpn/app/AndroidPaidRoute.kt",
    "android/app/src/main/java/org/nostrvpn/app/AndroidWallet.kt",
    "android/app/src/main/java/org/nostrvpn/app/core/AppCoreClient.kt",
    "android/app/src/main/java/org/nostrvpn/app/core/Models.kt",
)
android_paid_route_ui = read(
    "android/app/src/main/java/org/nostrvpn/app/AndroidPaidRoute.kt",
)

common_operations = {
    "macOS": (
        macos,
        [
            '"paid_automatic"',
            '"paid_manual"',
            "discoverPaidRouteOffers",
            "setManualPaidExitProvider",
            "setPaidRouteMarketFilter",
            "visibleOffers",
            "streamPaidRoutePayments",
            "openPaidRouteChannelFromWallet",
            "signPaidRoutePaymentEnvelopeFromWallet",
            "closePaidRouteChannelFromWallet",
            "paidRouteWalletSettings",
        ],
    ),
    "Linux": (
        linux,
        [
            '"paid_automatic"',
            '"paid_manual"',
            "DiscoverPaidRouteOffers",
            "SetManualPaidExitProvider",
            "SetPaidRouteMarketFilter",
            "visible_offers",
            "StreamPaidRoutePayments",
            "OpenPaidRouteChannelFromWallet",
            "SignPaidRoutePaymentEnvelopeFromWallet",
            "ClosePaidRouteChannelFromWallet",
            "build_paid_route_wallet_card",
        ],
    ),
    "Windows": (
        windows,
        [
            '"paid_automatic"',
            '"paid_manual"',
            "DiscoverPaidRouteOffers",
            "SetManualPaidExitProvider",
            "SetPaidRouteMarketFilter",
            "NativePaidRouteMarketFilterState",
            "VisibleOffers",
            "StreamPaidRoutePayments",
            "OpenPaidRouteChannelFromWallet",
            "SignPaidRoutePaymentEnvelopeFromWallet",
            "ClosePaidRouteChannelFromWallet",
            "WalletView",
        ],
    ),
    "Android": (
        android,
        [
            '"paid_automatic"',
            '"paid_manual"',
            "discoverPaidRouteOffers",
            "setManualPaidExitProvider",
            "setPaidRouteMarketFilter",
            "visibleOffers",
            "streamPaidRoutePayments",
            "openPaidRouteChannelFromWallet",
            "signPaidRoutePaymentEnvelopeFromWallet",
            "closePaidRouteChannelFromWallet",
            "PaidRouteCardMode.Wallet",
        ],
    ),
}

for platform, (source, operations) in common_operations.items():
    require(platform, source, operations)

require("Android buyer controls", android_paid_route_ui, ["streamPaidRoutePayments"])

require(
    "macOS seller",
    macos,
    ["paidExitSellerAvailable", "paid-exit-seller-enabled", "collectPaidExitChannel"],
)
require(
    "Linux seller",
    linux,
    ["paid_exit_seller.supported", "nvpn-paid-exit-seller-enabled", "CollectPaidExitChannel"],
)
require(
    "Windows seller guard",
    windows,
    ["PaidExitSellerVisible => State.PaidExitSeller.Supported"],
)
if "PaidExitSellerCard" in android:
    raise SystemExit("Android must not expose unsupported paid-exit seller controls")

ios_policy = read("ios/Sources/AppStorePolicy.swift")
require(
    "iOS App Store policy",
    ios_policy,
    [
        'state.internetSource == "paid_automatic" || state.internetSource == "paid_manual"',
        'type.contains("paid_route")',
        'type.contains("paid_exit")',
    ],
)
ios_ui = "\n".join(
    path.read_text(encoding="utf-8")
    for path in (ROOT / "ios/Sources").glob("*View*.swift")
)
for forbidden in ("PaidRouteMarket", "PaidRouteWallet", "PaidExitSeller"):
    if forbidden in ios_ui:
        raise SystemExit(f"iOS must not expose paid-exit UI: found {forbidden}")

print("native paid-exit UI parity contract passed")
