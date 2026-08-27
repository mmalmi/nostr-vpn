package org.nostrvpn.app

import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.width
import androidx.compose.material3.Button
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Checkbox
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import org.json.JSONObject
import org.nostrvpn.app.core.AppState
import org.nostrvpn.app.core.NativeActions
import org.nostrvpn.app.core.PaidRouteMarketState
import org.nostrvpn.app.core.PaidRouteOfferState
import org.nostrvpn.app.core.PaidRouteSessionState

internal enum class PaidRouteCardMode {
    Market,
    Wallet,
}

private enum class PaidRouteWalletFlow { Receive, Send }

@Composable
internal fun PaidRouteMarketCard(
    state: AppState,
    dispatch: (JSONObject) -> Unit,
    mode: PaidRouteCardMode,
    qrJson: ((String) -> JSONObject)? = null,
) {
    val market = state.paidRouteMarket
    var mintUrl by remember { mutableStateOf(market.wallet.defaultMint) }
    var token by remember { mutableStateOf("") }
    var topUpAmount by remember { mutableStateOf("") }
    var sendAmount by remember { mutableStateOf("") }
    var withdrawInvoice by remember { mutableStateOf("") }
    var walletFlow by remember { mutableStateOf<PaidRouteWalletFlow?>(null) }
    var walletTokenScannerVisible by remember { mutableStateOf(false) }
    var pendingWalletToken by remember { mutableStateOf<String?>(null) }
    var redeemingWalletToken by remember { mutableStateOf(false) }
    var filterCountry by remember { mutableStateOf(market.filter.countryCode) }
    var filterIpv4 by remember { mutableStateOf(market.filter.requireIpv4) }
    var filterIpv6 by remember { mutableStateOf(market.filter.requireIpv6) }
    var filterSort by remember { mutableStateOf(market.filter.sort.ifBlank { "quality" }) }
    var manualProvider by remember { mutableStateOf(market.manualProviderLink) }
    LaunchedEffect(
        market.filter.countryCode,
        market.filter.requireIpv4,
        market.filter.requireIpv6,
        market.filter.sort,
    ) {
        filterCountry = market.filter.countryCode
        filterIpv4 = market.filter.requireIpv4
        filterIpv6 = market.filter.requireIpv6
        filterSort = market.filter.sort.ifBlank { "quality" }
    }
    LaunchedEffect(market.manualProviderLink) {
        manualProvider = market.manualProviderLink
    }
    AppCard {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text(
                    if (mode == PaidRouteCardMode.Wallet) "Wallet" else "Buy Internet",
                    style = MaterialTheme.typography.titleMedium,
                )
                if (mode == PaidRouteCardMode.Market) {
                    Text(
                        "Experimental",
                        color = Muted,
                        style = MaterialTheme.typography.labelSmall,
                    )
                }
                if (market.wallet.balanceKnown) {
                    Text(
                        market.wallet.totalBalanceText.ifBlank { formatPaidRouteMsat(market.wallet.totalBalanceMsat) },
                        color = if (mode == PaidRouteCardMode.Wallet) MaterialTheme.colorScheme.onSurface else Muted,
                        style = if (mode == PaidRouteCardMode.Wallet) MaterialTheme.typography.headlineLarge else MaterialTheme.typography.bodySmall,
                        fontWeight = if (mode == PaidRouteCardMode.Wallet) FontWeight.Bold else FontWeight.Normal,
                    )
                }
                if (state.walletFiatEnabled && market.wallet.fiatBalanceText.isNotBlank()) {
                    Text("≈ ${market.wallet.fiatBalanceText}", color = Muted, style = MaterialTheme.typography.bodySmall)
                }
                if (mode == PaidRouteCardMode.Wallet && market.wallet.exchangeRateText.isNotBlank()) {
                    Text(
                        "${market.wallet.exchangeRateText} · ${market.wallet.exchangeRateSources}",
                        color = Muted,
                        style = MaterialTheme.typography.labelSmall,
                    )
                }
            }
            if (mode == PaidRouteCardMode.Market) {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedButton(
                        enabled = market.sessions.any(::paidRouteSessionCanSignPayment),
                        onClick = { dispatch(NativeActions.streamPaidRoutePayments()) },
                    ) {
                        Text("Pay")
                    }
                    Button(
                        enabled = market.supported,
                        onClick = { dispatch(NativeActions.discoverPaidRouteOffers()) },
                    ) {
                        Text("Find")
                    }
                }
            }
        }
        if (mode == PaidRouteCardMode.Market && market.statusText.isNotBlank()) {
            Text(market.statusText, color = Muted, style = MaterialTheme.typography.bodySmall)
        }
        if (!market.supported) {
            Text(
                if (mode == PaidRouteCardMode.Wallet) {
                    "Wallet is not supported on this platform"
                } else {
                    "Buying internet is not supported on this platform"
                },
                color = Muted,
            )
            return@AppCard
        }

        when (mode) {
            PaidRouteCardMode.Market -> {
                OutlinedTextField(
                    value = manualProvider,
                    onValueChange = { manualProvider = it },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                    label = { Text("Provider npub or paid exit link") },
                )
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(
                        enabled = manualProvider.isNotBlank(),
                        onClick = { dispatch(NativeActions.setManualPaidExitProvider(manualProvider.trim())) },
                    ) { Text("Add provider") }
                    if (market.manualProviderLink.isNotBlank()) {
                        OutlinedButton(onClick = { dispatch(NativeActions.clearManualPaidExitProvider()) }) {
                            Text("Clear")
                        }
                    }
                }
                if (market.manualProviderStatusText.isNotBlank()) {
                    Text(market.manualProviderStatusText, color = Muted, style = MaterialTheme.typography.bodySmall)
                }

                PaidRouteMarketFilterControls(
                    market = market,
                    country = filterCountry,
                    onCountryChange = { filterCountry = it },
                    requireIpv4 = filterIpv4,
                    onRequireIpv4Change = { filterIpv4 = it },
                    requireIpv6 = filterIpv6,
                    onRequireIpv6Change = { filterIpv6 = it },
                    sort = filterSort,
                    onSortChange = { sort ->
                        filterSort = sort
                        dispatchPaidRouteMarketFilter(
                            dispatch,
                            filterCountry,
                            filterIpv4,
                            filterIpv6,
                            sort,
                        )
                    },
                    onApply = {
                        dispatchPaidRouteMarketFilter(
                            dispatch,
                            filterCountry,
                            filterIpv4,
                            filterIpv6,
                            filterSort,
                        )
                    },
                    onClear = {
                        filterCountry = ""
                        filterIpv4 = false
                        filterIpv6 = false
                        filterSort = "quality"
                        dispatchPaidRouteMarketFilter(dispatch, "", false, false, "quality")
                    },
                )

                PaidRoutePaymentActionResult(market.lastPaymentAction, dispatch)

                HorizontalDivider()
                Text("Offers", style = MaterialTheme.typography.titleSmall)
                val visibleOffers = if (market.hiddenOfferCount > 0 || market.visibleOffers.isNotEmpty()) {
                    market.visibleOffers
                } else {
                    market.offers
                }
                if (market.offers.isEmpty()) {
                    Text("No internet sellers found", color = Muted, style = MaterialTheme.typography.bodySmall)
                } else if (visibleOffers.isEmpty()) {
                    Text("No matching sellers", color = Muted, style = MaterialTheme.typography.bodySmall)
                } else {
                    if (market.hiddenOfferCount > 0) {
                        Text(
                            "${market.hiddenOfferCount} hidden by filters",
                            color = Muted,
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                    visibleOffers.take(6).forEach { offer ->
                        PaidRouteOfferRow(state, offer, dispatch)
                    }
                }

                HorizontalDivider()
                Text("Your Paid Internet", style = MaterialTheme.typography.titleSmall)
                if (market.sessions.isEmpty()) {
                    Text("No seller selected", color = Muted, style = MaterialTheme.typography.bodySmall)
                } else {
                    market.sessions.forEach { session ->
                        PaidRouteSessionRow(session, market.lastPaymentAction.envelopeJson, dispatch)
                    }
                }
            }
            PaidRouteCardMode.Wallet -> {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(
                        modifier = Modifier.weight(1f),
                        onClick = { walletFlow = PaidRouteWalletFlow.Receive },
                    ) {
                        Text("Receive")
                    }
                    Button(
                        modifier = Modifier.weight(1f),
                        onClick = { walletFlow = PaidRouteWalletFlow.Send },
                    ) {
                        Text("Send")
                    }
                }
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                    OutlinedTextField(
                        value = mintUrl,
                        onValueChange = { mintUrl = it },
                        modifier = Modifier.weight(1f),
                        singleLine = true,
                        label = { Text("Mint URL") },
                    )
                    Button(
                        enabled = mintUrl.trim().isNotEmpty(),
                        onClick = {
                            dispatch(NativeActions.addPaidRouteWalletMint(mintUrl.trim(), null))
                        },
                    ) {
                        Text("Add")
                    }
                }
                OutlinedButton(onClick = { dispatch(NativeActions.refreshPaidRouteWallet()) }) {
                    Text("Refresh wallet")
                }
                HorizontalDivider()
                Text("Mints", style = MaterialTheme.typography.titleSmall)
                if (market.wallet.mints.isEmpty()) {
                    Text("No wallet mints", color = Muted, style = MaterialTheme.typography.bodySmall)
                } else {
                    market.wallet.mints.forEach { mint ->
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Column(Modifier.weight(1f)) {
                                Text(mint.url, fontWeight = FontWeight.SemiBold)
                                if (mint.balanceKnown) {
                                    Text(
                                        mint.balanceText.ifBlank { formatPaidRouteMsat(mint.balanceMsat) },
                                        color = Muted,
                                        style = MaterialTheme.typography.bodySmall,
                                    )
                                }
                            }
                            if (mint.isDefault || mint.url == market.wallet.defaultMint) {
                                Text("Default", color = Accent, style = MaterialTheme.typography.bodySmall)
                            } else {
                                OutlinedButton(onClick = {
                                    dispatch(NativeActions.setPaidRouteDefaultMint(mint.url))
                                }) {
                                    Text("Default")
                                }
                            }
                            Spacer(Modifier.width(6.dp))
                            OutlinedButton(onClick = {
                                dispatch(NativeActions.removePaidRouteWalletMint(mint.url))
                            }) {
                                Text("Remove")
                            }
                        }
                    }
                }
                PaidRouteWalletActionResult(market.wallet.lastAction)
            }
        }
    }

    walletFlow?.let { flow ->
        val hasMint = market.wallet.defaultMint.isNotBlank()
        AlertDialog(
            onDismissRequest = { walletFlow = null },
            title = { Text(if (flow == PaidRouteWalletFlow.Receive) "Receive" else "Send") },
            text = {
                Column(
                    modifier = Modifier.verticalScroll(rememberScrollState()),
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    Text("Lightning", style = MaterialTheme.typography.titleSmall)
                    if (!hasMint) {
                        Text("Add a mint before using Lightning.", color = Muted, style = MaterialTheme.typography.bodySmall)
                    }
                    if (flow == PaidRouteWalletFlow.Receive) {
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                            OutlinedTextField(
                                value = topUpAmount,
                                onValueChange = { topUpAmount = it },
                                modifier = Modifier.weight(1f),
                                singleLine = true,
                                label = { Text("Amount in sats") },
                            )
                            Button(
                                enabled = hasMint && parsePositivePaidRouteAmount(topUpAmount) != null,
                                onClick = {
                                    val amount = parsePositivePaidRouteAmount(topUpAmount) ?: return@Button
                                    dispatch(NativeActions.topUpPaidRouteWallet(null, amount))
                                },
                            ) { Text("Invoice") }
                        }
                    } else {
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                            OutlinedTextField(
                                value = withdrawInvoice,
                                onValueChange = { withdrawInvoice = it },
                                modifier = Modifier.weight(1f),
                                singleLine = true,
                                label = { Text("Invoice") },
                            )
                            Button(
                                enabled = hasMint && withdrawInvoice.trim().isNotEmpty(),
                                onClick = {
                                    dispatch(NativeActions.withdrawPaidRouteWalletLightning(null, withdrawInvoice.trim()))
                                },
                            ) { Text("Pay") }
                        }
                    }

                    Text("Token", style = MaterialTheme.typography.titleSmall)
                    if (flow == PaidRouteWalletFlow.Receive) {
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                            OutlinedTextField(
                                value = token,
                                onValueChange = { value ->
                                    token = value
                                    if (isLikelyCashuToken(value)) {
                                        val pastedToken = value.trim()
                                        token = ""
                                        redeemingWalletToken = false
                                        pendingWalletToken = pastedToken
                                        dispatch(NativeActions.previewPaidRouteWalletToken(pastedToken))
                                    }
                                },
                                modifier = Modifier.weight(1f),
                                singleLine = true,
                                label = { Text("Paste token") },
                            )
                            Button(onClick = { walletTokenScannerVisible = true }) {
                                Text("Scan QR")
                            }
                        }
                    } else {
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                            OutlinedTextField(
                                value = sendAmount,
                                onValueChange = { sendAmount = it },
                                modifier = Modifier.weight(1f),
                                singleLine = true,
                                label = { Text("Amount in sats") },
                            )
                            Button(
                                enabled = hasMint && parsePositivePaidRouteAmount(sendAmount) != null,
                                onClick = {
                                    val amount = parsePositivePaidRouteAmount(sendAmount) ?: return@Button
                                    dispatch(NativeActions.sendPaidRouteWalletToken(null, amount))
                                },
                            ) { Text("Export") }
                        }
                    }
                    PaidRouteWalletActionResult(
                        market.wallet.lastAction,
                        qrJson = qrJson,
                        showInvoiceQrCode = flow == PaidRouteWalletFlow.Receive,
                    )
                }
            },
            confirmButton = {
                TextButton(onClick = { walletFlow = null }) { Text("Done") }
            },
        )
    }
    if (walletTokenScannerVisible) {
        QrScannerDialog(
            onDismiss = { walletTokenScannerVisible = false },
            onScanned = { value ->
                val scannedToken = value.trim()
                if (!isLikelyCashuToken(scannedToken)) {
                    "Not a Cashu token."
                } else {
                    walletTokenScannerVisible = false
                    token = ""
                    redeemingWalletToken = false
                    pendingWalletToken = scannedToken
                    dispatch(NativeActions.previewPaidRouteWalletToken(scannedToken))
                    null
                }
            },
        )
    }
    pendingWalletToken?.let { pendingToken ->
        val preview = market.wallet.lastAction
        val ready = preview.kind == "preview" && preview.tokenRedeemable && !redeemingWalletToken
        val reviewStatus = state.error.takeIf { it.isNotBlank() }
            ?.let { "Could not redeem token: $it" }
            ?: if (redeemingWalletToken) "Redeeming…"
            else if (preview.kind == "preview") preview.statusText else "Checking…"
        LaunchedEffect(redeemingWalletToken, state.error, preview.kind) {
            if (!redeemingWalletToken) return@LaunchedEffect
            if (state.error.isNotBlank()) {
                redeemingWalletToken = false
            } else if (preview.kind == "receive") {
                pendingWalletToken = null
                redeemingWalletToken = false
            }
        }
        AlertDialog(
            onDismissRequest = {
                if (!redeemingWalletToken) pendingWalletToken = null
            },
            title = { Text("Redeem token?") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("Amount: ${if (preview.kind == "preview") preview.amountText else "Checking…"}")
                    if (preview.kind == "preview") {
                        Text("Mint: ${preview.mintUrl}")
                        if (preview.tokenMemo.isNotBlank()) Text("Memo: ${preview.tokenMemo}")
                    }
                    Text("Status: $reviewStatus")
                }
            },
            confirmButton = {
                TextButton(
                    enabled = ready,
                    onClick = {
                        redeemingWalletToken = true
                        dispatch(NativeActions.receivePaidRouteWalletToken(pendingToken))
                    },
                ) { Text("Redeem") }
            },
            dismissButton = {
                TextButton(
                    enabled = !redeemingWalletToken,
                    onClick = {
                        pendingWalletToken = null
                        redeemingWalletToken = false
                    },
                ) { Text("Cancel") }
            },
        )
    }
}

private fun isLikelyCashuToken(value: String): Boolean {
    val token = value.trim()
    return token.length > 12 && token.startsWith("cashu", ignoreCase = true)
}

@Composable
private fun PaidRouteMarketFilterControls(
    market: PaidRouteMarketState,
    country: String,
    onCountryChange: (String) -> Unit,
    requireIpv4: Boolean,
    onRequireIpv4Change: (Boolean) -> Unit,
    requireIpv6: Boolean,
    onRequireIpv6Change: (Boolean) -> Unit,
    sort: String,
    onSortChange: (String) -> Unit,
    onApply: () -> Unit,
    onClear: () -> Unit,
) {
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
            OutlinedTextField(
                value = country,
                onValueChange = { value ->
                    onCountryChange(
                        value.filter { it.code < 128 && it.isLetter() }.take(2).uppercase(),
                    )
                },
                modifier = Modifier.weight(1f),
                singleLine = true,
                label = { Text("Country") },
            )
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
            PaidRouteSortButton("Quality", "quality", sort, onSortChange)
            PaidRouteSortButton("Price", "price", sort, onSortChange)
            PaidRouteSortButton("Newest", "newest", sort, onSortChange)
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Checkbox(checked = requireIpv4, onCheckedChange = onRequireIpv4Change)
                Text("IPv4", style = MaterialTheme.typography.bodySmall)
            }
            Row(verticalAlignment = Alignment.CenterVertically) {
                Checkbox(checked = requireIpv6, onCheckedChange = onRequireIpv6Change)
                Text("IPv6", style = MaterialTheme.typography.bodySmall)
            }
            Spacer(Modifier.weight(1f))
            OutlinedButton(onClick = onClear, enabled = market.offers.isNotEmpty()) {
                Text("Clear")
            }
            Button(onClick = onApply, enabled = market.offers.isNotEmpty()) {
                Text("Apply")
            }
        }
    }
}

@Composable
private fun PaidRouteSortButton(
    label: String,
    value: String,
    selected: String,
    onSelect: (String) -> Unit,
) {
    if (selected.ifBlank { "quality" } == value) {
        Button(onClick = { onSelect(value) }) {
            Text(label)
        }
    } else {
        OutlinedButton(onClick = { onSelect(value) }) {
            Text(label)
        }
    }
}

private fun dispatchPaidRouteMarketFilter(
    dispatch: (JSONObject) -> Unit,
    country: String,
    requireIpv4: Boolean,
    requireIpv6: Boolean,
    sort: String,
) {
    dispatch(
        NativeActions.setPaidRouteMarketFilter(
            countryCode = country.trim(),
            requireIpv4 = requireIpv4,
            requireIpv6 = requireIpv6,
            sort = sort.ifBlank { "quality" },
        ),
    )
}

@Composable
private fun PaidRouteWalletActionResult(
    action: org.nostrvpn.app.core.PaidRouteWalletActionState,
    qrJson: ((String) -> JSONObject)? = null,
    showInvoiceQrCode: Boolean = false,
) {
    if (action.kind.isBlank() && action.statusText.isBlank()) return
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Text(action.statusText.ifBlank { paidRouteWalletActionTitle(action.kind) }, color = Muted, style = MaterialTheme.typography.bodySmall)
        if (action.paymentRequest.isNotBlank()) {
            if (showInvoiceQrCode && action.kind == "topup" && qrJson != null) {
                QrCode(
                    text = action.paymentRequest,
                    qrJson = qrJson,
                    accessibilityDescription = "Wallet invoice QR code",
                )
                if (action.expiresAtUnix > 0) {
                    Text(
                        "Expires ${java.text.DateFormat.getDateTimeInstance().format(java.util.Date(action.expiresAtUnix * 1_000))}",
                        color = Muted,
                        style = MaterialTheme.typography.labelSmall,
                    )
                }
            }
            CopyLine(action.paymentRequest, "Lightning invoice ready")
        }
        if (action.token.isNotBlank()) {
            CopyLine(action.token, "Token ready")
        }
        if (action.preimage.isNotBlank()) {
            CopyLine(action.preimage, "Lightning preimage ready")
        }
    }
}

@Composable
private fun PaidRoutePaymentActionResult(
    action: org.nostrvpn.app.core.PaidRoutePaymentActionState,
    dispatch: (JSONObject) -> Unit,
) {
    if (action.kind.isBlank() && action.statusText.isBlank() && action.envelopeJson.isBlank()) return
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Text(
            action.statusText.ifBlank { paidRoutePaymentActionTitle(action.kind) },
            color = Muted,
            style = MaterialTheme.typography.bodySmall,
        )
        if (action.envelopeJson.isNotBlank()) {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                Text("Payment ready", modifier = Modifier.weight(1f), color = Muted)
                OutlinedButton(onClick = {
                    dispatch(NativeActions.sendPaidRoutePaymentEnvelope(action.envelopeJson))
                }) {
                    Text("Send payment")
                }
            }
        }
    }
}

@Composable
private fun PaidRouteOfferRow(
    state: AppState,
    offer: PaidRouteOfferState,
    dispatch: (JSONObject) -> Unit,
) {
    val active = state.internetSource == "paid_manual" && state.exitNode == offer.sellerNpub
    val compatibleMint = offer.acceptedMints.any { accepted ->
        state.paidRouteMarket.wallet.mints.any { it.url == accepted }
    }
    Column(verticalArrangement = Arrangement.spacedBy(3.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
            Text(paidRouteOfferTitle(offer), fontWeight = FontWeight.SemiBold)
            Text(
                offer.statusText.ifBlank { offer.sellerNpub },
                color = Muted,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                style = MaterialTheme.typography.bodySmall,
            )
            val metricText = paidRouteMetricText(
                offer.qualityText.ifBlank {
                    paidRouteQualityText(offer.latencyMs, offer.jitterMs, offer.packetLossPpm)
                },
                offer.bandwidthText,
            )
            if (metricText.isNotBlank()) {
                Text(
                    metricText,
                    color = Muted,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        }
            Button(
                enabled = offer.key.isNotBlank() && compatibleMint && !active,
                onClick = { dispatch(NativeActions.buyPaidRouteOffer(offer.key)) },
            ) {
                Text(if (active) "Active" else "Connect")
            }
        }
        if (!compatibleMint) {
            Text(
                "Add one of this seller's accepted mints to buy",
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodySmall,
            )
        }
    }
}

@Composable
private fun PaidRouteSessionRow(
    session: PaidRouteSessionState,
    envelopeJson: String,
    dispatch: (JSONObject) -> Unit,
) {
    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text(paidRouteBuyerSessionTitle(session), fontWeight = FontWeight.SemiBold)
                Text(
                    paidRouteSessionDetail(session),
                    color = Muted,
                    style = MaterialTheme.typography.bodySmall,
                )
                if (session.locationText.isNotBlank()) {
                    Text(
                        session.locationText,
                        color = Muted,
                        style = MaterialTheme.typography.bodySmall,
                    )
                } else if (session.realizedExitIp.isNotBlank()) {
                    Text(
                        "${session.realizedExitIp} · ${paidRouteCountryClaimText(session)}",
                        color = Muted,
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
                val metricText = paidRouteMetricText(
                    session.qualityText.ifBlank {
                        paidRouteQualityText(session.latencyMs, session.jitterMs, session.packetLossPpm)
                    },
                    session.bandwidthText,
                )
                if (metricText.isNotBlank()) {
                    Text(
                        metricText,
                        color = Muted,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
                if (session.settlementText.isNotBlank()) {
                    Text(
                        session.settlementText,
                        color = Muted,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
            }
            Column(horizontalAlignment = Alignment.End) {
                Text(
                    session.paidText.ifBlank { "${formatPaidRouteMsat(session.paidMsat)} paid" },
                    style = MaterialTheme.typography.bodySmall,
                )
                if (session.unpaidMsat > 0) {
                    Text(
                        session.unpaidText.ifBlank { "${formatPaidRouteMsat(session.unpaidMsat)} behind" },
                        color = Color(0xFF9A3412),
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
            }
        }
        Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = {
                    dispatch(NativeActions.selectPaidRouteSession(session.sessionId, connect = true))
                }) {
                    Text("Connect")
                }
                OutlinedButton(onClick = {
                    dispatch(NativeActions.probePaidRouteSession(session.sessionId, timeoutSecs = 5))
                }) {
                    Text("Probe")
                }
            }
            if (paidRouteSessionCanOpenChannel(session) ||
                paidRouteSessionCanSignPayment(session) ||
                paidRouteSessionCanCloseChannel(session) ||
                envelopeJson.isNotBlank()
            ) {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    if (paidRouteSessionCanOpenChannel(session)) {
                        OutlinedButton(onClick = {
                            dispatch(NativeActions.openPaidRouteChannelFromWallet(session.sessionId))
                        }) {
                            Text("Fund")
                        }
                    }
                    if (paidRouteSessionCanSignPayment(session)) {
                        OutlinedButton(onClick = {
                            dispatch(NativeActions.signPaidRoutePaymentEnvelopeFromWallet(session.sessionId))
                        }) {
                            Text("Pay")
                        }
                    }
                    if (paidRouteSessionCanCloseChannel(session)) {
                        OutlinedButton(onClick = {
                            dispatch(NativeActions.closePaidRouteChannelFromWallet(session.sessionId))
                        }) {
                            Text("Settle")
                        }
                    }
                    if (envelopeJson.isNotBlank()) {
                        OutlinedButton(onClick = {
                            dispatch(NativeActions.sendPaidRoutePaymentEnvelope(envelopeJson))
                        }) {
                            Text("Send")
                        }
                    }
                }
            }
        }
    }
}

private fun paidRouteOfferTitle(offer: PaidRouteOfferState): String {
    val location = offer.countryCode.ifBlank { "Unknown country" }.uppercase()
    val price = offer.priceText
    return "$location · $price"
}

private fun paidRouteSessionDetail(session: PaidRouteSessionState): String {
    if (session.detailText.isNotBlank()) return session.detailText
    val access = paidRouteAccessTitle(session.accessState, session.lifecycleStatus.ifBlank { "session" })
    val units = when {
        session.bytes > 0 -> "${formatBytes(session.bytes)} used"
        session.packets > 0 -> "${session.packets} packets"
        else -> "${session.deliveredUnits} units"
    }
    return "$access, $units, ${formatPaidRouteMsat(session.amountDueMsat)} due"
}

private fun paidRouteBuyerSessionTitle(session: PaidRouteSessionState): String =
    when {
        session.titleText.isNotBlank() -> session.titleText
        session.allowRouting -> "Ready"
        session.unpaidMsat > 0 -> "Payment needed"
        !session.paymentChannelReady -> "Needs funds"
        else -> paidRoutePlainStatus(
            session.statusText.ifBlank { session.lifecycleStatus },
            "Session",
        )
    }

private fun paidRouteAccessTitle(value: String, fallback: String): String =
    when (value) {
        "paid" -> "Paid"
        "free_probe" -> "Free test"
        "grace" -> "Grace"
        "suspended" -> "Paused"
        else -> paidRoutePlainStatus(value, fallback)
    }

private fun paidRoutePlainStatus(value: String, fallback: String): String {
    val raw = value.ifBlank { fallback }
    return when (raw) {
        "opening" -> "Opening"
        "probing" -> "Checking quality"
        "active" -> "Active"
        "paused" -> "Paused"
        "closed" -> "Closed"
        "session" -> "Session"
        else -> raw.replace('_', ' ').replaceFirstChar { it.uppercase() }
    }
}

internal fun paidRoutePaymentActionTitle(kind: String): String =
    when (kind) {
        "send" -> "Payment sent"
        "receive" -> "Payment received"
        "apply" -> "Payment applied"
        "create" -> "Payment ready"
        "open_channel" -> "Exit funded"
        "sign" -> "Payment ready"
        "close" -> "Channel settled"
        "stream" -> "Payments sent"
        "probe" -> "Quality checked"
        else -> kind.ifBlank { "Payment" }.replace('_', ' ').replaceFirstChar { it.uppercase() }
    }

private fun paidRouteWalletActionTitle(kind: String): String =
    when (kind) {
        "topup" -> "Invoice ready"
        "receive" -> "Token imported"
        "send" -> "Token ready"
        "withdraw" -> "Invoice paid"
        "refresh" -> "Wallet refreshed"
        "open_channel" -> "Exit funded"
        else -> kind.ifBlank { "Wallet updated" }.replace('_', ' ').replaceFirstChar { it.uppercase() }
    }

private fun paidRouteCountryClaimText(session: PaidRouteSessionState): String =
    when (session.countryClaimStatus) {
        "match" -> "${session.observedCountryCode.ifBlank { session.claimedCountryCode }} matches claim"
        "mismatch" -> "${session.observedCountryCode.ifBlank { "Observed country" }} differs from ${session.claimedCountryCode}"
        else -> session.observedCountryCode.ifBlank { session.claimedCountryCode.ifBlank { "country unknown" } }
    }

private fun paidRouteQualityText(latencyMs: Int, jitterMs: Int, packetLossPpm: Int): String {
    if (latencyMs <= 0 && jitterMs <= 0 && packetLossPpm <= 0) return "Quality unmeasured"
    val loss = packetLossPpm.toDouble() / 10_000.0
    return "${latencyMs} ms · ${jitterMs} ms jitter · %.2f%% loss".format(loss)
}

private fun paidRouteMetricText(qualityText: String, bandwidthText: String): String =
    listOf(qualityText, bandwidthText)
        .map { it.trim() }
        .filter { it.isNotEmpty() && it != "Quality unmeasured" }
        .joinToString(" · ")

internal fun paidExitSellerStatusText(seller: org.nostrvpn.app.core.PaidExitSellerState): String {
    val fallback =
        if (seller.supported) {
            "People can pay to use my internet"
        } else {
            "This platform cannot sell public internet access"
        }
    return seller.statusText.ifBlank { fallback }
        .replace("Paid exit selling", "Selling internet")
        .replace("paid exit selling", "selling internet")
}

internal fun paidExitSellerInternetText(seller: org.nostrvpn.app.core.PaidExitSellerState): String =
    seller.internetText.ifBlank {
        when (seller.upstream) {
            "wireguard_exit", "wireguard", "wg", "upstream_vpn", "vpn" -> "My internet through WireGuard"
            else -> "My internet"
        }
    }

private fun paidRouteSessionCanOpenChannel(session: PaidRouteSessionState): Boolean =
    session.sessionId.isNotBlank() && !session.paymentChannelReady

private fun paidRouteSessionCanSignPayment(session: PaidRouteSessionState): Boolean =
    session.sessionId.isNotBlank() && session.paymentChannelReady && session.unpaidMsat > 0

private fun paidRouteSessionCanCloseChannel(session: PaidRouteSessionState): Boolean =
    session.sessionId.isNotBlank() &&
        session.paymentChannelReady &&
        session.lifecycleStatus !in setOf("closed", "expired")

private fun parsePositivePaidRouteAmount(value: String): Long? =
    value.trim().toLongOrNull()?.takeIf { it > 0 }

internal fun formatPaidRouteMsat(msat: Long): String {
    if (msat <= 0) return "0 sat"
    val whole = msat / 1000
    val rem = msat % 1000
    return if (rem == 0L) {
        "$whole sat"
    } else {
        "%d.%03d sat".format(whole, rem)
    }
}

internal fun formatBytes(bytes: Long): String {
    val units = listOf("B", "KB", "MB", "GB", "TB")
    var value = bytes.toDouble()
    var index = 0
    while (value >= 1024.0 && index < units.lastIndex) {
        value /= 1024.0
        index += 1
    }
    return when {
        index == 0 -> "$bytes B"
        kotlin.math.abs(value - kotlin.math.round(value)) < 0.05 -> "%.0f %s".format(value, units[index])
        else -> "%.1f %s".format(value, units[index])
    }
}

internal fun paidRouteTrafficUnitText(units: Long): String = formatBytes(units)

private fun formatDecimalBytes(bytes: Long): String {
    val units = listOf("B", "KB", "MB", "GB", "TB")
    var value = bytes.toDouble()
    var index = 0
    while (value >= 1000.0 && index < units.lastIndex) {
        value /= 1000.0
        index += 1
    }
    return when {
        index == 0 -> "$bytes B"
        kotlin.math.abs(value - kotlin.math.round(value)) < 0.05 -> "%.0f %s".format(value, units[index])
        else -> "%.1f %s".format(value, units[index])
    }
}
