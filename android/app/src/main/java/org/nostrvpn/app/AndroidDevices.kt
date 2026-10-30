package org.nostrvpn.app

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.Image
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
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
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import org.json.JSONObject
import org.nostrvpn.app.core.AppState
import org.nostrvpn.app.core.NativeActions
import org.nostrvpn.app.core.NetworkState
import org.nostrvpn.app.core.ParticipantState

@Composable
private fun PlusIcon() {
    Canvas(Modifier.size(18.dp)) {
        val strokeWidth = 2.6.dp.toPx()
        val center = size.width / 2f
        drawLine(
            Color.White,
            Offset(center, 2.dp.toPx()),
            Offset(center, size.height - 2.dp.toPx()),
            strokeWidth = strokeWidth,
            cap = StrokeCap.Round,
        )
        drawLine(
            Color.White,
            Offset(2.dp.toPx(), center),
            Offset(size.width - 2.dp.toPx(), center),
            strokeWidth = strokeWidth,
            cap = StrokeCap.Round,
        )
    }
}

@Composable
private fun QrCodeIcon() {
    Canvas(Modifier.size(18.dp)) {
        val color = Color.White
        val cell = size.width / 7f
        val finderStroke = Stroke(width = 1.35.dp.toPx())

        fun finder(x: Int, y: Int) {
            drawRect(
                color,
                topLeft = Offset(x * cell, y * cell),
                size = Size(3 * cell, 3 * cell),
                style = finderStroke,
            )
            drawRect(
                color,
                topLeft = Offset((x + 1) * cell, (y + 1) * cell),
                size = Size(cell, cell),
            )
        }

        fun module(x: Int, y: Int) {
            drawRect(
                color,
                topLeft = Offset(x * cell, y * cell),
                size = Size(cell, cell),
            )
        }

        finder(0, 0)
        finder(4, 0)
        finder(0, 4)
        module(4, 4)
        module(6, 4)
        module(5, 5)
        module(4, 6)
        module(6, 6)
    }
}

internal fun androidx.compose.foundation.lazy.LazyListScope.devicesPage(
    state: AppState,
    network: NetworkState,
    dispatch: (JSONObject) -> Unit,
    onAddDevice: () -> Unit,
    onDeleteNetwork: () -> Unit,
) {
    if (!network.enabled) {
        item {
            Button(
                onClick = { dispatch(NativeActions.setNetworkEnabled(network.id, true)) },
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text("Activate network")
            }
        }
    }
    if (network.localIsAdmin) {
        item {
            Button(
                onClick = onAddDevice,
                enabled = network.enabled,
                modifier = Modifier
                    .fillMaxWidth()
                    .mobileUiSelector(
                        id = "manual-admin-open",
                        description = "Open manual device approval",
                    ),
            ) {
                Text("Add device")
            }
        }
    }
    items(sortedParticipants(network.participants, state), key = { it.pubkeyHex.ifBlank { it.npub } }) { participant ->
        ParticipantRow(state, participant, network = network, dispatch = dispatch)
    }
    item {
        OutlinedButton(
            onClick = onDeleteNetwork,
            modifier = Modifier
                .fillMaxWidth()
                .padding(top = 8.dp),
        ) {
            Text("Delete network", color = Color(0xFFB00020))
        }
    }
}

@Composable
private fun DeviceListHeader(
    state: AppState,
    network: NetworkState,
) {
    Column {
        Text(networkTitle(network), style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
        Text(deviceCountText(network), color = Muted, style = MaterialTheme.typography.bodySmall)
    }
}

private fun sortedParticipants(participants: List<ParticipantState>, state: AppState): List<ParticipantState> =
    participants.sortedWith(
        compareByDescending<ParticipantState> { it.isCurrentDevice(state) }
            .thenByDescending { it.reachable }
            .thenBy(String.CASE_INSENSITIVE_ORDER) { it.deviceName(state) },
    )

internal fun ParticipantState.isCurrentDevice(state: AppState): Boolean =
    (state.ownNpub.isNotBlank() && npub == state.ownNpub) || meshState == "local"

private fun ParticipantState.deviceName(state: AppState): String {
    if (magicDnsName.isNotBlank()) return magicDnsName
    if (isCurrentDevice(state) && state.selfMagicDnsName.isNotBlank()) return state.selfMagicDnsName
    if (alias.isNotBlank()) return alias
    if (magicDnsAlias.isNotBlank()) return magicDnsAlias
    if (npub.length <= 19) return npub.ifBlank { "Device" }
    return "${npub.take(12)}...${npub.takeLast(6)}"
}

private fun deviceCountText(network: NetworkState): String {
    if (network.expectedCount == 0L) return "This device"
    val word = if (network.expectedCount == 1L) "device" else "devices"
    return "${network.onlineCount} online - ${network.expectedCount} $word"
}

@Composable
private fun NetworkSetupCard(
    state: AppState,
    qrJson: (String) -> JSONObject,
    dispatch: (JSONObject) -> Unit,
    dispatchSucceeded: (JSONObject, () -> Unit) -> Unit,
    onCreated: (() -> Unit)? = null,
    showWelcomeHeader: Boolean = false,
) {
    var setupMode by remember { mutableStateOf<NetworkSetupMode?>(null) }
    var joinBaselineNetworkIds by remember { mutableStateOf<Set<String>?>(null) }
    var networkName by remember { mutableStateOf("My Network") }
    var manualExpanded by remember { mutableStateOf(false) }
    var manualAdminId by remember { mutableStateOf("") }
    var manualNetworkId by remember { mutableStateOf("") }
    val joinRequestQrCodeOrLink = state.joinRequestQrCodeOrLink.ifBlank {
        state.networks.firstOrNull { it.joinRequestQrCodeOrLink.isNotBlank() }
            ?.joinRequestQrCodeOrLink
            .orEmpty()
    }
    val networkIds = state.networks.mapTo(linkedSetOf()) { it.id }

    LaunchedEffect(setupMode, networkIds) {
        val baseline = joinBaselineNetworkIds
        if (
            setupMode == NetworkSetupMode.Join &&
            baseline != null &&
            networkIds.any { it !in baseline }
        ) {
            joinBaselineNetworkIds = null
            onCreated?.invoke()
        }
    }

    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        if (showWelcomeHeader && setupMode == null) {
            NostrVpnWelcomeHeader()
        }
        if (setupMode == null) {
            Column(verticalArrangement = Arrangement.spacedBy(18.dp)) {
                Button(
                    onClick = { setupMode = NetworkSetupMode.Create },
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(58.dp)
                        .mobileUiSelector(
                            id = "network-setup-create",
                            description = "Create Network",
                        ),
                    shape = RoundedCornerShape(16.dp),
                    contentPadding = PaddingValues(horizontal = 20.dp, vertical = 14.dp),
                ) {
                    Row(
                        horizontalArrangement = Arrangement.spacedBy(10.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        PlusIcon()
                        Text(
                            "Create Network",
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.SemiBold,
                        )
                    }
                }
                Button(
                    onClick = {
                        if (!state.vpnEnabled) {
                            dispatch(NativeActions.connectVpn())
                        }
                        joinBaselineNetworkIds = networkIds
                        setupMode = NetworkSetupMode.Join
                    },
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(58.dp)
                        .mobileUiSelector(
                            id = "network-setup-join",
                            description = "Join Network",
                        ),
                    shape = RoundedCornerShape(16.dp),
                    contentPadding = PaddingValues(horizontal = 20.dp, vertical = 14.dp),
                ) {
                    Row(
                        horizontalArrangement = Arrangement.spacedBy(10.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        QrCodeIcon()
                        Text(
                            "Join Network",
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.SemiBold,
                        )
                    }
                }
            }
        } else {
            val mode = setupMode
            if (mode != null) {
                TextButton(onClick = { setupMode = null }) {
                    Text("Back")
                }
                when (mode) {
                    NetworkSetupMode.Create -> SetupChoiceCard("Create Network", Color(0xFF16A34A)) {
                        Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                            OutlinedTextField(
                                value = networkName,
                                onValueChange = { networkName = it },
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .mobileUiSelector(
                                        id = "network-create-name",
                                        description = "Network name",
                                    ),
                                singleLine = true,
                                label = { Text("Network name") },
                            )
                            Button(
                                onClick = {
                                    dispatchSucceeded(
                                        NativeActions.addNetwork(networkName.trim().ifBlank { "My Network" }),
                                    ) {
                                        networkName = "My Network"
                                        onCreated?.invoke()
                                    }
                                },
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .mobileUiSelector(
                                        id = "network-create-submit",
                                        description = "Create network",
                                    ),
                            ) {
                                Text("Create")
                            }
                        }
                    }
                    NetworkSetupMode.Join -> {
                        SetupChoiceCard("Join Network", Color(0xFF2563EB)) {
                            if (joinRequestQrCodeOrLink.isNotBlank()) {
                                Box(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .mobileUiSelector(
                                            id = "join-request-qr-content",
                                            description = "Join request QR content width",
                                        ),
                                ) {
                                    QrCode(
                                        text = joinRequestQrCodeOrLink,
                                        qrJson = qrJson,
                                        accessibilityDescription = "Join request QR code",
                                    )
                                }
                                CopyButton(joinRequestQrCodeOrLink, "Copy request")
                            }

                            TextButton(
                                onClick = { manualExpanded = !manualExpanded },
                                modifier = Modifier.mobileUiSelector(
                                    id = "manual-join-expand",
                                    description = "Manual join",
                                ),
                            ) {
                                Text(if (manualExpanded) "Manual join ▴" else "Manual join ▾")
                            }
                            if (manualExpanded) {
                                val admin = manualAdminId.trim()
                                val mesh = normalizeNetworkIdInput(manualNetworkId)
                                val adminInvalid = admin.isNotEmpty() && !isValidDeviceId(admin)
                                Text(
                                    "Give the admin your Device ID. Enter their Device ID and Network ID here; they must add your Device ID too.",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = Muted,
                                )
                                CopyLine(
                                    value = state.ownNpub,
                                    selectorId = "joiner-device-id-value",
                                    selectorDescription = "Joiner Device ID value",
                                )
                                OutlinedTextField(
                                    value = manualAdminId,
                                    onValueChange = { manualAdminId = it },
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .mobileUiSelector(
                                            id = "manual-join-admin-id",
                                            description = "Manual join admin Device ID",
                                        ),
                                    singleLine = true,
                                    label = { Text("Admin Device ID") },
                                    isError = adminInvalid,
                                    supportingText = if (adminInvalid) {
                                        { Text("Not a valid device ID") }
                                    } else {
                                        null
                                    },
                                )
                                OutlinedTextField(
                                    value = manualNetworkId,
                                    onValueChange = { manualNetworkId = it },
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .mobileUiSelector(
                                            id = "manual-join-network-id",
                                            description = "Manual join Network ID",
                                        ),
                                    singleLine = true,
                                    label = { Text("Network ID") },
                                )
                                Button(
                                    enabled = admin.isNotEmpty() && mesh.isNotEmpty() && !adminInvalid,
                                    onClick = {
                                        dispatchSucceeded(NativeActions.manualAddNetwork(admin, mesh)) {
                                            manualAdminId = ""
                                            manualNetworkId = ""
                                            manualExpanded = false
                                            onCreated?.invoke()
                                        }
                                    },
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .mobileUiSelector(
                                            id = "manual-join-submit",
                                            description = "Add network manually",
                                        ),
                                ) {
                                    Text("Add manually")
                                }
                            }

                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun NostrVpnWelcomeHeader() {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(top = 26.dp, bottom = 10.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Image(
            painter = painterResource(R.drawable.ic_launcher_foreground),
            contentDescription = null,
            modifier = Modifier.size(82.dp),
        )
        Text(
            "Nostr VPN",
            style = MaterialTheme.typography.headlineMedium,
            fontWeight = FontWeight.Bold,
            textAlign = TextAlign.Center,
            modifier = Modifier.fillMaxWidth(),
        )
    }
}

@Composable
private fun SetupChoiceCard(
    title: String,
    accent: Color,
    content: @Composable ColumnScope.() -> Unit,
) {
    AppCard {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Canvas(Modifier.size(10.dp)) {
                drawCircle(accent)
            }
            Spacer(Modifier.width(8.dp))
            Text(title, style = MaterialTheme.typography.titleMedium, color = accent)
        }
        content()
    }
}

// LazyListScope wrapper for the Add Network body, used as the entire
// screen content when there is no active network. Mirrors the in-dialog
// content we show when the user picks "Add network" from the header
// switcher with an existing network already in place.
internal fun androidx.compose.foundation.lazy.LazyListScope.addNetworkBody(
    state: AppState,
    qrJson: (String) -> JSONObject,
    dispatch: (JSONObject) -> Unit,
    dispatchSucceeded: (JSONObject, () -> Unit) -> Unit,
    showWelcomeHeader: Boolean = false,
) {
    item {
        NetworkSetupCard(
            state,
            qrJson,
            dispatch,
            dispatchSucceeded,
            showWelcomeHeader = showWelcomeHeader,
        )
    }
}

@Composable
internal fun AddNetworkDialog(
    state: AppState,
    qrJson: (String) -> JSONObject,
    dispatch: (JSONObject) -> Unit,
    dispatchSucceeded: (JSONObject, () -> Unit) -> Unit,
    onDismiss: () -> Unit,
    onCreated: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Add Network") },
        text = {
            Column(
                modifier = Modifier.verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                if (state.error.isNotBlank()) {
                    Notice(state.error)
                }
                NetworkSetupCard(state, qrJson, dispatch, dispatchSucceeded, onCreated = onCreated)
            }
        },
        confirmButton = {
            TextButton(onClick = onDismiss) { Text("Done") }
        },
    )
}

/// Admin-only sheet for approving a joining device's signed join request.
@Composable
internal fun AddDevicesDialog(
    state: AppState,
    network: NetworkState,
    scanDeviceQr: (String) -> Unit,
    dispatch: (JSONObject) -> Unit,
    dispatchSucceeded: (JSONObject, () -> Unit) -> Unit,
    onDismiss: () -> Unit,
) {
    var joinRequestInput by remember(network.id) { mutableStateOf("") }
    var pendingJoinRequest by remember(network.id) { mutableStateOf<String?>(null) }
    val context = androidx.compose.ui.platform.LocalContext.current
    val clipboard = remember(context) {
        context.getSystemService(android.content.ClipboardManager::class.java)
    }
    fun stageJoinRequest(value: String) {
        val trimmed = value.trim()
        if (looksLikeJoinRequestQrOrLink(trimmed)) {
            pendingJoinRequest = trimmed
        }
    }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Add Device") },
        text = {
            Column(
                modifier = Modifier.verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                if (state.error.isNotBlank()) {
                    Notice(state.error)
                }
                Text("Add join request", style = MaterialTheme.typography.titleMedium)
                Text(
                    "Scan or paste the joiner's join request. Valid links open confirmation automatically.",
                    style = MaterialTheme.typography.bodySmall,
                    color = Muted,
                )
                OutlinedTextField(
                    value = joinRequestInput,
                    onValueChange = {
                        joinRequestInput = it
                        stageJoinRequest(it)
                    },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                    label = { Text("Join request") },
                )
                OutlinedButton(
                    onClick = {
                        clipboard?.primaryClip
                            ?.takeIf { it.itemCount > 0 }
                            ?.getItemAt(0)
                            ?.coerceToText(context)
                            ?.toString()
                            ?.let {
                                joinRequestInput = it
                                stageJoinRequest(it)
                            }
                    },
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text("Paste")
                }
                Button(
                    onClick = { scanDeviceQr(network.id) },
                    modifier = Modifier
                        .fillMaxWidth()
                        .mobileUiSelector(
                            id = "join-request-scan-open",
                            description = "Scan joining device QR",
                        ),
                ) {
                    Text("Scan QR")
                }
                Spacer(modifier = Modifier.height(8.dp))
                Text("For manual join", style = MaterialTheme.typography.titleMedium)
                Text(
                    "Share these with the joining device, then add its Device ID below.",
                    style = MaterialTheme.typography.bodySmall,
                    color = Muted,
                )
                Text("Your Device ID", style = MaterialTheme.typography.bodySmall, color = Muted)
                CopyLine(
                    value = state.ownNpub,
                    selectorId = "admin-device-id-value",
                    selectorDescription = "Admin Device ID value",
                )
                Text("Network ID", style = MaterialTheme.typography.bodySmall, color = Muted)
                CopyLine(
                    value = network.networkId,
                    displayValue = displayNetworkId(network.networkId),
                    selectorId = "admin-network-id-value",
                    selectorDescription = "Admin Network ID value",
                )
                Text("Add by Device ID", style = MaterialTheme.typography.titleMedium)
                AddParticipantForm(network, dispatchSucceeded, onAdded = onDismiss)
            }
        },
        confirmButton = {
            TextButton(onClick = onDismiss) {
                Text("Done")
            }
        },
    )
    pendingJoinRequest?.let { request ->
        AlertDialog(
            onDismissRequest = { pendingJoinRequest = null },
            title = { Text("Add device?") },
            text = { Text("Add the device from this join request to ${network.name.ifBlank { "this network" }}?") },
            confirmButton = {
                Button(
                    onClick = {
                        dispatchSucceeded(NativeActions.importJoinRequest(request)) {
                            joinRequestInput = ""
                            pendingJoinRequest = null
                            onDismiss()
                        }
                    },
                ) {
                    Text("Add")
                }
            },
            dismissButton = {
                TextButton(onClick = { pendingJoinRequest = null }) {
                    Text("Cancel")
                }
            },
        )
    }
}

private fun displayNetworkId(value: String): String {
    val trimmed = value.trim()
    if (trimmed.length <= 4 || !trimmed.all { it.isHexDigit() }) {
        return trimmed
    }
    return trimmed.chunked(4).joinToString("-")
}

private fun normalizeNetworkIdInput(value: String): String {
    val trimmed = value.trim()
    val compact = trimmed.filter { !it.isWhitespace() && it != '-' }
    if (compact.isEmpty() && trimmed.all { it.isWhitespace() || it == '-' }) {
        return ""
    }
    return if (compact.isNotEmpty() && compact.all { it.isHexDigit() }) compact.lowercase() else trimmed
}

private fun Char.isHexDigit(): Boolean =
    this in '0'..'9' || lowercaseChar() in 'a'..'f'
