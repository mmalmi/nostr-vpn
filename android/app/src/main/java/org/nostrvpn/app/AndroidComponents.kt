package org.nostrvpn.app

import android.content.ClipData
import android.content.ClipboardManager
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Checkbox
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.Switch
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import java.net.URI
import java.net.URLDecoder
import org.json.JSONObject
import org.nostrvpn.app.core.AppState
import org.nostrvpn.app.core.NativeActions
import org.nostrvpn.app.core.NetworkState
import org.nostrvpn.app.core.ParticipantState

internal fun networkTitle(network: NetworkState?): String =
    network?.name?.ifBlank { "Private network" } ?: "No network"

@Composable
internal fun ParticipantRow(
    state: AppState,
    participant: ParticipantState,
    network: NetworkState? = null,
    dispatch: ((JSONObject) -> Unit)? = null,
) {
    val isSelf = participant.isSelf(state)
    val rosterAcceptance = rosterAcceptance(participant)
    var detailOpen by remember { mutableStateOf(false) }
    AppCard {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier
                .clickable { detailOpen = true }
                .mobileUiSelector(
                    id = "roster-participant-$rosterAcceptance-${participant.npub}",
                    description = "Roster participant $rosterAcceptance ${participant.npub}",
                ),
        ) {
            Dot(selected = if (isSelf) state.vpnActive else participant.reachable && participant.rosterAccepted)
            Spacer(Modifier.width(12.dp))
            Column(Modifier.weight(1f)) {
                Text(
                    participant.displayName(state),
                    fontWeight = FontWeight.SemiBold,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    if (isSelf) Pill("This device", Color(0xFFECFDF5), Ok)
                    if (participant.isAdmin) Pill("Admin", Color(0xFFF5F3FF), Accent)
                    if (participant.offersExitNode) {
                        Pill(
                            participant.exitNodeLabel(state),
                            participant.exitNodeBackground(state),
                            participant.exitNodeTint(state),
                        )
                    }
                    if (participant.isFipsRouted(state)) Pill("via mesh", Color(0xFFF1F5F9), Muted)
                }
                Text(participant.subtitle(isSelf), color = Muted, maxLines = 1)
                Text(participant.statusLabel(state), color = Muted, style = MaterialTheme.typography.bodySmall)
            }
            Text("›", color = Muted)
        }
    }
    if (detailOpen) {
        DeviceDetailDialog(
            state = state,
            participant = participant,
            network = network,
            dispatch = dispatch,
            onDismiss = { detailOpen = false },
        )
    }
}

internal fun rosterAcceptance(participant: ParticipantState): String =
    if (participant.rosterAccepted) "accepted" else "pending"

@Composable
private fun DeviceDetailDialog(
    state: AppState,
    participant: ParticipantState,
    network: NetworkState?,
    dispatch: ((JSONObject) -> Unit)?,
    onDismiss: () -> Unit,
) {
    val isSelf = participant.isSelf(state)
    val manageNetwork = network?.takeIf { it.localIsAdmin }
    val manageDispatch = dispatch
    var aliasDraft by remember { mutableStateOf(participant.magicDnsAlias) }
    var endpointHintsDraft by remember { mutableStateOf(participant.fipsEndpointHints.joinToString(", ")) }
    var pendingRemove by remember { mutableStateOf(false) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(participant.displayName(state)) },
        text = {
            Column(
                modifier = Modifier.verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                Text(participant.detailStatusLabel(state), color = Muted)
                Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    if (isSelf) Pill("This device", Color(0xFFECFDF5), Ok)
                    if (participant.isAdmin) Pill("Admin", Color(0xFFF5F3FF), Accent)
                    if (participant.offersExitNode) {
                        Pill(
                            participant.exitNodeLabel(state),
                            participant.exitNodeBackground(state),
                            participant.exitNodeTint(state),
                        )
                    }
                }
                if (participant.magicDnsName.isNotBlank()) {
                    Text("Magic DNS", style = MaterialTheme.typography.labelMedium, color = Muted)
                    Text(participant.magicDnsName)
                }
                Text("Device ID", style = MaterialTheme.typography.labelMedium, color = Muted)
                CopyLine(participant.npub)
                if (participant.tunnelIp.isNotBlank()) {
                    Text("Tunnel IP", style = MaterialTheme.typography.labelMedium, color = Muted)
                    CopyLine(participant.tunnelIp)
                }
                Text("FIPS path", style = MaterialTheme.typography.labelMedium, color = Muted)
                Text(participant.fipsPathLabel(state))
                if (participant.fipsSrttAgeMs > 0) {
                    Text("Latency age", style = MaterialTheme.typography.labelMedium, color = Muted)
                    Text(formatDurationMs(participant.fipsSrttAgeMs))
                }
                if (participant.lastFipsControlSeenText.isNotBlank()) {
                    Text("Control seen", style = MaterialTheme.typography.labelMedium, color = Muted)
                    Text(participant.lastFipsControlSeenText)
                }
                if (participant.lastFipsDataSeenText.isNotBlank()) {
                    Text("Data seen", style = MaterialTheme.typography.labelMedium, color = Muted)
                    Text(participant.lastFipsDataSeenText)
                }
                if (participant.fipsEndpointHints.isNotEmpty()) {
                    Text("Address hints", style = MaterialTheme.typography.labelMedium, color = Muted)
                    Text(participant.fipsEndpointHints.joinToString(", "))
                }
                if (manageNetwork != null && manageDispatch != null) {
                    Spacer(Modifier.height(8.dp))
                    OutlinedTextField(
                        value = aliasDraft,
                        onValueChange = { aliasDraft = it },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true,
                        label = { Text("Alias") },
                    )
                    Button(onClick = {
                        manageDispatch(JSONObject().put("type", "set_participant_alias")
                            .put("npub", participant.npub).put("alias", aliasDraft))
                    }) { Text("Save alias") }
                    if (!isSelf) {
                        OutlinedTextField(
                            value = endpointHintsDraft,
                            onValueChange = { endpointHintsDraft = it },
                            modifier = Modifier.fillMaxWidth(),
                            singleLine = true,
                            label = { Text("Address hints") },
                            placeholder = { Text("host or host:port") },
                        )
                        Button(onClick = {
                            manageDispatch(NativeActions.setParticipantEndpointHints(
                                participant.npub,
                                endpointHintsDraft.split(',', '\n', '\r', '\t', ' ')
                                    .map { it.trim() }
                                    .filter { it.isNotEmpty() },
                            ))
                        }) { Text("Save hints") }
                        OutlinedButton(onClick = {
                            val type = if (participant.isAdmin) "remove_admin" else "add_admin"
                            manageDispatch(JSONObject().put("type", type)
                                .put("networkId", manageNetwork.id).put("npub", participant.npub))
                        }) {
                            Text(if (participant.isAdmin) "Remove admin" else "Make admin")
                        }
                        OutlinedButton(onClick = { pendingRemove = true }) {
                            Text("Remove from network")
                        }
                    }
                }
            }
        },
        confirmButton = {
            TextButton(onClick = onDismiss) { Text("Done") }
        },
    )
    if (pendingRemove && manageNetwork != null && manageDispatch != null && !isSelf) {
        AlertDialog(
            onDismissRequest = { pendingRemove = false },
            title = { Text("Remove ${participant.displayName(state)}?") },
            text = { Text("This removes the device from the network's roster. They keep the network locally but won't be in this roster anymore.") },
            confirmButton = {
                TextButton(onClick = {
                    manageDispatch(JSONObject().put("type", "remove_participant")
                        .put("networkId", manageNetwork.id).put("npub", participant.npub))
                    pendingRemove = false
                    onDismiss()
                }) { Text("Remove") }
            },
            dismissButton = {
                TextButton(onClick = { pendingRemove = false }) { Text("Cancel") }
            },
        )
    }
}

@Composable
internal fun AddParticipantForm(
    network: NetworkState,
    dispatchSucceeded: (JSONObject, () -> Unit) -> Unit,
    onAdded: () -> Unit,
) {
    var deviceId by remember(network.id) { mutableStateOf("") }
    var alias by remember(network.id) { mutableStateOf("") }
    val trimmedDeviceId = deviceId.trim()
    val showError = trimmedDeviceId.isNotEmpty() && !isValidDeviceId(trimmedDeviceId)
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        OutlinedTextField(
            value = deviceId,
            onValueChange = { deviceId = it },
            modifier = Modifier
                .fillMaxWidth()
                .mobileUiSelector(
                    id = "manual-admin-joiner-id",
                    description = "Manual joiner Device ID",
                ),
            singleLine = true,
            label = { Text("Device ID") },
            isError = showError,
            supportingText = if (showError) ({ Text("Not a valid device ID") }) else null,
        )
        OutlinedTextField(
            value = alias,
            onValueChange = { alias = it },
            modifier = Modifier
                .fillMaxWidth()
                .mobileUiSelector(
                    id = "manual-admin-alias",
                    description = "Manual joiner name",
                ),
            singleLine = true,
            label = { Text("Name") },
        )
        Button(
            enabled = trimmedDeviceId.isNotEmpty() && !showError,
            onClick = {
                dispatchSucceeded(
                    NativeActions.addParticipant(
                        network.id,
                        trimmedDeviceId,
                        alias.trim().ifBlank { null },
                    ),
                ) {
                    deviceId = ""
                    alias = ""
                    onAdded()
                }
            },
            modifier = Modifier.mobileUiSelector(
                id = "manual-admin-submit",
                description = "Add joining device manually",
            ),
        ) {
            Text("Add")
        }
    }
}
private val BECH32_BODY_CHARSET: Set<Char> = "qpzry9x8gf2tvdw0s3jn54khce6mua7l".toSet()

internal data class ScannedDeviceLink(
    val deviceId: String,
    val alias: String? = null,
)

/** A valid device ID is a bech32-encoded npub: `npub1` + 58 bech32 chars. */
internal fun isValidDeviceId(value: String): Boolean {
    val trimmed = value.trim()
    if (trimmed.length != 63 || !trimmed.startsWith("npub1")) return false
    return trimmed.substring(5).all { it in BECH32_BODY_CHARSET }
}

internal fun parseScannedDeviceLinkQr(value: String): ScannedDeviceLink? {
    val trimmed = value.trim()
    normalizedDeviceIdCandidate(trimmed)?.let { return ScannedDeviceLink(it) }
    parseScannedDeviceJson(trimmed)?.let { return it }
    parseScannedDeviceUri(trimmed)?.let { return it }
    return null
}

internal fun looksLikeJoinRequestQrOrLink(value: String): Boolean {
    val trimmed = value.trim()
    val prefix = "nvpn://join-request/"
    return trimmed.startsWith(prefix, ignoreCase = true) && trimmed.length > prefix.length
}

private fun parseScannedDeviceJson(value: String): ScannedDeviceLink? {
    if (!value.startsWith("{")) return null
    val json = parseFlatJsonStringMap(value)
    val device = firstValidDeviceId(
        json["deviceId"],
        json["device"],
        json["npub"],
        json["requesterNpub"],
    ) ?: return null
    val alias = firstNonBlank(
        json["name"],
        json["nodeName"],
        json["label"],
    )
    return ScannedDeviceLink(device, alias)
}

private fun parseFlatJsonStringMap(value: String): Map<String, String> =
    Regex(""""([^"\\]+)"\s*:\s*"([^"\\]*)"""")
        .findAll(value)
        .associate { match -> match.groupValues[1] to match.groupValues[2] }

private fun parseScannedDeviceUri(value: String): ScannedDeviceLink? {
    val uri = runCatching { URI(value) }.getOrNull() ?: return null
    if (!uri.scheme.equals("nvpn", ignoreCase = true)) return null
    val params = parseQueryParams(uri.rawQuery.orEmpty())
    val device = firstValidDeviceId(
        params["deviceId"],
        params["device"],
        params["npub"],
        params["requesterNpub"],
        uri.host,
        uri.rawPath.orEmpty().split('/').lastOrNull(),
    ) ?: return null
    val alias = firstNonBlank(params["name"], params["nodeName"], params["label"])
    return ScannedDeviceLink(device, alias)
}

private fun parseQueryParams(query: String): Map<String, String> {
    if (query.isBlank()) return emptyMap()
    return query.split('&')
        .mapNotNull { part ->
            val key = part.substringBefore('=', missingDelimiterValue = "").trim()
            if (key.isEmpty()) return@mapNotNull null
            val value = part.substringAfter('=', missingDelimiterValue = "")
            key to urlDecode(value)
        }
        .toMap()
}

private fun urlDecode(value: String): String =
    runCatching { URLDecoder.decode(value, Charsets.UTF_8.name()) }.getOrDefault(value)

private fun firstValidDeviceId(vararg values: String?): String? =
    values.firstNotNullOfOrNull { normalizedDeviceIdCandidate(it.orEmpty()) }

private fun normalizedDeviceIdCandidate(value: String): String? {
    val trimmed = value.trim()
    if (trimmed.isEmpty()) return null
    val withoutNostrPrefix = if (trimmed.startsWith("nostr:", ignoreCase = true)) {
        trimmed.drop(6).trim()
    } else {
        trimmed
    }
    return withoutNostrPrefix.takeIf { isValidDeviceId(it) }
}

private fun firstNonBlank(vararg values: String?): String? =
    values.firstOrNull { !it.isNullOrBlank() }?.trim()

private fun formatDurationMs(ms: Long): String {
    if (ms <= 0) return "-"
    if (ms < 1_000) return "$ms ms"
    val seconds = ms / 1_000
    if (seconds < 60) return "${seconds}s"
    val minutes = seconds / 60
    if (minutes < 60) return "${minutes}m"
    return "${minutes / 60}h"
}

@Composable
internal fun DeviceSettingsCard(state: AppState, dispatch: (JSONObject) -> Unit) {
    var nodeName by remember(state.nodeName) { mutableStateOf(state.nodeName) }
    var endpoint by remember(state.endpoint) { mutableStateOf(state.endpoint) }
    var tunnelIp by remember(state.tunnelIp) { mutableStateOf(state.tunnelIp) }
    var port by remember(state.listenPort) { mutableStateOf(state.listenPort.toString()) }
    AppCard {
        Text("This Device", style = MaterialTheme.typography.titleMedium)
        OutlinedTextField(nodeName, { nodeName = it }, Modifier.fillMaxWidth(), singleLine = true, label = { Text("Name") })
        OutlinedTextField(tunnelIp, { tunnelIp = it }, Modifier.fillMaxWidth(), singleLine = true, label = { Text("Tunnel IP") })
        OutlinedTextField(endpoint, { endpoint = it }, Modifier.fillMaxWidth(), singleLine = true, label = { Text("Endpoint") })
        OutlinedTextField(port, { port = it }, Modifier.fillMaxWidth(), singleLine = true, label = { Text("Listen Port") })
        Button(onClick = {
            dispatch(
                NativeActions.updateSettings(
                    "nodeName" to nodeName,
                    "endpoint" to endpoint,
                    "tunnelIp" to tunnelIp,
                    "listenPort" to port.toIntOrNull(),
                ),
            )
        }) {
            Text("Save")
        }
    }
}

@Composable
internal fun GeneralSettingsCard(state: AppState, dispatch: (JSONObject) -> Unit) {
    AppCard {
        Text("General", style = MaterialTheme.typography.titleMedium)
        Row(verticalAlignment = Alignment.CenterVertically) {
            Checkbox(
                checked = state.autoconnect,
                onCheckedChange = { enabled -> dispatch(NativeActions.updateSettings("autoconnect" to enabled)) },
            )
            Text("Start VPN automatically")
        }
        Row(verticalAlignment = Alignment.CenterVertically) {
            Checkbox(
                checked = state.exitNodeLeakProtection,
                onCheckedChange = { enabled ->
                    dispatch(NativeActions.updateSettings("exitNodeLeakProtection" to enabled))
                },
            )
            Text("Block internet if selected source disconnects")
        }
    }
}

@Composable
internal fun FipsSettingsCard(state: AppState, dispatch: (JSONObject) -> Unit) {
    AppCard {
        Text("FIPS", style = MaterialTheme.typography.titleMedium)
        Row(verticalAlignment = Alignment.CenterVertically) {
            Checkbox(
                checked = state.connectToNonRosterFipsPeers,
                onCheckedChange = { enabled ->
                    dispatch(NativeActions.updateSettings("connectToNonRosterFipsPeers" to enabled))
                },
            )
            Text("Connect to non-roster FIPS peers")
        }
        Row(verticalAlignment = Alignment.CenterVertically) {
            Checkbox(
                checked = state.fipsNostrDiscoveryEnabled,
                onCheckedChange = { enabled ->
                    dispatch(NativeActions.updateSettings("fipsNostrDiscoveryEnabled" to enabled))
                },
            )
            Text("Find peers over Nostr relays")
        }
        Row(verticalAlignment = Alignment.CenterVertically) {
            Checkbox(
                checked = state.fipsBootstrapEnabled,
                onCheckedChange = { enabled ->
                    dispatch(NativeActions.updateSettings("fipsBootstrapEnabled" to enabled))
                },
            )
            Text("Use bootstrap servers")
        }
        Row(verticalAlignment = Alignment.CenterVertically) {
            Checkbox(
                checked = state.fipsWebrtcEnabled,
                onCheckedChange = { enabled ->
                    dispatch(NativeActions.updateSettings("fipsWebrtcEnabled" to enabled))
                },
            )
            Text("Enable WebRTC transport")
        }
    }
}

@Composable
internal fun RelaySettingsCard(state: AppState, dispatch: (JSONObject) -> Unit) {
    var relayInput by remember { mutableStateOf("") }

    fun normalizeRelayUrl(value: String): String? {
        val trimmed = value.trim()
        if (trimmed.isEmpty()) return null
        return if (trimmed.startsWith("ws://") || trimmed.startsWith("wss://")) trimmed else "wss://$trimmed"
    }

    fun uniqueRelays(values: List<String>): List<String> {
        val seen = linkedSetOf<String>()
        values.forEach { relay ->
            if (relay.isNotBlank()) seen.add(relay)
        }
        return seen.toList()
    }

    fun relayLists(): Pair<List<String>, List<String>> {
        val enabled = uniqueRelays(state.relays.filter { it.enabled }.mapNotNull { normalizeRelayUrl(it.url) })
        val disabled = uniqueRelays(state.relays.filter { !it.enabled }.mapNotNull { normalizeRelayUrl(it.url) })
            .filter { it !in enabled }
        return enabled to disabled
    }

    fun saveRelays(enabledInput: List<String>, disabledInput: List<String>) {
        val enabled = uniqueRelays(enabledInput)
        val disabled = uniqueRelays(disabledInput).filter { it !in enabled }
        dispatch(
            NativeActions.updateSettings(
                "relays" to enabled,
                "disabledRelays" to disabled,
            ),
        )
    }

    fun addRelay() {
        val url = normalizeRelayUrl(relayInput) ?: return
        val (enabled, disabled) = relayLists()
        saveRelays(
            if (url in enabled) enabled else enabled + url,
            disabled.filter { it != url },
        )
        relayInput = ""
    }

    fun setRelay(url: String, enabledValue: Boolean) {
        val relayUrl = normalizeRelayUrl(url) ?: return
        val (enabled, disabled) = relayLists()
        saveRelays(
            if (enabledValue) enabled.filter { it != relayUrl } + relayUrl else enabled.filter { it != relayUrl },
            if (enabledValue) disabled.filter { it != relayUrl } else disabled.filter { it != relayUrl } + relayUrl,
        )
    }

    fun deleteRelay(url: String) {
        val relayUrl = normalizeRelayUrl(url) ?: return
        val (enabled, disabled) = relayLists()
        saveRelays(
            enabled.filter { it != relayUrl },
            disabled.filter { it != relayUrl },
        )
    }

    AppCard {
        Text("Relays", style = MaterialTheme.typography.titleMedium)
        Row(verticalAlignment = Alignment.CenterVertically) {
            OutlinedTextField(
                relayInput,
                { relayInput = it },
                Modifier.weight(1f),
                singleLine = true,
                placeholder = { Text("wss://relay.example.com") },
            )
            Spacer(Modifier.width(8.dp))
            Button(
                onClick = { addRelay() },
                enabled = relayInput.trim().isNotEmpty(),
            ) {
                Text("Add")
            }
        }
        Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
            state.relays.forEach { relay ->
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Dot(selected = relay.enabled && relay.status == "connected")
                    Spacer(Modifier.width(8.dp))
                    Text(
                        relay.url,
                        modifier = Modifier
                            .weight(1f)
                            .alpha(if (relay.enabled) 1f else 0.62f),
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                    Switch(
                        checked = relay.enabled,
                        onCheckedChange = { setRelay(relay.url, it) },
                    )
                    TextButton(onClick = { deleteRelay(relay.url) }) {
                        Text("Delete")
                    }
                }
            }
        }
    }
}

@Composable
internal fun ExitNodeRow(
    title: String,
    subtitle: String,
    selected: Boolean,
    enabled: Boolean,
    onClick: () -> Unit,
) {
    val alpha = if (enabled) 1f else 0.5f
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier =
            Modifier
                .fillMaxWidth()
                .clickable(enabled = enabled, onClick = onClick)
                .padding(vertical = 6.dp)
                .alpha(alpha),
    ) {
        Text(
            if (selected) "●" else "○",
            color =
                if (selected) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.outline,
            style = MaterialTheme.typography.titleLarge,
        )
        Spacer(Modifier.width(10.dp))
        Column(modifier = Modifier.weight(1f)) {
            Text(title, style = MaterialTheme.typography.bodyMedium)
            if (subtitle.isNotEmpty()) {
                Text(
                    subtitle,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.outline,
                    maxLines = 1,
                )
            }
        }
    }
}

@Composable
internal fun WireGuardSettingsCard(
    state: AppState,
    dispatch: (JSONObject) -> Unit,
    importConfigFile: () -> Unit,
) {
    var config by remember(state.wireguardExitConfig) { mutableStateOf(state.wireguardExitConfig) }

    AppCard {
        Text("WireGuard Upstream", style = MaterialTheme.typography.titleMedium)
        Text(
            "Paste a WireGuard config from an upstream VPN provider such as Mullvad or Proton VPN.",
            color = Muted,
            style = MaterialTheme.typography.bodySmall,
        )
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("Enabled", modifier = Modifier.weight(1f))
            Switch(
                checked = state.wireguardExitEnabled,
                onCheckedChange = { enabled ->
                    dispatch(NativeActions.updateSettings("wireguardExitEnabled" to enabled))
                },
                modifier = Modifier.mobileUiSelector(
                    id = "wireguard-enabled",
                    description = if (state.wireguardExitEnabled) {
                        "WireGuard upstream on"
                    } else {
                        "WireGuard upstream off"
                    },
                ),
            )
        }
        OutlinedTextField(
            config,
            { config = it },
            Modifier
                .fillMaxWidth()
                .mobileUiSelector(
                    id = "wireguard-config",
                    description = "WireGuard upstream config",
                ),
            minLines = 8,
            label = { Text("Config") },
        )
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(
                onClick = {
                    dispatch(
                        NativeActions.updateSettings(
                            "wireguardExitConfig" to config,
                        ),
                    )
                },
                modifier = Modifier.mobileUiSelector(
                    id = "wireguard-save",
                    description = "Save WireGuard upstream config",
                ),
            ) {
                Text("Save")
            }
            OutlinedButton(onClick = importConfigFile) {
                Text("Import file")
            }
        }
    }
}

@Composable
internal fun DiagnosticsCard(state: AppState) {
    AppCard {
        Text("Diagnostics", style = MaterialTheme.typography.titleMedium)
        Metric("Runtime", state.runtimeStatusDetail.ifBlank { state.platform })
        Metric("Peers", "${state.connectedPeerCount}/${state.expectedPeerCount}")
        Metric("Roster FIPS", "${state.fipsConnectedPeerCount}/${state.fipsRosterPeerCount} direct")
        Metric("Other FIPS", "${state.nonFipsRosterPeerCount}")
        Metric("MagicDNS", state.magicDnsStatus)
        Metric("Version", state.appVersion)
        state.health.forEach { issue ->
            Text(issue.severity, color = Color(0xFFA16207), fontWeight = FontWeight.SemiBold)
            Text(issue.summary)
            if (issue.detail.isNotBlank()) Text(issue.detail, color = Muted)
        }
    }
}

@Composable
internal fun QrCode(
    text: String,
    qrJson: (String) -> JSONObject,
    accessibilityDescription: String,
    modifier: Modifier = Modifier,
) {
    val qr = remember(text) { qrJson(text) }
    val width = qr.optInt("width")
    val cells = qr.optJSONArray("cells")
    Canvas(
        modifier = modifier
            .fillMaxWidth()
            .aspectRatio(1f)
            .mobileUiSelector(
                id = "qr-code",
                description = accessibilityDescription,
            )
            .clip(RoundedCornerShape(8.dp))
            .background(Color.White),
    ) {
        drawRect(Color.White)
        if (width <= 0 || cells == null) return@Canvas
        val quiet = 3
        val modules = width + quiet * 2
        val cell = size.minDimension / modules
        for (y in 0 until width) {
            for (x in 0 until width) {
                if (cells.optBoolean(y * width + x)) {
                    drawRect(
                        color = Color(0xFF111827),
                        topLeft = androidx.compose.ui.geometry.Offset((x + quiet) * cell, (y + quiet) * cell),
                        size = Size(cell, cell),
                    )
                }
            }
        }
    }
}

@Composable
internal fun AppCard(content: @Composable ColumnScope.() -> Unit) {
    Card(
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        shape = RoundedCornerShape(8.dp),
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
            content = content,
        )
    }
}

@Composable
internal fun EmptyCard(text: String) {
    AppCard { Text(text, color = Muted) }
}

@Composable
internal fun Notice(text: String) {
    AppCard { Text(text, color = Color(0xFF9A3412)) }
}

@Composable
internal fun CopyLine(
    value: String,
    displayValue: String = value,
    selectorId: String? = null,
    selectorDescription: String? = null,
) {
    val valueModifier = if (selectorId != null && selectorDescription != null) {
        Modifier.mobileUiSelector(
            id = selectorId,
            description = "$selectorDescription: $value",
        )
    } else {
        Modifier
    }
    Row(verticalAlignment = Alignment.Top) {
        Text(
            breakableDisplayValue(displayValue),
            modifier = valueModifier.weight(1f),
            color = Muted,
            softWrap = true,
        )
        CopyButton(value)
    }
}

private fun breakableDisplayValue(value: String): String {
    val display = value.ifBlank { "-" }
    return if (display.length > 24 && display.none { it.isWhitespace() }) {
        display.chunked(8).joinToString("\u200B")
    } else {
        display
    }
}

@Composable
internal fun CopyButton(value: String, text: String = "Copy") {
    val context = LocalContext.current
    TextButton(enabled = value.isNotBlank(), onClick = {
        val clipboard = context.getSystemService(ClipboardManager::class.java)
        clipboard.setPrimaryClip(ClipData.newPlainText("Nostr VPN", value))
    }, modifier = Modifier.widthIn(min = 64.dp)) {
        Text(text, maxLines = 1, softWrap = false)
    }
}

@Composable
internal fun Metric(label: String, value: String) {
    Row {
        Text(label, color = Muted, modifier = Modifier.width(88.dp))
        Text(value.ifBlank { "-" }, modifier = Modifier.weight(1f), maxLines = 2, overflow = TextOverflow.Ellipsis)
    }
}

@Composable
internal fun Dot(selected: Boolean) {
    Box(
        modifier = Modifier
            .size(if (selected) 12.dp else 8.dp)
            .clip(CircleShape)
            .background(if (selected) Ok else Color(0xFFD1D5DB)),
    )
}

@Composable
internal fun Pill(text: String, background: Color, foreground: Color) {
    Text(
        text = text,
        color = foreground,
        style = MaterialTheme.typography.labelSmall,
        maxLines = 1,
        softWrap = false,
        modifier = Modifier
            .clip(RoundedCornerShape(999.dp))
            .background(background)
            .padding(horizontal = 8.dp, vertical = 3.dp),
    )
}

internal val Accent = Color(0xFF7C3AED)
internal val Ok = Color(0xFF16A34A)
internal val Muted = Color(0xFF68717C)
internal const val JOIN_REQUEST_SENT_TEXT = "Join request sent"
