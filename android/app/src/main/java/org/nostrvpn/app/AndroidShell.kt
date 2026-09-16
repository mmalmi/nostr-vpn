package org.nostrvpn.app

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.lightColorScheme
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
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import kotlin.math.PI
import kotlin.math.cos
import kotlin.math.sin
import org.json.JSONObject
import org.nostrvpn.app.core.AppState
import org.nostrvpn.app.core.NativeActions
import org.nostrvpn.app.core.NetworkState
import org.nostrvpn.app.core.activeNetwork
import org.nostrvpn.app.update.AndroidSelfUpdateState

internal data class SelfUpdateActions(
    val check: () -> Unit,
    val download: () -> Unit,
    val install: () -> Unit,
    val setAutoCheck: (Boolean) -> Unit,
)

private enum class Page(val title: String) {
    Devices("Devices"),
    Internet("Internet"),
    Wallet("Wallet"),
    Settings("Settings"),
}
internal enum class NetworkSetupMode {
    Create,
    Join,
}

private fun Page.visibleIn(state: AppState): Boolean =
    when (this) {
        Page.Wallet -> state.paidRouteMarket.supported
        Page.Devices, Page.Internet, Page.Settings -> true
    }

@Composable
internal fun NostrVpnTheme(content: @Composable () -> Unit) {
    val darkTheme = isSystemInDarkTheme()
    MaterialTheme(
        colorScheme = if (darkTheme) {
            darkColorScheme(
                primary = Color(0xFFA78BFA),
                secondary = Color(0xFF67E8F9),
                background = Color(0xFF101419),
                surface = Color(0xFF171D24),
                onPrimary = Color(0xFF1E1235),
                onSecondary = Color(0xFF06161A),
                onBackground = Color(0xFFE7ECF2),
                onSurface = Color(0xFFE7ECF2),
                surfaceVariant = Color(0xFF202833),
                onSurfaceVariant = Color(0xFFAAB4C0),
                error = Color(0xFFFCA5A5),
                outline = Color(0xFF5F6B7A),
            )
        } else {
            lightColorScheme(
                primary = Color(0xFF8B5CF6),
                secondary = Color(0xFF22D3EE),
                background = Color(0xFFF6F7F8),
                surface = Color.White,
                onPrimary = Color.White,
                onSecondary = Color(0xFF111827),
                onBackground = Color(0xFF17202A),
                onSurface = Color(0xFF17202A),
                surfaceVariant = Color(0xFFF1F5F9),
                onSurfaceVariant = Color(0xFF68717C),
                error = Color(0xFFB00020),
                outline = Color(0xFF9CA3AF),
            )
        },
        content = content,
    )
}

@Composable
internal fun NostrVpnApp(
    state: AppState,
    qrJson: (String) -> JSONObject,
    scanDeviceQr: (String) -> Unit,
    dispatch: (JSONObject) -> Unit,
    dispatchSucceeded: (JSONObject) -> Boolean,
    currentActiveNetworkId: () -> String?,
    deviceAddCompletionNonce: Long,
    toggleVpn: () -> Unit,
    selfUpdateState: AndroidSelfUpdateState,
    selfUpdateActions: SelfUpdateActions,
    importWireGuardConfigFile: () -> Unit,
) {
    var page by remember { mutableStateOf(Page.Devices) }
    var manualExitChooserOpen by remember { mutableStateOf(false) }
    var showAddDevice by remember { mutableStateOf(false) }
    var showAddNetwork by remember { mutableStateOf(false) }
    var pendingNetworkRemoval by remember { mutableStateOf<NetworkState?>(null) }
    var shownNetworkId by remember { mutableStateOf<String?>(null) }
    val activeNetwork = state.activeNetwork
    val network = state.networks.firstOrNull { it.id == shownNetworkId }
        ?: activeNetwork
        ?: state.networks.firstOrNull()
    val visiblePages = Page.entries.filter { it.visibleIn(state) }
    val effectivePage = if (page.visibleIn(state)) page else Page.Devices
    LaunchedEffect(showAddDevice, network?.enabled) {
        if (showAddDevice && network?.enabled != true) {
            showAddDevice = false
        }
    }
    LaunchedEffect(state.paidRouteMarket.supported) {
        if (!page.visibleIn(state)) {
            page = Page.Devices
        }
    }
    LaunchedEffect(deviceAddCompletionNonce) {
        if (deviceAddCompletionNonce > 0) {
            showAddDevice = false
            page = Page.Devices
        }
    }
    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        topBar = {
            if (network != null) {
                MobileTopBar(
                    state = state,
                    network = network,
                    activeNetwork = activeNetwork,
                    toggleVpn = toggleVpn,
                    onSelectNetwork = { shownNetworkId = it },
                    onAddNetwork = { showAddNetwork = true },
                )
            }
        },
        bottomBar = {
            // Bottom nav only makes sense once a network exists. With no
            // network the only meaningful action is Add Network, which we
            // surface as the entire screen body.
            if (network != null) {
                NavigationBar(containerColor = MaterialTheme.colorScheme.surface) {
                    visiblePages.forEach { item ->
                        NavigationBarItem(
                            selected = effectivePage == item,
                            onClick = { page = item },
                            modifier = Modifier.mobileUiSelector(
                                id = "navigation-${item.title.lowercase()}",
                                description = "${item.title} tab",
                            ),
                            icon = {
                                NavIcon(
                                    item,
                                    selected = effectivePage == item,
                                    attention = false,
                                )
                            },
                            label = {
                                val balance = state.paidRouteMarket.wallet.navigationBalanceText
                                Text(
                                    if (item == Page.Wallet && balance.isNotBlank()) {
                                        "Wallet $balance"
                                    } else {
                                        item.title
                                    },
                                )
                            },
                        )
                    }
                }
            }
        },
    ) { padding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .exposeMobileUiSelectors()
                .padding(padding),
            contentPadding = PaddingValues(18.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            if (state.error.isNotBlank()) {
                item { Notice(state.error) }
            }
            if (network == null) {
                addNetworkBody(
                    state,
                    qrJson,
                    dispatch,
                    dispatchSucceeded,
                    showWelcomeHeader = true,
                )
            } else {
                when (effectivePage) {
                    Page.Devices -> devicesPage(
                        state,
                        network,
                        dispatch,
                        onAddDevice = { showAddDevice = true },
                        onDeleteNetwork = { pendingNetworkRemoval = network },
                    )
                    Page.Internet -> internetPage(state, network, dispatch, importWireGuardConfigFile, manualExitChooserOpen) { manualExitChooserOpen = it }
                    Page.Wallet -> walletPage(state, qrJson, dispatch)
                    Page.Settings -> settingsPage(state, network, dispatch, selfUpdateState, selfUpdateActions)
                }
            }
        }
    }
    if (showAddDevice && network?.enabled == true) {
        AddDevicesDialog(
            state = state,
            network = network,
            scanDeviceQr = scanDeviceQr,
            dispatch = dispatch,
            dispatchSucceeded = dispatchSucceeded,
            onDismiss = { showAddDevice = false },
        )
    }
    if (showAddNetwork) {
        AddNetworkDialog(
            state = state,
            qrJson = qrJson,
            dispatch = dispatch,
            dispatchSucceeded = dispatchSucceeded,
            onDismiss = { showAddNetwork = false },
            onCreated = {
                // Land on the new network's Devices view: dismiss the
                // dialog and reset the nav to Devices in case the user
                // was on another page when they tapped Add
                // network.
                shownNetworkId = currentActiveNetworkId()
                showAddNetwork = false
                page = Page.Devices
            },
        )
    }
    pendingNetworkRemoval?.let { target ->
        AlertDialog(
            onDismissRequest = { pendingNetworkRemoval = null },
            title = { Text("Delete ${target.name.ifBlank { "network" }}?") },
            text = { Text("Removes the network from this device.") },
            confirmButton = {
                TextButton(onClick = {
                    dispatch(NativeActions.removeNetwork(target.id))
                    pendingNetworkRemoval = null
                }) {
                    Text("Delete", color = Color(0xFFB00020))
                }
            },
            dismissButton = {
                TextButton(onClick = { pendingNetworkRemoval = null }) { Text("Cancel") }
            },
        )
    }
}

@Composable
private fun MobileTopBar(
    state: AppState,
    network: NetworkState?,
    activeNetwork: NetworkState?,
    toggleVpn: () -> Unit,
    onSelectNetwork: (String) -> Unit,
    onAddNetwork: () -> Unit,
) {
    var menuExpanded by remember { mutableStateOf(false) }
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(MaterialTheme.colorScheme.surface)
            .statusBarsPadding()
            .padding(horizontal = 18.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Box(Modifier.weight(1f)) {
            // Single dropdown: switch network OR add a new one. Whole row
            // tappable so it reads as a "current network: name" affordance.
            Row(
                modifier = Modifier.clickable { menuExpanded = true },
                verticalAlignment = Alignment.CenterVertically,
            ) {
                if (state.networks.size > 1) {
                    NetworkStatusDot(network)
                    Spacer(Modifier.width(8.dp))
                }
                Text(
                    networkTitle(network),
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.SemiBold,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Spacer(Modifier.width(6.dp))
                Text("▾", color = Muted)
            }
            DropdownMenu(expanded = menuExpanded, onDismissRequest = { menuExpanded = false }) {
                state.networks.forEach { saved ->
                    DropdownMenuItem(
                        text = {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                if (state.networks.size > 1) {
                                    NetworkStatusDot(saved)
                                    Spacer(Modifier.width(8.dp))
                                }
                                Text(networkTitle(saved))
                            }
                        },
                        onClick = {
                            menuExpanded = false
                            onSelectNetwork(saved.id)
                        },
                    )
                }
                if (state.networks.isNotEmpty()) {
                    HorizontalDivider()
                }
                DropdownMenuItem(
                    text = { Text("Add network") },
                    onClick = {
                        menuExpanded = false
                        onAddNetwork()
                    },
                )
            }
        }
        Switch(
            checked = state.vpnEnabled,
            enabled = state.vpnControlSupported && activeNetwork != null,
            onCheckedChange = { toggleVpn() },
            modifier = Modifier.mobileUiSelector(
                id = "vpn-toggle",
                description = if (state.vpnEnabled) "Turn VPN off" else "Turn VPN on",
            ),
        )
    }
}

@Composable
private fun NetworkStatusDot(network: NetworkState?) {
    Canvas(modifier = Modifier.size(8.dp)) {
        drawCircle(if (network?.enabled == true) Color(0xFF16A34A) else Color(0xFF9CA3AF))
    }
}

@Composable
private fun NavIcon(page: Page, selected: Boolean, attention: Boolean = false) {
    val color = if (selected) Accent else MaterialTheme.colorScheme.onSurface
    val badgeRing = MaterialTheme.colorScheme.surface
    Canvas(modifier = Modifier.size(28.dp)) {
        val strokeWidth = 2.6.dp.toPx()
        val stroke = Stroke(width = strokeWidth, cap = StrokeCap.Round)
        when (page) {
            Page.Devices -> {
                val radius = 3.6.dp.toPx()
                val gap = 5.4.dp.toPx()
                val center = Offset(size.width / 2f, size.height / 2f)
                for (x in listOf(-gap, gap)) {
                    for (y in listOf(-gap, gap)) {
                        drawCircle(color, radius, Offset(center.x + x, center.y + y))
                    }
                }
            }
            Page.Internet -> {
                val center = Offset(size.width / 2f, size.height / 2f)
                drawCircle(color, 10.5.dp.toPx(), center, style = stroke)
                drawLine(
                    color,
                    Offset(center.x - 10.5.dp.toPx(), center.y),
                    Offset(center.x + 10.5.dp.toPx(), center.y),
                    strokeWidth = strokeWidth,
                    cap = StrokeCap.Round,
                )
                drawLine(
                    color,
                    Offset(center.x, center.y - 10.5.dp.toPx()),
                    Offset(center.x, center.y + 10.5.dp.toPx()),
                    strokeWidth = strokeWidth,
                    cap = StrokeCap.Round,
                )
            }
            Page.Wallet -> {
                val left = 5.dp.toPx()
                val top = 8.dp.toPx()
                val right = 23.dp.toPx()
                val bottom = 21.dp.toPx()
                drawRoundRect(
                    color,
                    topLeft = Offset(left, top),
                    size = androidx.compose.ui.geometry.Size(right - left, bottom - top),
                    cornerRadius = androidx.compose.ui.geometry.CornerRadius(2.5.dp.toPx()),
                    style = stroke,
                )
                drawLine(color, Offset(left + 2.dp.toPx(), 13.dp.toPx()), Offset(right - 2.dp.toPx(), 13.dp.toPx()), strokeWidth = strokeWidth, cap = StrokeCap.Round)
                drawCircle(color, 1.8.dp.toPx(), Offset(19.dp.toPx(), 17.dp.toPx()))
            }
            Page.Settings -> {
                val center = Offset(size.width / 2f, size.height / 2f)
                val inner = 8.6.dp.toPx()
                val outer = 12.1.dp.toPx()
                repeat(8) { index ->
                    val angle = index * PI.toFloat() / 4f
                    val start = Offset(center.x + cos(angle) * inner, center.y + sin(angle) * inner)
                    val end = Offset(center.x + cos(angle) * outer, center.y + sin(angle) * outer)
                    drawLine(color, start, end, strokeWidth = strokeWidth, cap = StrokeCap.Round)
                }
                drawCircle(color, 6.7.dp.toPx(), center, style = stroke)
                drawCircle(color, 2.4.dp.toPx(), center)
            }
        }
        if (attention) {
            val center = Offset(size.width - 4.dp.toPx(), 4.dp.toPx())
            drawCircle(badgeRing, 5.dp.toPx(), center)
            drawCircle(Color(0xFFDC2626), 4.dp.toPx(), center)
        }
    }
}
