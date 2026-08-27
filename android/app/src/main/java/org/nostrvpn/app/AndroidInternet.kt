package org.nostrvpn.app

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.size
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import org.json.JSONObject
import org.nostrvpn.app.core.AppState
import org.nostrvpn.app.core.NativeActions
import org.nostrvpn.app.core.NetworkState

internal fun androidx.compose.foundation.lazy.LazyListScope.internetPage(
    state: AppState,
    network: NetworkState?,
    dispatch: (JSONObject) -> Unit,
    importWireGuardConfigFile: () -> Unit,
) {
    item {
        AppCard {
            Text("Internet source", style = MaterialTheme.typography.titleMedium)
            Spacer(Modifier.height(10.dp))
            var sourceMenuExpanded by remember { mutableStateOf(false) }
            val sourceOptions = listOf(
                "direct" to "This device",
                "private_vpn" to "Private VPN device",
                "paid_automatic" to "Paid · Automatic · Experimental",
                "paid_manual" to "Paid · Choose manually",
                "wireguard" to "WireGuard VPN",
            )
            Box {
                Button(
                    onClick = { sourceMenuExpanded = true },
                    modifier = Modifier.mobileUiSelector(
                        id = "internet-source-picker",
                        description = "Internet source picker",
                    ),
                ) {
                    Text(sourceOptions.firstOrNull { it.first == state.internetSource }?.second ?: "This device")
                }
                DropdownMenu(
                    expanded = sourceMenuExpanded,
                    onDismissRequest = { sourceMenuExpanded = false },
                ) {
                    sourceOptions.forEach { (source, title) ->
                        DropdownMenuItem(
                            text = { Text(title) },
                            modifier = Modifier.mobileUiSelector(
                                id = "internet-source-$source",
                                description = "Internet source $title",
                            ),
                            onClick = {
                                sourceMenuExpanded = false
                                dispatch(NativeActions.updateSettings("internetSource" to source))
                            },
                        )
                    }
                }
            }
            Text(
                state.exitNodeStatusText,
                modifier = Modifier.mobileUiSelector(
                    id = "internet-source-status",
                    description = "Current internet status",
                ),
                color = if (state.exitNodeBlocked) MaterialTheme.colorScheme.error else Muted,
                style = MaterialTheme.typography.bodySmall,
            )

            if (state.internetSource == "private_vpn") {
                val exitParticipants = network?.participants.orEmpty()
                    .filter { it.offersExitNode && !it.isCurrentDevice(state) }
                if (exitParticipants.isEmpty()) {
                    Text("No trusted devices sharing internet", color = Muted, style = MaterialTheme.typography.bodySmall)
                } else {
                    exitParticipants.forEach { participant ->
                        ExitNodeRow(
                            title = participant.magicDnsName.ifBlank { participant.alias },
                            subtitle = participant.npub,
                            selected = state.exitNode == participant.npub,
                            enabled = true,
                            onClick = {
                                dispatch(
                                    NativeActions.updateSettings(
                                        "internetSource" to "private_vpn",
                                        "exitNode" to participant.npub,
                                    ),
                                )
                            },
                        )
                    }
                }
            }

            Spacer(Modifier.height(10.dp))
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Text(
                    "Block internet if selected source disconnects",
                    modifier = Modifier.weight(1f),
                    style = MaterialTheme.typography.bodyMedium,
                )
                Switch(
                    checked = state.exitNodeLeakProtection,
                    onCheckedChange = { enabled ->
                        dispatch(NativeActions.updateSettings("exitNodeLeakProtection" to enabled))
                    },
                )
            }
        }
    }
    if (state.internetSource == "paid_automatic") {
        item {
            AppCard {
                Text("Automatic paid provider", style = MaterialTheme.typography.titleMedium)
                Text("Experimental", color = Muted, style = MaterialTheme.typography.labelSmall)
                Text(
                    state.exitNodeStatusText,
                    color = Muted,
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        }
    } else if (state.internetSource == "paid_manual") {
        item { PaidRouteMarketCard(state, dispatch, PaidRouteCardMode.Market) }
    }
    item {
        AppCard {
            Text("Share Internet", style = MaterialTheme.typography.titleMedium)
            Row(verticalAlignment = Alignment.CenterVertically) {
                Checkbox(
                    checked = state.advertiseExitNode,
                    onCheckedChange = { enabled ->
                        dispatch(NativeActions.updateSettings("advertiseExitNode" to enabled))
                    },
                )
                val name = network?.name?.ifBlank { null } ?: "this network"
                Text("Share internet with $name")
            }
        }
    }
    if (state.internetSource == "wireguard") {
        item { WireGuardSettingsCard(state, dispatch, importWireGuardConfigFile) }
    }
    if (state.internetSource != "direct") {
        item { ExitDnsSettingsCard(state, dispatch) }
    }
}
