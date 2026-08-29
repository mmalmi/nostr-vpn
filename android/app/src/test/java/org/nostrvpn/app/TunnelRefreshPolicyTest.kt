package org.nostrvpn.app

import org.nostrvpn.app.core.AppState
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class TunnelRefreshPolicyTest {
    @Test
    fun periodicStatusRefreshSkipsTunnelConfigRecomputation() {
        assertFalse(
            AndroidRefreshPolicy.shouldRefreshTunnelConfig(AndroidRefreshTrigger.PERIODIC),
        )
        assertTrue(
            AndroidRefreshPolicy.shouldRefreshTunnelConfig(AndroidRefreshTrigger.CONFIG_CHANGED),
        )
    }

    @Test
    fun revisionOnlyRefreshDoesNotReplaceComposeState() {
        val current = AppState(rev = 7, nodeName = "Pixel")

        assertFalse(
            AndroidRefreshPolicy.shouldReplaceState(
                current = current,
                refreshed = current.copy(rev = 8),
            ),
        )
        assertTrue(
            AndroidRefreshPolicy.shouldReplaceState(
                current = current,
                refreshed = current.copy(rev = 8, vpnStatus = "VPN on"),
            ),
        )
    }

    @Test
    fun qrAndManualApprovalActionsRestartTheRunningTunnel() {
        assertTrue(TunnelRefreshPolicy.requiresTunnelRefresh("import_join_request"))
        assertTrue(TunnelRefreshPolicy.requiresTunnelRefresh("accept_join_request"))
        assertTrue(TunnelRefreshPolicy.requiresTunnelRefresh("manual_add_network"))
        assertTrue(TunnelRefreshPolicy.requiresTunnelRefresh("add_participant"))
        assertTrue(TunnelRefreshPolicy.requiresTunnelRefresh("set_manual_paid_exit_provider"))
        assertTrue(TunnelRefreshPolicy.requiresTunnelRefresh("clear_manual_paid_exit_provider"))
    }

    @Test
    fun creatingOrImportingANetworkStartsTheTunnelOnlyWhenItIsOff() {
        assertTrue(TunnelRefreshPolicy.shouldStartTunnelAfterAction("add_network", false))
        assertTrue(TunnelRefreshPolicy.shouldStartTunnelAfterAction("import_join_request", false))
        assertFalse(TunnelRefreshPolicy.shouldStartTunnelAfterAction("add_network", true))
        assertFalse(TunnelRefreshPolicy.shouldStartTunnelAfterAction("tick", false))
    }

    @Test
    fun rosterAndTunnelSettingsRestartButUiOnlyActionsDoNot() {
        assertTrue(TunnelRefreshPolicy.requiresTunnelRefresh("set_participant_alias"))
        assertTrue(
            TunnelRefreshPolicy.requiresTunnelRefresh(
                "update_settings",
                setOf("exitDnsMode"),
            ),
        )
        assertTrue(
            TunnelRefreshPolicy.requiresTunnelRefresh(
                "update_settings",
                setOf("internetSource"),
            ),
        )
        assertFalse(TunnelRefreshPolicy.requiresTunnelRefresh("tick"))
        assertFalse(
            TunnelRefreshPolicy.requiresTunnelRefresh(
                "update_settings",
                setOf("fiatCurrency"),
            ),
        )
    }
    @Test
    fun explicitDisconnectAlwaysStopsTheAndroidVpnService() {
        assertEquals(
            TunnelServiceCommand.DISCONNECT,
            TunnelServiceCommandPolicy.commandAfterAction(
                actionType = "disconnect_vpn",
                wasEnabled = false,
                isEnabled = false,
                requiresRefresh = false,
            ),
        )
        assertEquals(
            TunnelServiceCommand.DISCONNECT,
            TunnelServiceCommandPolicy.commandAfterAction(
                actionType = "disconnect_vpn",
                wasEnabled = true,
                isEnabled = true,
                requiresRefresh = false,
            ),
        )
    }

    @Test
    fun activityStartDisconnectsStateLeftByAKilledTunnelProcess() {
        assertEquals(
            TunnelServiceCommand.DISCONNECT,
            TunnelServiceCommandPolicy.commandAfterActivityStart(
                vpnEnabled = true,
                tunnelOwnedInProcess = false,
            ),
        )
        assertEquals(
            TunnelServiceCommand.NONE,
            TunnelServiceCommandPolicy.commandAfterActivityStart(
                vpnEnabled = true,
                tunnelOwnedInProcess = true,
            ),
        )
        assertEquals(
            TunnelServiceCommand.NONE,
            TunnelServiceCommandPolicy.commandAfterActivityStart(
                vpnEnabled = false,
                tunnelOwnedInProcess = false,
            ),
        )
    }

    @Test
    fun rapidToggleReadsAuthoritativeStateInsteadOfAStaleComposeValue() {
        assertEquals("connect_vpn", nextVpnToggleAction(vpnEnabled = false).getString("type"))
        assertEquals("disconnect_vpn", nextVpnToggleAction(vpnEnabled = true).getString("type"))
    }

    @Test
    fun tunnelTransitionsAndRefreshesSelectTheExpectedServiceCommand() {
        assertEquals(
            TunnelServiceCommand.CONNECT,
            TunnelServiceCommandPolicy.commandAfterAction("connect_vpn", false, true, false),
        )
        assertEquals(
            TunnelServiceCommand.CONNECT,
            TunnelServiceCommandPolicy.commandAfterAction("update_settings", true, true, true),
        )
        assertEquals(
            TunnelServiceCommand.NONE,
            TunnelServiceCommandPolicy.commandAfterAction("tick", true, true, false),
        )
    }

    @Test
    fun asynchronouslyReceivedRosterRestartsOnlyAnEnabledChangedTunnel() {
        assertTrue(
            TunnelConfigRefreshPolicy.requiresAsyncRefresh(
                vpnEnabled = true,
                observedConfigJson = """{"routeTargets":["10.44.0.1/32"]}""",
                currentConfigJson = """{"routeTargets":["10.44.0.0/16"]}""",
            ),
        )
        assertFalse(
            TunnelConfigRefreshPolicy.requiresAsyncRefresh(
                vpnEnabled = true,
                observedConfigJson = """{"routeTargets":["10.44.0.0/16"]}""",
                currentConfigJson = """{"routeTargets":["10.44.0.0/16"]}""",
            ),
        )
        assertFalse(
            TunnelConfigRefreshPolicy.requiresAsyncRefresh(
                vpnEnabled = false,
                observedConfigJson = """{"routeTargets":["10.44.0.1/32"]}""",
                currentConfigJson = """{"routeTargets":["10.44.0.0/16"]}""",
            ),
        )
    }

    @Test
    fun learnedEndpointsAndSerializedAppStateDoNotRestartTheTunnel() {
        val observed = """
            {
              "networkId":"mesh",
              "routeTargets":["10.44.0.0/16"],
              "peers":[{"npub":"peer"}],
              "advertisedEndpoint":"udp://old",
              "peerHints":{"peer":[{"address":"udp://old"}]},
              "appConfigToml":"old",
              "error":""
            }
        """.trimIndent()
        val refreshed = """
            {
              "error":"",
              "appConfigToml":"new",
              "peerHints":{"peer":[{"address":"udp://new"}]},
              "advertisedEndpoint":"udp://new",
              "peers":[{"npub":"peer"}],
              "routeTargets":["10.44.0.0/16"],
              "networkId":"mesh"
            }
        """.trimIndent()

        assertFalse(
            TunnelConfigRefreshPolicy.requiresAsyncRefresh(
                vpnEnabled = true,
                observedConfigJson = observed,
                currentConfigJson = refreshed,
            ),
        )
    }

    @Test
    fun runningTunnelDrainsQueuedJoinApprovalsBeforeRestart() {
        val queuedApproval = """
            {"queuedJoinRosters":[{"recipientNpub":"npub1joiner"}]}
        """.trimIndent()

        assertTrue(
            TunnelConfigRefreshPolicy.shouldDeferRestartForQueuedApproval(
                tunnelRunning = true,
                configJson = queuedApproval,
            ),
        )
        assertFalse(
            TunnelConfigRefreshPolicy.shouldDeferRestartForQueuedApproval(
                tunnelRunning = false,
                configJson = queuedApproval,
            ),
        )
        assertFalse(
            TunnelConfigRefreshPolicy.shouldDeferRestartForQueuedApproval(
                tunnelRunning = true,
                configJson = """{"queuedJoinRosters":[]}""",
            ),
        )
        assertFalse(
            TunnelConfigRefreshPolicy.shouldDeferRestartForQueuedApproval(
                tunnelRunning = true,
                configJson = "not-json",
            ),
        )
    }
}
