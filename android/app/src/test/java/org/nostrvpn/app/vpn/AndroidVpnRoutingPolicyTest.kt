package org.nostrvpn.app.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.json.JSONObject
import org.junit.Test

class AndroidVpnRoutingPolicyTest {
    @Test
    fun wireGuardExitIncludesOwnProcessSoAppTrafficEntersTunnel() {
        assertFalse(AndroidVpnRoutingPolicy.excludesOwnProcess(wireGuardExitActive = true))
    }

    @Test
    fun fipsExitExcludesOwnProcessEvenThoughItHasDefaultRoute() {
        assertFalse(AndroidVpnRoutingPolicy.requiresBypass(listOf("0.0.0.0/0")))
        assertTrue(AndroidVpnRoutingPolicy.excludesOwnProcess(wireGuardExitActive = false))
    }

    @Test
    fun directAndSplitModesExcludeOwnProcess() {
        assertTrue(AndroidVpnRoutingPolicy.excludesOwnProcess(wireGuardExitActive = false))
    }

    @Test
    fun splitTunnelPermitsUnmatchedTrafficToUseDeviceInternet() {
        val routes = listOf("10.44.0.0/16", "10.72.0.9/32")
        assertTrue(AndroidVpnRoutingPolicy.requiresBypass(routes))
        assertEquals(
            listOf("0.0.0.0/0", "::/0"),
            AndroidVpnRoutingPolicy.excludedDeviceInternetRoutes(routes),
        )
        assertTrue(AndroidVpnRoutingPolicy.requiresBypass(emptyList()))
        assertFalse(AndroidVpnRoutingPolicy.supportsAlwaysOn(routes))
        assertFalse(AndroidVpnRoutingPolicy.installsVpnDns(routes))
    }

    @Test
    fun fullTunnelExitRemainsNonBypassable() {
        assertFalse(AndroidVpnRoutingPolicy.requiresBypass(listOf("0.0.0.0/0")))
        assertFalse(AndroidVpnRoutingPolicy.requiresBypass(listOf("::/0")))
        assertTrue(
            AndroidVpnRoutingPolicy
                .excludedDeviceInternetRoutes(listOf("0.0.0.0/0"))
                .isEmpty(),
        )
        assertTrue(AndroidVpnRoutingPolicy.supportsAlwaysOn(listOf("0.0.0.0/0")))
        assertTrue(AndroidVpnRoutingPolicy.installsVpnDns(listOf("0.0.0.0/0")))
    }

    @Test
    fun routeConfigNormalizesEntriesAndDetectsEitherInternetDefault() {
        val config = JSONObject(
            """{"routeTargets":[" 10.44.0.0/16 ","","   ","::/0"]}""",
        )

        assertEquals(
            listOf("10.44.0.0/16", "::/0"),
            AndroidVpnRoutingPolicy.routeTargets(config),
        )
        assertTrue(AndroidVpnRoutingPolicy.hasDefaultRoute(config))
        assertTrue(
            AndroidVpnRoutingPolicy.supportsAlwaysOnVpn(
                """{"routeTargets":["0.0.0.0/0"]}""",
            ),
        )
    }

    @Test
    fun memberRoutesUnderASelectedExitDoNotChangeTheInterface() {
        val exit = listOf("0.0.0.0/0", "10.44.0.53/32", "10.44.116.211/32")
        assertEquals(setOf("0.0.0.0/0"), AndroidVpnRoutingPolicy.effectiveRoutes(exit))
        assertEquals(
            AndroidVpnRoutingPolicy.effectiveRoutes(exit),
            AndroidVpnRoutingPolicy.effectiveRoutes(exit + "10.44.46.86/32"),
        )

        val split = listOf("10.44.0.53/32", "10.44.116.211/32")
        assertEquals(split.toSet(), AndroidVpnRoutingPolicy.effectiveRoutes(split))
        assertEquals(
            setOf("10.44.0.0/16", "10.72.0.9/32"),
            AndroidVpnRoutingPolicy.effectiveRoutes(
                listOf("10.44.0.0/16", "10.44.9.9/32", "10.72.0.9/32"),
            ),
        )
        assertEquals(
            setOf("0.0.0.0/0", "fd00::1/128"),
            AndroidVpnRoutingPolicy.effectiveRoutes(listOf("0.0.0.0/0", "fd00::1/128")),
        )
    }

    @Test
    fun missingOrMalformedRouteConfigCannotEnableAlwaysOn() {
        assertEquals(
            emptyList<String>(),
            AndroidVpnRoutingPolicy.routeTargets(JSONObject()),
        )
        assertFalse(AndroidVpnRoutingPolicy.hasDefaultRoute(JSONObject()))
        assertFalse(AndroidVpnRoutingPolicy.supportsAlwaysOnVpn("not-json"))
    }

    @Test
    fun onlyAChangedEstablishedFingerprintIsAPhysicalNetworkChange() {
        assertFalse(
            AndroidVpnRoutingPolicy.isPhysicalNetworkChange(
                previousFingerprint = null,
                currentFingerprint = "wifi",
            ),
        )
        assertFalse(
            AndroidVpnRoutingPolicy.isPhysicalNetworkChange(
                previousFingerprint = "wifi",
                currentFingerprint = "wifi",
            ),
        )
        assertTrue(
            AndroidVpnRoutingPolicy.isPhysicalNetworkChange(
                previousFingerprint = "wifi",
                currentFingerprint = "ethernet",
            ),
        )
    }

    @Test
    fun wireGuardUsesRouteReadyNetworkWhileValidationIsPending() {
        val candidate = underlay(
            handle = 41,
            active = true,
            routeReady = true,
        )

        assertEquals(
            41L,
            AndroidVpnRoutingPolicy.preferredWireGuardUnderlay(listOf(candidate)),
        )
    }

    @Test
    fun validatedActiveThenValidatedFallbackRemainPreferred() {
        val routeReadyActive = underlay(
            handle = 10,
            active = true,
            routeReady = true,
        )
        val validatedFallback = underlay(
            handle = 20,
            validated = true,
            routeReady = true,
        )
        val validatedActive = underlay(
            handle = 30,
            active = true,
            validated = true,
            routeReady = true,
        )

        assertEquals(
            20L,
            AndroidVpnRoutingPolicy.preferredWireGuardUnderlay(
                listOf(routeReadyActive, validatedFallback),
            ),
        )
        assertEquals(
            30L,
            AndroidVpnRoutingPolicy.preferredWireGuardUnderlay(
                listOf(routeReadyActive, validatedFallback, validatedActive),
            ),
        )
    }

    @Test
    fun routeReadyCaptivePortalIsNeverUsedAsWireGuardUnderlay() {
        assertNull(
            AndroidVpnRoutingPolicy.preferredWireGuardUnderlay(
                listOf(
                    underlay(
                        handle = 50,
                        active = true,
                        validated = true,
                        routeReady = true,
                        captivePortal = true,
                    ),
                ),
            ),
        )
    }

    @Test
    fun validationMetadataKeepsTheSameUnderlaySelected() {
        val pendingValidation = underlay(
            handle = 60,
            active = true,
            routeReady = true,
            validated = false,
        )
        val validated = pendingValidation.copy(validated = true)

        assertEquals(
            AndroidVpnRoutingPolicy.preferredWireGuardUnderlay(listOf(pendingValidation)),
            AndroidVpnRoutingPolicy.preferredWireGuardUnderlay(listOf(validated)),
        )
    }

    @Test
    fun networkRefreshesAreLeadingEdgeAndCoalesced() {
        assertEquals(0L, AndroidVpnRoutingPolicy.nextUnderlayRefreshDelay(null, true, 250))
        assertEquals(250L, AndroidVpnRoutingPolicy.nextUnderlayRefreshDelay(null, false, 250))
        assertEquals(0L, AndroidVpnRoutingPolicy.nextUnderlayRefreshDelay(250, true, 250))
        assertNull(AndroidVpnRoutingPolicy.nextUnderlayRefreshDelay(0, true, 250))
        assertNull(AndroidVpnRoutingPolicy.nextUnderlayRefreshDelay(250, false, 250))
    }

    private fun underlay(
        handle: Long,
        active: Boolean = false,
        validated: Boolean = false,
        routeReady: Boolean = false,
        captivePortal: Boolean = false,
        transportPreference: Int = 1,
    ) = AndroidVpnRoutingPolicy.UnderlayNetworkCandidate(
        handle = handle,
        active = active,
        validated = validated,
        usable = routeReady && !captivePortal,
        transportPreference = transportPreference,
    )
}
