package org.nostrvpn.app.vpn

import android.annotation.TargetApi
import android.net.IpPrefix
import android.os.Build
import org.json.JSONObject
import java.net.InetAddress

internal object AndroidVpnRoutingPolicy {
    data class UnderlayNetworkCandidate(
        val handle: Long,
        val active: Boolean,
        val validated: Boolean,
        val usable: Boolean,
        val transportPreference: Int,
    )

    fun isPhysicalNetworkChange(
        previousFingerprint: String?,
        currentFingerprint: String,
    ): Boolean =
        previousFingerprint != null && previousFingerprint != currentFingerprint

    fun excludesOwnProcess(wireGuardExitActive: Boolean): Boolean =
        !wireGuardExitActive

    fun requiresBypass(routeTargets: List<String>): Boolean =
        routeTargets.none { route ->
            route.trim() == "0.0.0.0/0" || route.trim() == "::/0"
        }

    fun excludedDeviceInternetRoutes(routeTargets: List<String>): List<String> =
        if (requiresBypass(routeTargets)) {
            listOf("0.0.0.0/0", "::/0")
        } else {
            emptyList()
        }

    fun supportsAlwaysOn(routeTargets: List<String>): Boolean =
        !requiresBypass(routeTargets)

    fun installsVpnDns(routeTargets: List<String>): Boolean =
        !requiresBypass(routeTargets)

    fun hasDefaultRoute(config: JSONObject): Boolean =
        routeTargets(config).any { route ->
            route == "0.0.0.0/0" || route == "::/0"
        }

    fun routeTargets(config: JSONObject): List<String> {
        val routes = config.optJSONArray("routeTargets") ?: return emptyList()
        return buildList {
            for (index in 0 until routes.length()) {
                routes.optString(index).trim().takeIf(String::isNotEmpty)?.let(::add)
            }
        }
    }

    fun supportsAlwaysOnVpn(configJson: String): Boolean =
        runCatching {
            supportsAlwaysOn(routeTargets(JSONObject(configJson)))
        }.getOrDefault(false)

    /**
     * The routes that decide where packets go. A route inside another route
     * of the list changes nothing, so a member address under the default
     * route of a selected exit is left out.
     */
    fun effectiveRoutes(routeTargets: List<String>): Set<String> {
        val prefixes = routeTargets.distinct().associateWith(::parsePrefix)
        return prefixes.filterTo(linkedMapOf()) { (route, prefix) ->
            prefix == null ||
                prefixes.none { (other, wider) ->
                    other != route && wider != null && covers(wider, prefix)
                }
        }.keys
    }

    @TargetApi(Build.VERSION_CODES.TIRAMISU)
    fun parseIpPrefix(value: String): IpPrefix? =
        parsePrefix(value)?.let { (address, length) -> IpPrefix(address, length) }

    private fun parsePrefix(value: String): Pair<InetAddress, Int>? {
        val parts = value.trim().split("/", limit = 2)
        val address = parts.firstOrNull()?.takeIf(String::isNotBlank) ?: return null
        val resolved = runCatching { InetAddress.getByName(address) }.getOrNull() ?: return null
        val maximumPrefix = resolved.address.size * 8
        val prefix = parts.getOrNull(1)?.toIntOrNull() ?: maximumPrefix
        if (prefix !in 0..maximumPrefix) {
            return null
        }
        return resolved to prefix
    }

    private fun covers(wider: Pair<InetAddress, Int>, route: Pair<InetAddress, Int>): Boolean {
        val widerBytes = wider.first.address
        val routeBytes = route.first.address
        if (widerBytes.size != routeBytes.size || wider.second >= route.second) {
            return false
        }
        return (0 until wider.second).all { bit ->
            val mask = 0x80 shr (bit % 8)
            (widerBytes[bit / 8].toInt() and mask) == (routeBytes[bit / 8].toInt() and mask)
        }
    }

    fun preferredWireGuardUnderlay(candidates: List<UnderlayNetworkCandidate>): Long? {
        val usable = candidates.filter(UnderlayNetworkCandidate::usable)
        val validated = usable.filter(UnderlayNetworkCandidate::validated)
        val eligible = validated.ifEmpty {
            usable
        }
        return eligible.minWithOrNull(
            compareBy<UnderlayNetworkCandidate>(
                { if (it.active) 0 else 1 },
                UnderlayNetworkCandidate::transportPreference,
                UnderlayNetworkCandidate::handle,
            ),
        )?.handle
    }

    fun nextUnderlayRefreshDelay(
        pendingDelay: Long?,
        immediate: Boolean,
        delayedRefresh: Long,
    ): Long? = (if (immediate) 0L else delayedRefresh)
        .takeIf { pendingDelay == null || it < pendingDelay }
}
