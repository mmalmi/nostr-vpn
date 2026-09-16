package org.nostrvpn.app

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

internal fun formatDecimalBytes(bytes: Long): String {
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
