package to.iris.nvpn.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import to.iris.nvpn.MainActivity
import to.iris.nvpn.R

class NostrVpnService : VpnService() {
  companion object {
    const val ACTION_START = "to.iris.nvpn.vpn.START"
    const val ACTION_STOP = "to.iris.nvpn.vpn.STOP"

    private const val CHANNEL_ID = "nostr-vpn-session"
    private const val NOTIFICATION_ID = 77
    private const val TAG = "NostrVpnService"
  }

  private var tunnelInterface: ParcelFileDescriptor? = null

  override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
    Log.i(TAG, "onStartCommand action=${intent?.action} startId=$startId")
    when (intent?.action) {
      ACTION_STOP -> {
        stopTunnel()
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
      }
      else -> {
        startForeground(NOTIFICATION_ID, buildNotification("Starting tunnel"))
        startTunnel()
      }
    }
    return START_NOT_STICKY
  }

  override fun onRevoke() {
    Log.w(TAG, "VPN permission revoked")
    NostrVpnState.lastError = "VPN permission revoked"
    stopTunnel()
    stopForeground(STOP_FOREGROUND_REMOVE)
    stopSelf()
    super.onRevoke()
  }

  override fun onDestroy() {
    Log.i(TAG, "onDestroy")
    stopTunnel()
    stopForeground(STOP_FOREGROUND_REMOVE)
    super.onDestroy()
  }

  private fun startTunnel() {
    val config = NostrVpnState.takePendingConfig()
    if (config == null) {
      Log.e(TAG, "Missing tunnel configuration")
      NostrVpnState.failStart("Missing tunnel configuration")
      stopForeground(STOP_FOREGROUND_REMOVE)
      stopSelf()
      return
    }

    stopTunnel()

    try {
      Log.i(
        TAG,
        "Establishing tunnel session=${config.sessionName} local=${config.localAddresses.joinToString()} routes=${config.routes.joinToString()} dns=${config.dnsServers.joinToString()}",
      )
      val builder = Builder().setSession(config.sessionName).setMtu(config.mtu)
      for (address in config.localAddresses) {
        val parsed = parseCidr(address)
        builder.addAddress(parsed.host, parsed.prefixLength)
      }
      for (route in config.routes) {
        val parsed = parseCidr(route)
        builder.addRoute(parsed.host, parsed.prefixLength)
      }
      for (dnsServer in config.dnsServers) {
        builder.addDnsServer(dnsServer)
      }
      for (searchDomain in config.searchDomains) {
        builder.addSearchDomain(searchDomain)
      }
      try {
        builder.addDisallowedApplication(packageName)
      } catch (_: Exception) {
      }

      val established = builder.establish()
        ?: throw IllegalStateException("Android refused to establish VPN interface")
      val retained = ParcelFileDescriptor.dup(established.fileDescriptor)
      val tunFd = established.detachFd()
      tunnelInterface = retained
      Log.i(TAG, "Tunnel established tunFd=$tunFd")

      NostrVpnState.service = this
      NostrVpnState.active = true
      NostrVpnState.lastError = null
      NostrVpnState.completeStart(tunFd)
      startForeground(NOTIFICATION_ID, buildNotification("Tunnel active"))
    } catch (error: Exception) {
      val message = error.message ?: "Failed to establish Android VPN"
      Log.e(TAG, "Failed to establish VPN tunnel", error)
      NostrVpnState.failStart(message)
      stopTunnel()
      stopForeground(STOP_FOREGROUND_REMOVE)
      stopSelf()
    }
  }

  private fun stopTunnel() {
    Log.i(TAG, "Stopping tunnel")
    try {
      tunnelInterface?.close()
    } catch (_: Exception) {
    }
    tunnelInterface = null

    if (NostrVpnState.service === this) {
      NostrVpnState.clear(NostrVpnState.lastError)
    }
  }

  private fun buildNotification(status: String): Notification {
    ensureNotificationChannel()

    val launchIntent =
      Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP)
    val pendingIntent =
      PendingIntent.getActivity(
        this,
        0,
        launchIntent,
        PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
      )

    return NotificationCompat.Builder(this, CHANNEL_ID)
      .setSmallIcon(R.mipmap.ic_launcher)
      .setContentTitle("Nostr VPN")
      .setContentText(status)
      .setCategory(NotificationCompat.CATEGORY_SERVICE)
      .setOngoing(true)
      .setContentIntent(pendingIntent)
      .build()
  }

  private fun ensureNotificationChannel() {
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
      return
    }

    val manager = getSystemService(NotificationManager::class.java) ?: return
    if (manager.getNotificationChannel(CHANNEL_ID) != null) {
      return
    }

    val channel =
      NotificationChannel(
        CHANNEL_ID,
        "Nostr VPN",
        NotificationManager.IMPORTANCE_LOW,
      )
    channel.description = "Foreground VPN session status"
    manager.createNotificationChannel(channel)
  }

  private data class ParsedCidr(val host: String, val prefixLength: Int)

  private fun parseCidr(value: String): ParsedCidr {
    val parts = value.trim().split("/", limit = 2)
    val host = parts[0].trim()
    require(host.isNotEmpty()) { "Invalid CIDR: $value" }

    val prefixLength =
      if (parts.size == 2) {
        parts[1].trim().toInt()
      } else if (host.contains(":")) {
        128
      } else {
        32
      }

    return ParsedCidr(host, prefixLength)
  }
}
