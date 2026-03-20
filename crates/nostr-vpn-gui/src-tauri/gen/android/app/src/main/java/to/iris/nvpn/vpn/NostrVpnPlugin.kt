package to.iris.nvpn.vpn

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.util.Log
import androidx.activity.result.ActivityResult
import androidx.core.content.ContextCompat
import app.tauri.annotation.ActivityCallback
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit

@InvokeArg
class StartArgs {
  lateinit var sessionName: String
  var localAddresses: Array<String> = emptyArray()
  var routes: Array<String> = emptyArray()
  var dnsServers: Array<String> = emptyArray()
  var searchDomains: Array<String> = emptyArray()
  var mtu: Int = 1280
}

data class TunnelConfig(
  val sessionName: String,
  val localAddresses: List<String>,
  val routes: List<String>,
  val dnsServers: List<String>,
  val searchDomains: List<String>,
  val mtu: Int,
)

private const val TAG = "NostrVpnPlugin"

object NostrVpnState {
  @Volatile var service: NostrVpnService? = null
  @Volatile var active: Boolean = false
  @Volatile var lastError: String? = null

  private var pendingConfig: TunnelConfig? = null
  private var startFuture: CompletableFuture<Int>? = null

  @Synchronized
  fun beginStart(config: TunnelConfig): CompletableFuture<Int> {
    pendingConfig = config
    active = false
    lastError = null
    return CompletableFuture<Int>().also { startFuture = it }
  }

  @Synchronized
  fun takePendingConfig(): TunnelConfig? {
    val config = pendingConfig
    pendingConfig = null
    return config
  }

  @Synchronized
  fun completeStart(tunFd: Int) {
    active = true
    lastError = null
    startFuture?.complete(tunFd)
    startFuture = null
  }

  @Synchronized
  fun failStart(message: String) {
    active = false
    lastError = message
    startFuture?.completeExceptionally(IllegalStateException(message))
    startFuture = null
  }

  @Synchronized
  fun clear(error: String? = null) {
    service = null
    pendingConfig = null
    active = false
    lastError = error
    startFuture = null
  }
}

@TauriPlugin
class NostrVpnPlugin(private val activity: Activity) : Plugin(activity) {
  @Command
  fun prepare(invoke: Invoke) {
    val intent = VpnService.prepare(activity)
    if (intent == null) {
      Log.i(TAG, "VPN permission already granted")
      val result = JSObject()
      result.put("prepared", true)
      invoke.resolve(result)
      return
    }

    startActivityForResult(invoke, intent, "prepareResult")
  }

  @ActivityCallback
  fun prepareResult(invoke: Invoke, result: ActivityResult) {
    if (result.resultCode == Activity.RESULT_OK) {
      Log.i(TAG, "VPN permission granted")
      val response = JSObject()
      response.put("prepared", true)
      invoke.resolve(response)
    } else {
      Log.w(TAG, "VPN permission denied")
      invoke.reject("VPN permission denied")
    }
  }

  @Command
  fun start(invoke: Invoke) {
    try {
      val args = invoke.parseArgs(StartArgs::class.java)
      Log.i(
        TAG,
        "start requested session=${args.sessionName} local=${args.localAddresses.joinToString()} routes=${args.routes.joinToString()} mtu=${args.mtu}",
      )
      val future =
        NostrVpnState.beginStart(
          TunnelConfig(
            sessionName = args.sessionName,
            localAddresses = args.localAddresses.toList(),
            routes = args.routes.toList(),
            dnsServers = args.dnsServers.toList(),
            searchDomains = args.searchDomains.toList(),
            mtu = args.mtu,
          )
        )

      val intent = Intent(activity, NostrVpnService::class.java).setAction(NostrVpnService.ACTION_START)
      ContextCompat.startForegroundService(activity, intent)

      Thread {
            try {
              val tunFd = future.get(10, TimeUnit.SECONDS)
              Log.i(TAG, "VPN service established tunFd=$tunFd")
              activity.runOnUiThread {
                val result = JSObject()
                result.put("tunFd", tunFd)
                result.put("active", true)
                invoke.resolve(result)
              }
            } catch (error: Exception) {
              val message = error.message ?: "Failed to establish Android VPN service"
              Log.e(TAG, "VPN service start failed", error)
              activity.runOnUiThread { invoke.reject(message) }
            }
          }
          .start()
    } catch (error: Exception) {
      Log.e(TAG, "Failed to parse Android VPN start request", error)
      invoke.reject(error.message ?: "Failed to start Android VPN")
    }
  }

  @Command
  fun stop(invoke: Invoke) {
    Log.i(TAG, "stop requested")
    val intent = Intent(activity, NostrVpnService::class.java).setAction(NostrVpnService.ACTION_STOP)
    activity.startService(intent)
    invoke.resolve()
  }

  @Command
  fun status(invoke: Invoke) {
    Log.i(TAG, "status requested active=${NostrVpnState.active} lastError=${NostrVpnState.lastError}")
    val result = JSObject()
    result.put("prepared", VpnService.prepare(activity) == null)
    result.put("active", NostrVpnState.active)
    NostrVpnState.lastError?.let { result.put("error", it) }
    invoke.resolve(result)
  }
}
