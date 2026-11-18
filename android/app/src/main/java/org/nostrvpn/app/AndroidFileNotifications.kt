package org.nostrvpn.app

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.FileObserver
import android.os.Handler
import android.os.HandlerThread
import org.json.JSONArray
import java.io.File
import java.io.ByteArrayOutputStream

/** Observes the daemon's atomic state projection, including while the activity is closed. */
internal class AndroidFileNotifications(private val context: Context) {
    private val thread = HandlerThread("nvpn-file-notifications")
    private lateinit var handler: Handler
    private val statuses = mutableMapOf<String, String>()
    private val notified = mutableMapOf<String, String>()
    private val completedArrivals = mutableSetOf<String>()
    private var directoryObserver: FileObserver? = null
    private var rootObserver: FileObserver? = null
    @Volatile private var stopped = false

    fun start() {
        thread.start()
        handler = Handler(thread.looper)
        active = this
        val root = appCoreDataDir(context)
        root.mkdirs()
        rootObserver = observer(root) { if (it == "file-transfers") handler.post { watchDirectory() } }.also { it.startWatching() }
        handler.post { watchDirectory() }
    }

    fun stop() {
        stopped = true
        if (active === this) active = null
        rootObserver?.stopWatching()
        directoryObserver?.stopWatching()
        handler.removeCallbacksAndMessages(null)
        thread.quitSafely()
    }

    @Suppress("DEPRECATION")
    private fun observer(directory: File, changed: (String?) -> Unit): FileObserver =
        object : FileObserver(directory.absolutePath, CREATE or MOVED_TO or CLOSE_WRITE) {
            override fun onEvent(event: Int, path: String?) { if (!stopped) changed(path) }
        }

    private fun watchDirectory() {
        if (stopped || directoryObserver != null) return
        val directory = appCoreDataDir(context).resolve("file-transfers")
        if (!directory.isDirectory) return
        directoryObserver = observer(directory) { if (it == "state.json") handler.post { refresh() } }.also { it.startWatching() }
        refresh()
    }

    private fun refresh() {
        if (stopped) return
        val state = appCoreDataDir(context).resolve("file-transfers/state.json")
        val rows = runCatching {
            state.inputStream().use { input ->
                val buffer = ByteArray(8192)
                val bytes = ByteArrayOutputStream(state.length().coerceIn(0, 8192).toInt())
                while (true) {
                    val read = input.read(buffer)
                    if (read < 0) break
                    require(bytes.size() + read <= 4 * 1024 * 1024)
                    bytes.write(buffer, 0, read)
                }
                JSONArray(bytes.toString("UTF-8"))
            }
        }.getOrNull() ?: return
        val manager = context.getSystemService(NotificationManager::class.java)
        val allowed = manager.areNotificationsEnabled() && (Build.VERSION.SDK_INT < 33 || context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED)
        if (allowed) manager.createNotificationChannel(NotificationChannel(CHANNEL, "Files", NotificationManager.IMPORTANCE_DEFAULT))
        val live = mutableSetOf<String>()
        for (index in 0 until rows.length()) {
            val row = rows.optJSONObject(index) ?: continue
            if (row.optBoolean("isSender")) continue
            val id = row.optString("id").takeIf { it.isNotBlank() } ?: continue
            live.add(id)
            val status = row.optString("status")
            val previous = statuses.put(id, status)
            if (status == "completed" && previous != null && previous != "completed") completedArrivals.add(id)
            if (status != "offered" && !(status == "completed" && id in completedArrivals)) {
                if (status != previous) manager.cancel(id, 7100)
                continue
            }
            if (!allowed || notified[id] == status) continue
            val files = row.optJSONArray("files") ?: JSONArray()
            val name = files.optJSONObject(0)?.optString("name").orEmpty()
            val summary = name + (if (files.length() > 1) " + ${files.length() - 1} files" else "") + " · ${formatBytes(row.optLong("totalBytes"))}"
            val intent = Intent(context, MainActivity::class.java)
                .setAction("${context.packageName}.OPEN_FILES")
                .setData(Uri.Builder().scheme("nvpn-files").authority("transfer").appendPath(id).build())
                .putExtra(EXTRA_TRANSFER_ID, id)
                .addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP)
            val pending = PendingIntent.getActivity(context, 7100, intent, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
            val peer = row.optString("peerName").ifBlank { "a device" }
            val notification = Notification.Builder(context, CHANNEL)
                .setSmallIcon(R.drawable.ic_launcher_monochrome)
                .setContentTitle(if (status == "offered") "Files from $peer" else "Files received")
                .setContentText(summary)
                .setStyle(Notification.BigTextStyle().bigText("$summary\n${if (status == "offered") "Open to accept or decline." else "Open to save or share."}"))
                .setContentIntent(pending).setAutoCancel(true).setOnlyAlertOnce(true)
                .setVisibility(Notification.VISIBILITY_PRIVATE)
                .build()
            runCatching { manager.notify(id, 7100, notification) }.onSuccess { notified[id] = status }
        }
        statuses.keys.retainAll(live)
        notified.keys.retainAll(live)
        completedArrivals.retainAll(live)
    }

    companion object {
        @Volatile private var active: AndroidFileNotifications? = null
        fun refreshActive() { active?.let { watcher -> if (!watcher.stopped) watcher.handler.post { watcher.refresh() } } }
        const val EXTRA_TRANSFER_ID = "open_file_transfer"
        private const val CHANNEL = "files"
    }
}
