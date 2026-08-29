package org.nostrvpn.app.vpn

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.drawable.Icon
import android.os.Build
import android.util.Log
import org.nostrvpn.app.MainActivity
import org.nostrvpn.app.R

internal const val VPN_NOTIFICATION_ID = 7001

internal object AndroidVpnNotifications {
    private const val NOTIFICATION_CHANNEL_ID = "vpn"

    fun configureIntent(context: Context): PendingIntent =
        PendingIntent.getActivity(
            context,
            2,
            Intent(context, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )

    fun createChannel(context: Context) {
        context.getSystemService(NotificationManager::class.java).createNotificationChannel(
            NotificationChannel(
                NOTIFICATION_CHANNEL_ID,
                context.getString(R.string.app_name),
                NotificationManager.IMPORTANCE_LOW,
            ).apply {
                setShowBadge(false)
            },
        )
    }

    fun tunnel(context: Context): Notification {
        val openAppIntent = context.packageManager.getLaunchIntentForPackage(context.packageName)
            ?: Intent(context, MainActivity::class.java)
        val openApp = PendingIntent.getActivity(
            context,
            0,
            openAppIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val disconnect = PendingIntent.getService(
            context,
            1,
            Intent(context, NostrVpnService::class.java)
                .setAction(NostrVpnService.ACTION_DISCONNECT),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        return Notification.Builder(context, NOTIFICATION_CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_launcher_monochrome)
            .setContentTitle(context.getString(R.string.app_name))
            .setContentText(context.getString(R.string.vpn_notification_connected))
            .setContentIntent(openApp)
            .setOngoing(true)
            .setCategory(Notification.CATEGORY_SERVICE)
            .addAction(
                Notification.Action.Builder(
                    Icon.createWithResource(context, R.drawable.ic_launcher_monochrome),
                    context.getString(R.string.vpn_notification_disconnect),
                    disconnect,
                ).build(),
            )
            .build()
    }

    fun publishTunnel(context: Context) {
        if (!notificationsAllowed(context)) return
        createChannel(context)
        runCatching {
            context.getSystemService(NotificationManager::class.java).notify(
                VPN_NOTIFICATION_ID,
                tunnel(context),
            )
        }.onFailure { error ->
            Log.w("NostrVpnService", "Failed to publish VPN notification", error)
        }
    }

    fun publishAlwaysOnSplitUnsupported(context: Context) {
        if (!notificationsAllowed(context)) return
        createChannel(context)
        val openSettings = PendingIntent.getActivity(
            context,
            3,
            Intent(android.provider.Settings.ACTION_VPN_SETTINGS),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        runCatching {
            context.getSystemService(NotificationManager::class.java).notify(
                VPN_NOTIFICATION_ID,
                Notification.Builder(context, NOTIFICATION_CHANNEL_ID)
                    .setSmallIcon(R.drawable.ic_launcher_monochrome)
                    .setContentTitle(context.getString(R.string.vpn_always_on_split_title))
                    .setContentText(context.getString(R.string.vpn_always_on_split_message))
                    .setContentIntent(openSettings)
                    .setAutoCancel(true)
                    .setCategory(Notification.CATEGORY_ERROR)
                    .build(),
            )
        }.onFailure { error ->
            Log.w("NostrVpnService", "Failed to publish Always-on VPN warning", error)
        }
    }

    fun clear(context: Context) {
        runCatching {
            context.getSystemService(NotificationManager::class.java)
                .cancel(VPN_NOTIFICATION_ID)
        }
    }

    private fun notificationsAllowed(context: Context): Boolean =
        Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU ||
            context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) ==
            PackageManager.PERMISSION_GRANTED
}
