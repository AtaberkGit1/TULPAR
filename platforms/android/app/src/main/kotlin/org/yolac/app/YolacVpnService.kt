package org.yolac.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.IpPrefix
import android.net.Network
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.service.quicksettings.TileService
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import java.net.InetAddress

class YolacVpnService : VpnService() {

    companion object {
        const val ACTION_START = "org.yolac.app.START"
        const val ACTION_STOP = "org.yolac.app.STOP"
        private const val CHANNEL_ID = "yolac_vpn_channel"
        private const val NOTIF_ID = 1001

        private val _stateFlow = MutableStateFlow(YolacNative.STATE_INACTIVE)
        val stateFlow: StateFlow<Int> = _stateFlow
    }

    private var tunInterface: ParcelFileDescriptor? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopProtection()
                return START_NOT_STICKY
            }
            // Supports both explicit user start and Android Always-On VPN system start (VpnService.SERVICE_INTERFACE / null)
            ACTION_START, SERVICE_INTERFACE, null -> {
                startProtection()
            }
        }
        return START_STICKY
    }

    private fun updateState(newState: Int) {
        _stateFlow.value = newState
        try {
            TileService.requestListeningState(
                this,
                ComponentName(this, TulparTileService::class.java),
            )
        } catch (_: Exception) {
        }
    }

    private fun establishTun(includeIpv6: Boolean): ParcelFileDescriptor? {
        return try {
            val builder = Builder()
                .setSession("TULPAR")
                .setMtu(1500)
                .addAddress("10.219.0.1", 30)
                .addRoute("0.0.0.0", 0)
                .addDnsServer("10.219.0.2")

            if (includeIpv6) {
                builder
                    .addAddress("fd79:6f6c:6163::1", 126)
                    .addRoute("::", 0)
                    .addDnsServer("fd79:6f6c:6163::2")
            }

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                builder.setMetered(false)
            }

            // Exclude RFC1918/link-local LAN subnets on API 33+ for seamless Captive Portal & local router access
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                try {
                    builder.excludeRoute(IpPrefix(InetAddress.getByName("192.168.0.0"), 16))
                    builder.excludeRoute(IpPrefix(InetAddress.getByName("172.16.0.0"), 12))
                    builder.excludeRoute(IpPrefix(InetAddress.getByName("169.254.0.0"), 16))
                } catch (_: Exception) {
                }
            }

            try {
                builder.addDisallowedApplication(packageName)
            } catch (_: Exception) {
            }

            builder.establish()
        } catch (_: Throwable) {
            null
        }
    }

    private fun startProtection() {
        if (tunInterface != null) return
        updateState(YolacNative.STATE_ACTIVATING)
        ensureNotificationChannel()
        try {
            val notif = buildNotification()
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                startForeground(NOTIF_ID, notif, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
            } else {
                startForeground(NOTIF_ID, notif)
            }
        } catch (_: Throwable) {
            YolacNative.nativeReportPlatformError(YolacNative.ERROR_PERMISSION_DENIED)
            updateState(YolacNative.STATE_ERROR)
            stopSelf()
            return
        }

        // Try dual-stack IPv4+IPv6 first; fall back seamlessly to IPv4-only + IPv6 leak blocking if OEM kernel lacks IPv6 TUN
        var usedIpv6 = true
        var pfd = establishTun(includeIpv6 = true)
        if (pfd == null) {
            usedIpv6 = false
            pfd = establishTun(includeIpv6 = false)
        }
        if (pfd == null) {
            YolacNative.nativeReportPlatformError(YolacNative.ERROR_TUN_SETUP_FAILED)
            updateState(YolacNative.STATE_ERROR)
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }

        tunInterface = pfd
        // Hand detached FD ownership cleanly to Rust core
        val detachedFd = pfd.detachFd()
        val ok = YolacNative.nativeStartTun(this, detachedFd, !usedIpv6)
        if (!ok) {
            YolacNative.nativeReportPlatformError(YolacNative.ERROR_TUN_SETUP_FAILED)
            updateState(YolacNative.STATE_ERROR)
            tunInterface = null
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }

        registerNetworkObserver()
        updateState(YolacNative.STATE_ACTIVE)
    }

    private fun stopProtection() {
        updateState(YolacNative.STATE_DEACTIVATING)
        unregisterNetworkObserver()
        YolacNative.nativeStop()
        tunInterface = null
        updateState(YolacNative.STATE_INACTIVE)
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun registerNetworkObserver() {
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                YolacNative.nativeNotifyNetworkChange()
            }

            override fun onLost(network: Network) {
                YolacNative.nativeNotifyNetworkChange()
            }
        }
        try {
            cm.registerDefaultNetworkCallback(cb)
            networkCallback = cb
        } catch (_: Exception) {
        }
    }

    private fun unregisterNetworkObserver() {
        val cb = networkCallback ?: return
        networkCallback = null
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return
        try {
            cm.unregisterNetworkCallback(cb)
        } catch (_: Exception) {
        }
    }

    override fun onRevoke() {
        stopProtection()
        super.onRevoke()
    }

    override fun onDestroy() {
        unregisterNetworkObserver()
        YolacNative.nativeStop()
        updateState(YolacNative.STATE_INACTIVE)
        super.onDestroy()
    }

    private fun ensureNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val mgr = getSystemService(NotificationManager::class.java) ?: return
            val channel = NotificationChannel(
                CHANNEL_ID,
                getString(R.string.notif_channel_name),
                NotificationManager.IMPORTANCE_LOW,
            ).apply {
                setShowBadge(false)
            }
            mgr.createNotificationChannel(channel)
        }
    }

    private fun buildNotification(): Notification {
        val openIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, CHANNEL_ID)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
        }
        return builder
            .setContentTitle(getString(R.string.notif_active_title))
            .setContentText(getString(R.string.notif_active_body))
            .setSmallIcon(R.drawable.ic_tulpar_status)
            .setOngoing(true)
            .setContentIntent(openIntent)
            .build()
    }
}
