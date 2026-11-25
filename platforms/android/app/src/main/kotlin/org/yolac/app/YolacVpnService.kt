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
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.service.quicksettings.TileService
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import java.net.Inet6Address
import java.net.InetAddress
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

class YolacVpnService : VpnService() {

    companion object {
        const val ACTION_START = "org.yolac.app.START"
        const val ACTION_STOP = "org.yolac.app.STOP"
        const val ACTION_REAPPLY = "org.yolac.app.REAPPLY"
        const val PREFS_NAME = "yolac_prefs"
        const val KEY_EXCLUDED_PACKAGES = "excluded_packages"
        const val KEY_DNS_PROFILE = "dns_profile"
        const val KEY_DNS_LABEL = "dns_label"
        const val KEY_QUIC_POLICY = "quic_policy"
        const val KEY_RULES_ALLOW = "rules_allow"
        const val KEY_RULES_BLOCK = "rules_block"
        const val KEY_RULES_EXCLUDE = "rules_exclude"

        fun applySavedUserSettings(context: Context) {
            val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            val dnsSpec = prefs.getString(KEY_DNS_PROFILE, "auto") ?: "auto"
            try {
                YolacNative.nativeSetDnsProfileJson(dnsSpec)
            } catch (_: Throwable) {
            }
            val quicMode = prefs.getInt(KEY_QUIC_POLICY, 1)
            try {
                YolacNative.nativeSetQuicPolicy(quicMode)
            } catch (_: Throwable) {
            }
            val allowRaw = prefs.getString(KEY_RULES_ALLOW, "") ?: ""
            val blockRaw = prefs.getString(KEY_RULES_BLOCK, "") ?: ""
            val excludeRaw = prefs.getString(KEY_RULES_EXCLUDE, "") ?: ""
            val rulesJson = HealthParser.buildUserRulesJson(allowRaw, blockRaw, excludeRaw)
            try {
                YolacNative.nativeSetUserRulesJson(rulesJson)
            } catch (_: Throwable) {
            }
        }
        private const val CHANNEL_ID = "yolac_vpn_channel"
        private const val NOTIF_ID = 1001

        private val _stateFlow = MutableStateFlow(YolacNative.STATE_INACTIVE)
        val stateFlow: StateFlow<Int> = _stateFlow

        private val _privateDnsWarning = MutableStateFlow(false)
        val privateDnsWarning: StateFlow<Boolean> = _privateDnsWarning

        fun syncStateFromNative() {
            try {
                val nativeState = YolacNative.nativeGetState()
                if (_stateFlow.value != YolacNative.STATE_ACTIVATING &&
                    _stateFlow.value != YolacNative.STATE_DEACTIVATING
                ) {
                    _stateFlow.value = nativeState
                }
            } catch (_: Throwable) {
            }
        }

        // Exact disjoint public IPv4 CIDR ranges for Android 8–12 (API 26–32, before excludeRoute)
        // Excludes: 0.0.0.0/8, 10.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12,
        //           192.168.0.0/16, and 224.0.0.0/3 (multicast + broadcast) while keeping LAN & mDNS native!
        private val PUBLIC_IPV4_COMPLEMENT_ROUTES: List<Pair<String, Int>> = listOf(
            "1.0.0.0" to 8,
            "2.0.0.0" to 7,
            "4.0.0.0" to 6,
            "8.0.0.0" to 7,
            "11.0.0.0" to 8,
            "12.0.0.0" to 6,
            "16.0.0.0" to 4,
            "32.0.0.0" to 3,
            "64.0.0.0" to 2,
            "128.0.0.0" to 3,
            "160.0.0.0" to 5,
            "168.0.0.0" to 8,
            "169.0.0.0" to 9,
            "169.128.0.0" to 10,
            "169.192.0.0" to 11,
            "169.224.0.0" to 12,
            "169.240.0.0" to 13,
            "169.248.0.0" to 14,
            "169.252.0.0" to 15,
            "169.255.0.0" to 16,
            "170.0.0.0" to 7,
            "172.0.0.0" to 12,
            "172.32.0.0" to 11,
            "172.64.0.0" to 10,
            "172.128.0.0" to 9,
            "173.0.0.0" to 8,
            "174.0.0.0" to 7,
            "176.0.0.0" to 4,
            "192.0.0.0" to 9,
            "192.128.0.0" to 11,
            "192.160.0.0" to 13,
            "192.169.0.0" to 16,
            "192.170.0.0" to 15,
            "192.172.0.0" to 14,
            "192.176.0.0" to 12,
            "192.192.0.0" to 10,
            "193.0.0.0" to 8,
            "194.0.0.0" to 7,
            "196.0.0.0" to 6,
            "200.0.0.0" to 5,
            "208.0.0.0" to 4,
            // Always route TULPAR's virtual DNS endpoint into TUN
            "10.219.0.2" to 32,
        )
    }

    private val worker = Executors.newSingleThreadExecutor()
    private val failedWithError = AtomicBoolean(false)
    private val serviceGen = AtomicLong(0L)
    @Volatile
    private var currentTunHasIpv6: Boolean = false
    @Volatile
    private var isRunningProtection: Boolean = false
    @Volatile
    private var observerRegisteredAtMs: Long = 0L

    private var networkCallback: ConnectivityManager.NetworkCallback? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                val gen = serviceGen.incrementAndGet()
                stopProtectionAsync(gen)
                return START_NOT_STICKY
            }
            ACTION_REAPPLY -> {
                val gen = serviceGen.get()
                if (isRunningProtection) {
                    worker.execute {
                        if (serviceGen.get() == gen) {
                            reapplyTunLocked()
                        }
                    }
                }
                return START_STICKY
            }
            // Supports both explicit user start and Android Always-On VPN system start
            ACTION_START, SERVICE_INTERFACE, null -> {
                val gen = serviceGen.incrementAndGet()
                failedWithError.set(false)
                updateState(YolacNative.STATE_ACTIVATING)
                ensureNotificationChannel()
                // Must call startForeground synchronously on Main Thread before offloading heavy TUN/Rust init
                try {
                    val notif = buildNotification()
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                        startForeground(NOTIF_ID, notif, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
                    } else {
                        startForeground(NOTIF_ID, notif)
                    }
                } catch (_: Throwable) {
                    failedWithError.set(true)
                    YolacNative.nativeReportPlatformError(YolacNative.ERROR_PERMISSION_DENIED)
                    updateState(YolacNative.STATE_ERROR)
                    stopSelf()
                    return START_NOT_STICKY
                }
                worker.execute { startProtectionLocked(gen) }
            }
        }
        return START_STICKY
    }

    /**
     * Called directly from Rust JNI (`jni_bridge.rs`) whenever the active TUN engine transitions
     * state (guards against unexpected TUN EOF/error leaving a stuck foreground notification).
     */
    fun onNativeStateChanged(nativeState: Int) {
        if (nativeState == YolacNative.STATE_ERROR) {
            failedWithError.set(true)
            isRunningProtection = false
            updateState(YolacNative.STATE_ERROR)
            unregisterNetworkObserver()
            try {
                stopForeground(STOP_FOREGROUND_REMOVE)
            } catch (_: Throwable) {
            }
            stopSelf()
        } else if (nativeState == YolacNative.STATE_INACTIVE && isRunningProtection) {
            isRunningProtection = false
            updateState(YolacNative.STATE_INACTIVE)
            unregisterNetworkObserver()
            try {
                stopForeground(STOP_FOREGROUND_REMOVE)
            } catch (_: Throwable) {
            }
            stopSelf()
        } else if (nativeState == YolacNative.STATE_ACTIVE && !failedWithError.get()) {
            updateState(nativeState)
        }
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

    private data class TunEstablishResult(
        val pfd: ParcelFileDescriptor,
        val selfAppExcluded: Boolean,
    )

    private fun establishTun(includeIpv6: Boolean): TunEstablishResult? {
        return try {
            val builder = Builder()
                .setSession("TULPAR")
                .setMtu(1500)
                .addAddress("10.219.0.1", 30)
                .addDnsServer("10.219.0.2")

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                builder.addRoute("0.0.0.0", 0)
                // Exclude LAN, multicast, broadcast & non-10.219 RFC1918 subnets so local router/Chromecast work
                val exclusions = listOf(
                    "10.0.0.0" to 9,
                    "10.128.0.0" to 10,
                    "10.192.0.0" to 12,
                    "10.208.0.0" to 13,
                    "10.216.0.0" to 15,
                    "10.218.0.0" to 16,
                    "10.220.0.0" to 14,
                    "10.224.0.0" to 11,
                    "172.16.0.0" to 12,
                    "192.168.0.0" to 16,
                    "169.254.0.0" to 16,
                    "224.0.0.0" to 4,
                    "255.255.255.255" to 32,
                )
                for ((ip, prefix) in exclusions) {
                    try {
                        builder.excludeRoute(IpPrefix(InetAddress.getByName(ip), prefix))
                    } catch (_: Exception) {
                    }
                }
            } else {
                // Android 8–12: disjoint public CIDR complement keeps LAN/router/mDNS out of TUN!
                for ((ip, prefix) in PUBLIC_IPV4_COMPLEMENT_ROUTES) {
                    builder.addRoute(ip, prefix)
                }
            }

            if (includeIpv6) {
                builder
                    .addAddress("fd79:6f6c:6163::1", 126)
                    .addRoute("::", 0)
                    .addDnsServer("fd79:6f6c:6163::2")
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    try {
                        builder.excludeRoute(IpPrefix(InetAddress.getByName("fe80::"), 10))
                        builder.excludeRoute(IpPrefix(InetAddress.getByName("ff00::"), 8))
                    } catch (_: Exception) {
                    }
                }
            }

            // Inherit true Wi-Fi / 4G / 5G meteredness instead of falsely reporting unmetered
            try {
                setUnderlyingNetworks(null)
            } catch (_: Exception) {
            }

            // Apply user-configured Per-App Split-Tunneling exclusions (banks, e-Devlet, games)
            val excludedPkgs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .getStringSet(KEY_EXCLUDED_PACKAGES, emptySet())
                ?: emptySet()
            for (pkg in excludedPkgs) {
                if (pkg.isNotBlank() && pkg != packageName) {
                    try {
                        builder.addDisallowedApplication(pkg)
                    } catch (_: Exception) {
                    }
                }
            }

            val selfExcluded = try {
                builder.addDisallowedApplication(packageName)
                true
            } catch (_: Exception) {
                false
            }

            val pfd = builder.establish() ?: return null
            TunEstablishResult(pfd = pfd, selfAppExcluded = selfExcluded)
        } catch (_: Throwable) {
            null
        }
    }

    private fun activeUnderlyingLinkProperties(): LinkProperties? {
        return try {
            val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return null
            val activeNet = cm.activeNetwork
            if (activeNet != null) {
                val caps = cm.getNetworkCapabilities(activeNet)
                if (caps != null && !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
                    return cm.getLinkProperties(activeNet)
                }
            }
            @Suppress("DEPRECATION")
            for (net in cm.allNetworks) {
                val caps = cm.getNetworkCapabilities(net) ?: continue
                if (caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                    !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
                ) {
                    return cm.getLinkProperties(net)
                }
            }
            null
        } catch (_: Throwable) {
            null
        }
    }

    private fun hasGlobalIpv6OnLink(lp: LinkProperties?): Boolean {
        if (lp == null) return false
        return try {
            val hasGlobalAddr = lp.linkAddresses.any { linkAddr ->
                val addr = linkAddr.address
                addr is Inet6Address &&
                    !addr.isLinkLocalAddress &&
                    !addr.isLoopbackAddress &&
                    !addr.isSiteLocalAddress &&
                    !addr.isMulticastAddress &&
                    !addr.isAnyLocalAddress &&
                    ((addr.address[0].toInt() and 0xFE) != 0xFC) // exclude ULA fc00::/7
            }
            val hasDefaultV6Route = lp.routes.any { route ->
                route.isDefaultRoute && route.destination.address is Inet6Address
            }
            hasGlobalAddr && hasDefaultV6Route
        } catch (_: Throwable) {
            false
        }
    }

    private fun inspectPrivateDnsStatus(lp: LinkProperties?) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            _privateDnsWarning.value = lp?.isPrivateDnsActive == true
        } else {
            _privateDnsWarning.value = false
        }
    }

    private fun startProtectionLocked(expectedGen: Long) {
        if (serviceGen.get() != expectedGen) return
        if (isRunningProtection && YolacNative.nativeGetState() == YolacNative.STATE_ACTIVE) {
            updateState(YolacNative.STATE_ACTIVE)
            return
        }

        val lp = activeUnderlyingLinkProperties()
        inspectPrivateDnsStatus(lp)
        var usedIpv6 = hasGlobalIpv6OnLink(lp)
        var established = establishTun(includeIpv6 = usedIpv6)
        if (established == null && usedIpv6) {
            usedIpv6 = false
            established = establishTun(includeIpv6 = false)
        }
        if (serviceGen.get() != expectedGen) {
            try {
                established?.pfd?.close()
            } catch (_: Throwable) {
            }
            return
        }
        if (established == null) {
            failedWithError.set(true)
            YolacNative.nativeReportPlatformError(YolacNative.ERROR_TUN_SETUP_FAILED)
            updateState(YolacNative.STATE_ERROR)
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }

        // Dynamically load an optional verified `.tulpar` strategy package (zero APK recompile)
        try {
            val activePkg = java.io.File(filesDir, "forge/active.tulpar")
            if (activePkg.isFile && activePkg.length() in 32L..(128L * 1024L)) {
                YolacNative.nativeLoadForgePackage(activePkg.readBytes())
            }
        } catch (_: Throwable) {
        }

        val isLockdown = Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q && isLockdownEnabled
        applySavedUserSettings(this)
        val detachedFd = established.pfd.detachFd()
        val ok = YolacNative.nativeStartTun(
            this,
            detachedFd,
            !usedIpv6,
            established.selfAppExcluded,
            isLockdown,
        )
        if (serviceGen.get() != expectedGen) {
            YolacNative.nativeStop()
            return
        }
        if (!ok) {
            failedWithError.set(true)
            YolacNative.nativeReportPlatformError(YolacNative.ERROR_TUN_SETUP_FAILED)
            updateState(YolacNative.STATE_ERROR)
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }

        currentTunHasIpv6 = usedIpv6
        isRunningProtection = true
        registerNetworkObserver()
        updateState(YolacNative.STATE_ACTIVE)
    }

    /**
     * Atomically swaps TUN interface (e.g. when roaming Wi-Fi IPv4-only <-> 4G/5G Dual-Stack IPv6,
     * or when the user updates Per-App Split-Tunneling exclusions in Settings).
     */
    private fun reapplyTunLocked(forcedIpv6: Boolean? = null) {
        if (!isRunningProtection) return
        val genAtStart = serviceGen.get()
        val lp = activeUnderlyingLinkProperties()
        inspectPrivateDnsStatus(lp)
        var targetIpv6 = forcedIpv6 ?: hasGlobalIpv6OnLink(lp)
        var established = establishTun(includeIpv6 = targetIpv6)
        if (established == null && targetIpv6) {
            targetIpv6 = false
            established = establishTun(includeIpv6 = false)
        }
        if (serviceGen.get() != genAtStart) {
            try {
                established?.pfd?.close()
            } catch (_: Throwable) {
            }
            return
        }
        if (established == null) {
            YolacNative.nativeSetDynamicIpv6Block(!targetIpv6)
            YolacNative.nativeNotifyNetworkChange()
            return
        }

        val isLockdown = Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q && isLockdownEnabled
        applySavedUserSettings(this)
        val detachedFd = established.pfd.detachFd()
        val ok = YolacNative.nativeStartTun(
            this,
            detachedFd,
            !targetIpv6,
            established.selfAppExcluded,
            isLockdown,
        )
        if (serviceGen.get() != genAtStart) {
            YolacNative.nativeStop()
            return
        }
        if (ok) {
            currentTunHasIpv6 = targetIpv6
            updateState(YolacNative.STATE_ACTIVE)
        } else {
            failedWithError.set(true)
            isRunningProtection = false
            YolacNative.nativeReportPlatformError(YolacNative.ERROR_TUN_SETUP_FAILED)
            updateState(YolacNative.STATE_ERROR)
            unregisterNetworkObserver()
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
        }
    }

    private fun stopProtectionAsync(expectedGen: Long) {
        isRunningProtection = false
        failedWithError.set(false)
        updateState(YolacNative.STATE_DEACTIVATING)
        unregisterNetworkObserver()
        worker.execute {
            YolacNative.nativeStop()
            // Do NOT strip notification or stopSelf if a rapid ACTION_START superseded this stop!
            if (serviceGen.get() != expectedGen) return@execute
            updateState(YolacNative.STATE_INACTIVE)
            try {
                stopForeground(STOP_FOREGROUND_REMOVE)
            } catch (_: Throwable) {
            }
            stopSelf()
        }
    }

    private fun registerNetworkObserver() {
        unregisterNetworkObserver()
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return
        observerRegisteredAtMs = System.currentTimeMillis()
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                if (System.currentTimeMillis() - observerRegisteredAtMs < 600L) return
                worker.execute { handleUnderlyingNetworkChange(cm.getLinkProperties(network), networkChanged = true) }
            }

            override fun onLinkPropertiesChanged(network: Network, linkProperties: LinkProperties) {
                if (System.currentTimeMillis() - observerRegisteredAtMs < 600L) return
                worker.execute { handleUnderlyingNetworkChange(linkProperties, networkChanged = false) }
            }

            override fun onLost(network: Network) {
                worker.execute {
                    if (isRunningProtection) {
                        YolacNative.nativeNotifyNetworkChange()
                    }
                }
            }
        }
        try {
            cm.registerDefaultNetworkCallback(cb)
            networkCallback = cb
        } catch (_: Exception) {
        }
    }

    private fun handleUnderlyingNetworkChange(lp: LinkProperties?, networkChanged: Boolean) {
        if (!isRunningProtection) return
        inspectPrivateDnsStatus(lp)
        val newHasIpv6 = hasGlobalIpv6OnLink(lp)
        if (newHasIpv6 != currentTunHasIpv6) {
            reapplyTunLocked(forcedIpv6 = newHasIpv6)
        } else if (networkChanged) {
            YolacNative.nativeNotifyNetworkChange()
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
        val gen = serviceGen.incrementAndGet()
        stopProtectionAsync(gen)
        super.onRevoke()
    }

    override fun onDestroy() {
        isRunningProtection = false
        unregisterNetworkObserver()
        worker.execute {
            YolacNative.nativeStop()
            if (!failedWithError.get()) {
                updateState(YolacNative.STATE_INACTIVE)
            }
        }
        worker.shutdown()
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
        val stopIntent = PendingIntent.getService(
            this,
            1,
            Intent(this, YolacVpnService::class.java).apply { action = ACTION_STOP },
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, CHANNEL_ID)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            builder.setForegroundServiceBehavior(Notification.FOREGROUND_SERVICE_IMMEDIATE)
        }
        val stopAction = Notification.Action.Builder(
            null,
            "Kapat",
            stopIntent,
        ).build()
        return builder
            .setContentTitle(getString(R.string.notif_active_title))
            .setContentText(getString(R.string.notif_active_body))
            .setSmallIcon(R.drawable.ic_tulpar_status)
            .setOngoing(true)
            .setContentIntent(openIntent)
            .addAction(stopAction)
            .build()
    }
}
