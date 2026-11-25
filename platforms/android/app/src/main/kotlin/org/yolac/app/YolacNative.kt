package org.yolac.app

import android.net.VpnService

object YolacNative {
    init {
        System.loadLibrary("yolac_ffi")
    }

    const val STATE_INACTIVE = 0
    const val STATE_ACTIVATING = 1
    const val STATE_ACTIVE = 2
    const val STATE_DEACTIVATING = 3
    const val STATE_ERROR = 4

    const val ERROR_PERMISSION_DENIED = 1
    const val ERROR_TUN_SETUP_FAILED = 2

    const val SECURITY_WARNING_TR =
        "GÜVENLİK UYARISI: TULPAR'ı yalnızca resmî GitHub sayfamızdan indirin! Üçüncü taraf kaynaklardan indirilen dosyalar değiştirilmiş veya zararlı olabilir."

    @JvmStatic
    external fun nativeStartTun(
        service: VpnService,
        tunFd: Int,
        blockUnprotectedIpv6: Boolean,
        selfAppExcluded: Boolean,
        isLockdown: Boolean,
    ): Boolean

    @JvmStatic
    external fun nativeStop()

    @JvmStatic
    external fun nativeGetState(): Int

    @JvmStatic
    external fun nativeNotifyNetworkChange()

    @JvmStatic
    external fun nativeSetDynamicIpv6Block(block: Boolean)

    @JvmStatic
    external fun nativeGetHealthJson(): String

    @JvmStatic
    external fun nativeCheckUpdatesJson(): String

    @JvmStatic
    external fun nativeRunDiagnosticsJson(): String

    @JvmStatic
    external fun nativeReportPlatformError(errorCode: Int)

    @JvmStatic
    external fun nativeLoadForgePackage(packageBytes: ByteArray): String

    @JvmStatic
    external fun nativeUnloadForgePackage()

    @JvmStatic
    external fun nativeGetForgeStatusJson(): String
}
