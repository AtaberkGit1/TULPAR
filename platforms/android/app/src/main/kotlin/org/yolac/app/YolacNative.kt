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

    external fun nativeStartTun(
        service: VpnService,
        tunFd: Int,
        blockUnprotectedIpv6: Boolean,
    ): Boolean

    external fun nativeStop()

    external fun nativeGetState(): Int

    external fun nativeNotifyNetworkChange()

    external fun nativeGetHealthJson(): String

    external fun nativeCheckUpdatesJson(): String

    external fun nativeReportPlatformError(errorCode: Int)
}
