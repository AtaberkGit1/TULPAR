package org.yolac.app

import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService

data class TilePresentation(
    val tileState: Int,
    val subtitleTr: String,
)

object TileStateMapper {
    const val TILE_STATE_UNAVAILABLE = 0
    const val TILE_STATE_INACTIVE = 1
    const val TILE_STATE_ACTIVE = 2

    fun mapNativeState(nativeState: Int): TilePresentation = when (nativeState) {
        YolacNative.STATE_ACTIVE -> TilePresentation(TILE_STATE_ACTIVE, "Aktif")
        YolacNative.STATE_ACTIVATING -> TilePresentation(TILE_STATE_UNAVAILABLE, "Bağlanıyor...")
        YolacNative.STATE_DEACTIVATING -> TilePresentation(TILE_STATE_UNAVAILABLE, "Kapatılıyor...")
        YolacNative.STATE_ERROR -> TilePresentation(TILE_STATE_INACTIVE, "Hata")
        else -> TilePresentation(TILE_STATE_INACTIVE, "Kapalı")
    }
}

class TulparTileService : TileService() {

    override fun onStartListening() {
        super.onStartListening()
        YolacVpnService.syncStateFromNative()
        syncTile()
    }

    override fun onClick() {
        super.onClick()
        if (isLocked) {
            unlockAndRun { performToggle() }
        } else {
            performToggle()
        }
    }

    private fun performToggle() {
        YolacVpnService.syncStateFromNative()
        val current = YolacVpnService.stateFlow.value
        if (current == YolacNative.STATE_ACTIVATING || current == YolacNative.STATE_DEACTIVATING) {
            return
        }

        if (current == YolacNative.STATE_ACTIVE) {
            try {
                val stopIntent = Intent(this, YolacVpnService::class.java).apply {
                    action = YolacVpnService.ACTION_STOP
                }
                startService(stopIntent)
            } catch (_: Throwable) {
            }
            syncTile()
            return
        }

        // If VPN permission was already granted by the user, start directly without opening the app.
        val prepareIntent = try {
            VpnService.prepare(this)
        } catch (_: Throwable) {
            null
        }
        if (prepareIntent == null) {
            try {
                val startIntent = Intent(this, YolacVpnService::class.java).apply {
                    action = YolacVpnService.ACTION_START
                }
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    startForegroundService(startIntent)
                } else {
                    startService(startIntent)
                }
                syncTile()
                return
            } catch (_: Throwable) {
                // Fall back to launching MainActivity cleanly on OEM FGS restriction
            }
        }
        openAppActivity()
    }

    private fun openAppActivity() {
        val launchIntent = Intent(this, MainActivity::class.java).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                val pending = PendingIntent.getActivity(
                    this,
                    1,
                    launchIntent,
                    PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
                )
                startActivityAndCollapse(pending)
            } else {
                @Suppress("DEPRECATION")
                startActivityAndCollapse(launchIntent)
            }
        } catch (_: Throwable) {
        }
    }

    private fun syncTile() {
        val tile = qsTile ?: return
        val pres = TileStateMapper.mapNativeState(YolacVpnService.stateFlow.value)
        tile.label = getString(R.string.app_name)
        tile.state = when (pres.tileState) {
            TileStateMapper.TILE_STATE_ACTIVE -> Tile.STATE_ACTIVE
            TileStateMapper.TILE_STATE_UNAVAILABLE -> Tile.STATE_UNAVAILABLE
            else -> Tile.STATE_INACTIVE
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            tile.subtitle = pres.subtitleTr
        }
        tile.updateTile()
    }
}
