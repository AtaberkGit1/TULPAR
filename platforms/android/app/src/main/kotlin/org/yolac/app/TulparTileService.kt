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
        syncTile()
    }

    override fun onClick() {
        super.onClick()
        val current = YolacVpnService.stateFlow.value
        if (current == YolacNative.STATE_ACTIVATING || current == YolacNative.STATE_DEACTIVATING) {
            return
        }

        if (current == YolacNative.STATE_ACTIVE) {
            val stopIntent = Intent(this, YolacVpnService::class.java).apply {
                action = YolacVpnService.ACTION_STOP
            }
            startService(stopIntent)
            syncTile()
            return
        }

        // If VPN permission was already granted by the user, start directly without opening the app.
        val prepareIntent = VpnService.prepare(this)
        if (prepareIntent == null) {
            val startIntent = Intent(this, YolacVpnService::class.java).apply {
                action = YolacVpnService.ACTION_START
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                startForegroundService(startIntent)
            } else {
                startService(startIntent)
            }
            syncTile()
        } else {
            val launchIntent = Intent(this, MainActivity::class.java).apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
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
