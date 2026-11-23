package org.yolac.app

import org.junit.Assert.assertEquals
import org.junit.Test

class TileStateMapperTest {

    @Test
    fun mapsAllEngineStatesToQuickSettingsTilePresentation() {
        val active = TileStateMapper.mapNativeState(YolacNative.STATE_ACTIVE)
        assertEquals(TileStateMapper.TILE_STATE_ACTIVE, active.tileState)
        assertEquals("Aktif", active.subtitleTr)

        val inactive = TileStateMapper.mapNativeState(YolacNative.STATE_INACTIVE)
        assertEquals(TileStateMapper.TILE_STATE_INACTIVE, inactive.tileState)
        assertEquals("Kapalı", inactive.subtitleTr)

        val starting = TileStateMapper.mapNativeState(YolacNative.STATE_ACTIVATING)
        assertEquals(TileStateMapper.TILE_STATE_UNAVAILABLE, starting.tileState)
        assertEquals("Bağlanıyor...", starting.subtitleTr)

        val stopping = TileStateMapper.mapNativeState(YolacNative.STATE_DEACTIVATING)
        assertEquals(TileStateMapper.TILE_STATE_UNAVAILABLE, stopping.tileState)
        assertEquals("Kapatılıyor...", stopping.subtitleTr)

        val err = TileStateMapper.mapNativeState(YolacNative.STATE_ERROR)
        assertEquals(TileStateMapper.TILE_STATE_INACTIVE, err.tileState)
        assertEquals("Hata", err.subtitleTr)
    }
}
