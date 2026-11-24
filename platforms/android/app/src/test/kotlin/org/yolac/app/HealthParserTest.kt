package org.yolac.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class HealthParserTest {

    @Test
    fun parsesAllSevenModulesAndHidesErrorsWhenHealthy() {
        val sampleJson = """
            [
              {"id":0,"name":"Akıllı Koruma","status":1,"detail":"Aktif"},
              {"id":1,"name":"DNS Koruması","status":1,"detail":"DoH/DoT aktif"},
              {"id":2,"name":"Reklam ve Takip Engelleme","status":1,"detail":"Aktif"},
              {"id":3,"name":"Gelişmiş Sansür Aşma","status":1,"detail":"TLS/SNI aktif"},
              {"id":4,"name":"Bağlantı Güvenliği","status":1,"detail":"Sızıntı koruması aktif"},
              {"id":5,"name":"Performans","status":1,"detail":"Düşük kaynak"},
              {"id":6,"name":"Güncellemeler","status":0,"detail":"Henüz kontrol edilmedi."}
            ]
        """.trimIndent()

        val items = HealthParser.parseModules(sampleJson)
        assertEquals(7, items.size)
        assertEquals("Akıllı Koruma", items[0].name)
        assertEquals("Güncellemeler", items[6].name)
        assertEquals(0, items[6].status)
        assertNull(HealthParser.formatErrorSummary(items))
    }

    @Test
    fun surfacesFullNameAndReasonForFailingModulesOnly() {
        val sampleJson = """
            [
              {"id":0,"name":"Akıllı Koruma","status":2,"detail":"VPN izni reddedildi."},
              {"id":1,"name":"DNS Koruması","status":2,"detail":"Şifreli DNS bağlantısı yok."},
              {"id":6,"name":"Güncellemeler","status":0,"detail":"Henüz kontrol edilmedi."}
            ]
        """.trimIndent()

        val items = HealthParser.parseModules(sampleJson)
        val err = HealthParser.formatErrorSummary(items)
        assertTrue(err!!.contains("Akıllı Koruma: VPN izni reddedildi."))
        assertTrue(err.contains("DNS Koruması: Şifreli DNS bağlantısı yok."))
        assertFalse(err.contains("Güncellemeler"))
    }

    @Test
    fun validatesOfficialGithubReleaseUrlsAndRejectsThirdPartyAndSpoofedRepos() {
        val official = HealthParser.parseUpdateResult(
            """{"status":"update_available","message":"Yeni sürüm","release_url":"https://github.com/AtaberkGit1/TULPAR/releases/tag/v0.4.0"}""",
        )
        assertTrue(official.isTrustedOfficialGithubReleaseUrl())

        val spoofedDomain = HealthParser.parseUpdateResult(
            """{"status":"update_available","message":"Yeni sürüm","release_url":"https://evil.example.org/tulpar.apk"}""",
        )
        assertFalse(spoofedDomain.isTrustedOfficialGithubReleaseUrl())

        val spoofedGithubRepo = HealthParser.parseUpdateResult(
            """{"status":"update_available","message":"Yeni sürüm","release_url":"https://github.com/attacker/TULPAR/releases/tag/v9.9.9"}""",
        )
        assertFalse(spoofedGithubRepo.isTrustedOfficialGithubReleaseUrl())
    }

    @Test
    fun parsesDiagnosticResultCleanly() {
        val diag = HealthParser.parseDiagnosticResult(
            """{"ok":true,"fastest_dns":"cloudflare-doh","fastest_rtt_ms":19,"summary":"En Hızlı Şifreli DNS: cloudflare-doh (19 ms)"}""",
        )
        assertTrue(diag.ok)
        assertTrue(diag.summary.contains("19 ms"))

        val broken = HealthParser.parseDiagnosticResult("not-json")
        assertFalse(broken.ok)
    }

    @Test
    fun verifiesRequiredTurkishSecurityWarningString() {
        assertEquals(
            "GÜVENLİK UYARISI: TULPAR'ı yalnızca resmî GitHub sayfamızdan indirin! Üçüncü taraf kaynaklardan indirilen dosyalar değiştirilmiş veya zararlı olabilir.",
            YolacNative.SECURITY_WARNING_TR,
        )
    }
}
