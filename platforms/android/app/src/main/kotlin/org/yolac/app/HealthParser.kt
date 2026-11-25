package org.yolac.app

import org.json.JSONArray
import org.json.JSONObject
import java.util.Locale

data class UpdateCheckUiResult(
    val status: String,
    val message: String,
    val releaseUrl: String,
) {
    fun isTrustedOfficialGithubReleaseUrl(): Boolean {
        return releaseUrl.lowercase(Locale.US)
            .startsWith("https://github.com/ataberkgit1/tulpar/releases")
    }
}

data class DiagnosticUiResult(
    val ok: Boolean,
    val summary: String,
)

data class DomainDoctorUiResult(
    val ok: Boolean,
    val verdict: String,
    val summary: String,
)

data class DnsProfileUiResult(
    val ok: Boolean,
    val key: String,
    val label: String,
    val error: String,
)

object HealthParser {
    fun parseModules(rawJson: String): List<ModuleHealthItem> {
        val list = mutableListOf<ModuleHealthItem>()
        try {
            val arr = JSONArray(rawJson)
            for (i in 0 until arr.length()) {
                val o = arr.getJSONObject(i)
                list.add(
                    ModuleHealthItem(
                        id = o.optInt("id", i),
                        name = o.optString("name", ""),
                        status = o.optInt("status", 0),
                        detail = o.optString("detail", ""),
                    ),
                )
            }
        } catch (_: Exception) {
        }
        return list
    }

    fun formatErrorSummary(items: List<ModuleHealthItem>): String? {
        val errors = items.filter { it.status == 2 }
        if (errors.isEmpty()) return null
        val seen = LinkedHashSet<String>()
        val lines = mutableListOf<String>()
        for (item in errors) {
            if (seen.add(item.detail)) {
                lines.add("${item.name}: ${item.detail}")
            }
        }
        return lines.joinToString("\n")
    }

    fun parseUpdateResult(rawJson: String): UpdateCheckUiResult {
        return try {
            val obj = JSONObject(rawJson)
            UpdateCheckUiResult(
                status = obj.optString("status", "error"),
                message = obj.optString("message", "Güncelleme kontrolü başarısız."),
                releaseUrl = obj.optString("release_url", ""),
            )
        } catch (_: Exception) {
            UpdateCheckUiResult(
                status = "error",
                message = "Güncelleme yanıtı okunamadı.",
                releaseUrl = "",
            )
        }
    }

    fun parseDiagnosticResult(rawJson: String): DiagnosticUiResult {
        return try {
            val obj = JSONObject(rawJson)
            DiagnosticUiResult(
                ok = obj.optBoolean("ok", false),
                summary = obj.optString("summary", "Ağ testi sonucu okunamadı."),
            )
        } catch (_: Exception) {
            DiagnosticUiResult(
                ok = false,
                summary = "Ağ testi yanıtı çözümlenemedi.",
            )
        }
    }

    fun parseDomainDoctorResult(rawJson: String): DomainDoctorUiResult {
        return try {
            val obj = JSONObject(rawJson)
            val dnsOk = obj.optBoolean("dns_ok", false)
            val directOk = obj.optBoolean("direct_tls_ok", false)
            val evasionOk = obj.optBoolean("evasion_tls_ok", false)
            DomainDoctorUiResult(
                ok = dnsOk && (directOk || evasionOk),
                verdict = obj.optString("verdict", "dns_failed"),
                summary = obj.optString("summary", "Alan adı testi tamamlanamadı."),
            )
        } catch (_: Exception) {
            DomainDoctorUiResult(
                ok = false,
                verdict = "dns_failed",
                summary = "Alan adı test yanıtı çözümlenemedi.",
            )
        }
    }

    fun parseDnsProfileSetResult(rawJson: String): DnsProfileUiResult {
        return try {
            val obj = JSONObject(rawJson)
            DnsProfileUiResult(
                ok = obj.optBoolean("ok", false),
                key = obj.optString("key", "auto"),
                label = obj.optString("label", "Otomatik (En Hızlı)"),
                error = obj.optString("error", ""),
            )
        } catch (_: Exception) {
            DnsProfileUiResult(
                ok = false,
                key = "auto",
                label = "Otomatik (En Hızlı)",
                error = "DNS profili ayarlanamadı.",
            )
        }
    }

    fun buildUserRulesJson(
        allowRaw: String,
        blockRaw: String,
        excludeRaw: String,
    ): String {
        fun cleanList(raw: String): JSONArray {
            val arr = JSONArray()
            val seen = LinkedHashSet<String>()
            for (part in raw.split(",", "\n", ";", " ")) {
                val dom = part.trim().trimEnd('.').lowercase(Locale.US)
                if (dom.isNotEmpty() && dom.length <= 253 && dom.contains('.') && seen.add(dom)) {
                    arr.put(dom)
                }
            }
            return arr
        }
        return JSONObject().apply {
            put("allowlist", cleanList(allowRaw))
            put("blocklist", cleanList(blockRaw))
            put("excluded_dpi", cleanList(excludeRaw))
            put("aggressive_dpi", JSONArray())
        }.toString()
    }
}
