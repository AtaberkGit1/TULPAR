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
}
