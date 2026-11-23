package org.yolac.app

import org.json.JSONArray
import org.json.JSONObject

data class UpdateCheckUiResult(
    val status: String,
    val message: String,
    val releaseUrl: String,
) {
    fun isTrustedOfficialGithubReleaseUrl(): Boolean {
        return releaseUrl.startsWith("https://github.com/") && releaseUrl.contains("/releases")
    }
}

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
        return errors.joinToString("\n") { "${it.name}: ${it.detail}" }
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
}
