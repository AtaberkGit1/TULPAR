package org.yolac.app

import android.content.Intent
import android.graphics.Color
import android.graphics.drawable.GradientDrawable
import android.net.Uri
import android.os.Bundle
import android.util.TypedValue
import android.view.Gravity
import android.view.View
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import androidx.activity.ComponentActivity
import androidx.core.view.WindowCompat
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class SettingsActivity : ComponentActivity() {

    private lateinit var rowView: ModuleStatusRowView
    private lateinit var errorTextView: TextView
    private lateinit var selectedTextView: TextView
    private lateinit var updateButton: Button
    private lateinit var updateStatusText: TextView

    private var selectedModuleId: Int? = null
    private var checkingUpdates = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        WindowCompat.setDecorFitsSystemWindows(window, false)
        window.statusBarColor = Color.BLACK
        window.navigationBarColor = Color.BLACK

        val density = resources.displayMetrics.density
        val pad = (20 * density).toInt()

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(Color.BLACK)
            setPadding(pad, (44 * density).toInt(), pad, (28 * density).toInt())
        }

        // Top bar: Back + Ayarlar
        val header = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }
        val backBtn = TextView(this).apply {
            text = "←"
            setTextColor(Color.WHITE)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 22f)
            contentDescription = "Geri"
            setPadding(0, (6 * density).toInt(), (16 * density).toInt(), (6 * density).toInt())
            setOnClickListener { finish() }
        }
        val title = TextView(this).apply {
            text = "Ayarlar"
            setTextColor(Color.WHITE)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 18f)
        }
        header.addView(backBtn)
        header.addView(title)
        root.addView(header)

        // Single non-wrapping horizontal row of 7 module status icons
        rowView = ModuleStatusRowView(this) { item ->
            selectedModuleId = item.id
            renderSelectedModule(item)
        }
        root.addView(
            rowView,
            LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT,
            ).apply {
                topMargin = (24 * density).toInt()
            },
        )

        // Red error summary (ONLY visible when 1 or more modules have status == Error)
        errorTextView = TextView(this).apply {
            setTextColor(Color.parseColor("#E74C3C"))
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 13f)
            visibility = View.GONE
        }
        root.addView(
            errorTextView,
            LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT,
            ).apply {
                topMargin = (14 * density).toInt()
            },
        )

        // Selected icon inspection text
        selectedTextView = TextView(this).apply {
            setTextColor(Color.parseColor("#BDBDBD"))
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 13f)
            visibility = View.GONE
        }
        root.addView(
            selectedTextView,
            LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT,
            ).apply {
                topMargin = (10 * density).toInt()
            },
        )

        // Manual GitHub Releases update check button (never runs in background)
        val btnBg = GradientDrawable().apply {
            setColor(Color.BLACK)
            setStroke((1.5f * density).toInt(), Color.parseColor("#555555"))
            cornerRadius = 8f * density
        }
        updateButton = Button(this).apply {
            text = "Güncellemeleri Kontrol Et"
            isAllCaps = false
            setTextColor(Color.WHITE)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 14f)
            background = btnBg
            setOnClickListener { runManualUpdateCheck() }
        }
        root.addView(
            updateButton,
            LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                (48 * density).toInt(),
            ).apply {
                topMargin = (22 * density).toInt()
            },
        )

        updateStatusText = TextView(this).apply {
            setTextColor(Color.parseColor("#BDBDBD"))
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 13f)
            visibility = View.GONE
        }
        root.addView(
            updateStatusText,
            LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT,
            ).apply {
                topMargin = (10 * density).toInt()
            },
        )

        // Prominent minimalist security warning directly below update button
        val warnBg = GradientDrawable().apply {
            setColor(Color.parseColor("#110707"))
            setStroke((1f * density).toInt(), Color.parseColor("#7A2B2B"))
            cornerRadius = 8f * density
        }
        val warningText = TextView(this).apply {
            text = YolacNative.SECURITY_WARNING_TR
            setTextColor(Color.parseColor("#E6B0AA"))
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 12.5f)
            val wp = (14 * density).toInt()
            setPadding(wp, wp, wp, wp)
            background = warnBg
        }
        root.addView(
            warningText,
            LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT,
            ).apply {
                topMargin = (18 * density).toInt()
            },
        )

        // Flexible spacer pushing credit footer to bottom
        root.addView(
            View(this),
            LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f),
        )

        val footer = TextView(this).apply {
            text = YolacNative.DEVELOPER_CREDIT_TR
            setTextColor(Color.parseColor("#6E6E6E"))
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f)
            gravity = Gravity.CENTER_HORIZONTAL
        }
        root.addView(
            footer,
            LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT,
            ),
        )

        setContentView(root)

        lifecycleScope.launch {
            YolacVpnService.stateFlow.collect {
                refreshHealth()
            }
        }
    }

    override fun onResume() {
        super.onResume()
        refreshHealth()
    }

    private fun refreshHealth() {
        val items = HealthParser.parseModules(YolacNative.nativeGetHealthJson())
        rowView.updateModules(items)

        val errSummary = HealthParser.formatErrorSummary(items)
        if (errSummary == null) {
            errorTextView.visibility = View.GONE
            errorTextView.text = ""
        } else {
            errorTextView.text = errSummary
            errorTextView.visibility = View.VISIBLE
        }

        selectedModuleId?.let { id ->
            items.find { it.id == id }?.let { renderSelectedModule(it) }
        }
    }

    private fun renderSelectedModule(item: ModuleHealthItem) {
        val stateLabel = when (item.status) {
            1 -> "Aktif"
            2 -> "Hata"
            else -> "Pasif / Kontrol edilmedi"
        }
        selectedTextView.text = "${item.name} ($stateLabel): ${item.detail}"
        selectedTextView.setTextColor(
            when (item.status) {
                1 -> Color.parseColor("#2ECC71")
                2 -> Color.parseColor("#E74C3C")
                else -> Color.parseColor("#9E9E9E")
            },
        )
        selectedTextView.visibility = View.VISIBLE
    }

    private fun runManualUpdateCheck() {
        if (checkingUpdates) return
        checkingUpdates = true
        updateButton.isEnabled = false
        updateStatusText.text = "Resmî GitHub sürümleri kontrol ediliyor..."
        updateStatusText.setTextColor(Color.parseColor("#BDBDBD"))
        updateStatusText.visibility = View.VISIBLE

        lifecycleScope.launch {
            val rawJson = withContext(Dispatchers.IO) {
                YolacNative.nativeCheckUpdatesJson()
            }
            checkingUpdates = false
            updateButton.isEnabled = true
            refreshHealth()

            val parsed = HealthParser.parseUpdateResult(rawJson)
            updateStatusText.text = parsed.message
            updateStatusText.setTextColor(
                if (parsed.status == "error") Color.parseColor("#E74C3C")
                else Color.parseColor("#2ECC71"),
            )
            if (parsed.status == "update_available" && parsed.isTrustedOfficialGithubReleaseUrl()) {
                startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(parsed.releaseUrl)))
            }
        }
    }
}
