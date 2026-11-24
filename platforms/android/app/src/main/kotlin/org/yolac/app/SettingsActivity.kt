package org.yolac.app

import android.app.AlertDialog
import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Color
import android.graphics.drawable.GradientDrawable
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.util.TypedValue
import android.view.Gravity
import android.view.View
import android.widget.Button
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.activity.ComponentActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.WindowInsetsControllerCompat
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class SettingsActivity : ComponentActivity() {

    private lateinit var rowView: ModuleStatusRowView
    private lateinit var errorTextView: TextView
    private lateinit var selectedTextView: TextView
    private lateinit var privateDnsBanner: TextView
    private lateinit var diagButton: Button
    private lateinit var diagStatusText: TextView
    private lateinit var splitTunnelButton: Button
    private lateinit var batteryButton: Button
    private lateinit var updateButton: Button
    private lateinit var updateStatusText: TextView

    private var selectedModuleId: Int? = null
    private var checkingUpdates = false
    private var runningDiagnostics = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        selectedModuleId = savedInstanceState?.let {
            if (it.containsKey("selected_module_id")) it.getInt("selected_module_id") else null
        }

        WindowCompat.setDecorFitsSystemWindows(window, false)
        @Suppress("DEPRECATION")
        run {
            window.statusBarColor = Color.BLACK
            window.navigationBarColor = Color.BLACK
        }
        val insetsCtrl = WindowInsetsControllerCompat(window, window.decorView)
        insetsCtrl.isAppearanceLightStatusBars = false
        insetsCtrl.isAppearanceLightNavigationBars = false

        val density = resources.displayMetrics.density
        val pad = (20 * density).toInt()
        val baseTop = (18 * density).toInt()
        val baseBottom = (28 * density).toInt()

        val scrollView = ScrollView(this).apply {
            isFillViewport = true
            setBackgroundColor(Color.BLACK)
        }

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(Color.BLACK)
            setPadding(pad, (44 * density).toInt(), pad, baseBottom)
        }

        ViewCompat.setOnApplyWindowInsetsListener(root) { v, insets ->
            val bars = insets.getInsets(
                WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout(),
            )
            v.setPadding(
                pad + bars.left,
                bars.top + baseTop,
                pad + bars.right,
                bars.bottom + baseBottom,
            )
            insets
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
        rowView.setSelectedModuleId(selectedModuleId)
        root.addView(
            rowView,
            LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT,
            ).apply {
                topMargin = (20 * density).toInt()
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
                topMargin = (12 * density).toInt()
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

        // Honest Android Private DNS advisory banner (only visible when OS Private DNS overrides TUN DNS)
        val dnsWarnBg = GradientDrawable().apply {
            setColor(Color.parseColor("#141005"))
            setStroke((1f * density).toInt(), Color.parseColor("#8A6D2E"))
            cornerRadius = 8f * density
        }
        privateDnsBanner = TextView(this).apply {
            text = "Not: Android Özel DNS (Private DNS) açık görünüyor. Reklam engelleme ve TULPAR DNS hızlandırmasının tam çalışması için Android Ağ ayarlarından Özel DNS'i 'Kapalı' yapmanız önerilir (açmak için dokunun)."
            setTextColor(Color.parseColor("#F5D78E"))
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 12.5f)
            val dp = (12 * density).toInt()
            setPadding(dp, dp, dp, dp)
            background = dnsWarnBg
            visibility = View.GONE
            setOnClickListener { openAndroidNetworkSettings() }
        }
        root.addView(
            privateDnsBanner,
            LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT,
            ).apply {
                topMargin = (14 * density).toInt()
            },
        )

        fun makeOutlineButton(label: String, borderHex: String = "#555555"): Button {
            val bg = GradientDrawable().apply {
                setColor(Color.BLACK)
                setStroke((1.5f * density).toInt(), Color.parseColor(borderHex))
                cornerRadius = 8f * density
            }
            return Button(this).apply {
                text = label
                isAllCaps = false
                setTextColor(Color.WHITE)
                setTextSize(TypedValue.COMPLEX_UNIT_SP, 14f)
                background = bg
            }
        }

        // Swiss Army Knife #1: Live Encrypted DNS & IPv6 Speed Diagnostic
        diagButton = makeOutlineButton("Ağ ve Hız Testi (DNS / IPv6)", "#4A7A5A").apply {
            setOnClickListener { runLiveDiagnostics() }
        }
        root.addView(
            diagButton,
            LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                (46 * density).toInt(),
            ).apply {
                topMargin = (18 * density).toInt()
            },
        )

        diagStatusText = TextView(this).apply {
            setTextColor(Color.parseColor("#BDBDBD"))
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 12.5f)
            visibility = View.GONE
        }
        root.addView(
            diagStatusText,
            LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT,
            ).apply {
                topMargin = (8 * density).toInt()
            },
        )

        // Swiss Army Knife #2: Per-App Split-Tunneling (Banks / e-Devlet / Games bypass)
        splitTunnelButton = makeOutlineButton(splitTunnelButtonLabel()).apply {
            setOnClickListener { openSplitTunnelDialog() }
        }
        root.addView(
            splitTunnelButton,
            LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                (46 * density).toInt(),
            ).apply {
                topMargin = (12 * density).toInt()
            },
        )

        // Swiss Army Knife #3: Battery Optimization shortcut (prevents Xiaomi/Samsung OEM background kills)
        batteryButton = makeOutlineButton("Pil Kısıtlamasını Kaldır (Arka Plan)").apply {
            setOnClickListener { openBatteryOptimizationSettings() }
        }
        root.addView(
            batteryButton,
            LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                (46 * density).toInt(),
            ).apply {
                topMargin = (12 * density).toInt()
            },
        )

        // Manual GitHub Releases update check button (never runs in background)
        updateButton = makeOutlineButton("Güncellemeleri Kontrol Et").apply {
            setOnClickListener { runManualUpdateCheck() }
        }
        root.addView(
            updateButton,
            LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                (46 * density).toInt(),
            ).apply {
                topMargin = (12 * density).toInt()
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
                topMargin = (8 * density).toInt()
            },
        )

        // Prominent minimalist security warning directly below controls
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

        scrollView.addView(
            root,
            FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT,
                FrameLayout.LayoutParams.WRAP_CONTENT,
            ),
        )
        setContentView(scrollView)

        lifecycleScope.launch {
            YolacVpnService.stateFlow.collect {
                refreshHealth()
            }
        }
        lifecycleScope.launch {
            YolacVpnService.privateDnsWarning.collect { active ->
                privateDnsBanner.visibility = if (active) View.VISIBLE else View.GONE
            }
        }
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        selectedModuleId?.let { outState.putInt("selected_module_id", it) }
    }

    override fun onResume() {
        super.onResume()
        YolacVpnService.syncStateFromNative()
        splitTunnelButton.text = splitTunnelButtonLabel()
        refreshHealth()
    }

    private fun getExcludedPackages(): MutableSet<String> {
        val saved = getSharedPreferences(YolacVpnService.PREFS_NAME, Context.MODE_PRIVATE)
            .getStringSet(YolacVpnService.KEY_EXCLUDED_PACKAGES, emptySet())
            ?: emptySet()
        return saved.toMutableSet()
    }

    private fun splitTunnelButtonLabel(): String {
        val count = getExcludedPackages().size
        return if (count > 0) {
            "Uygulama Hariç Tut ($count hariç)"
        } else {
            "Uygulama Hariç Tut (Banka / Oyun)"
        }
    }

    private fun openSplitTunnelDialog() {
        lifecycleScope.launch {
            val apps = withContext(Dispatchers.IO) {
                val intent = Intent(Intent.ACTION_MAIN, null).apply {
                    addCategory(Intent.CATEGORY_LAUNCHER)
                }
                val resolved = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    packageManager.queryIntentActivities(
                        intent,
                        PackageManager.ResolveInfoFlags.of(0),
                    )
                } else {
                    @Suppress("DEPRECATION")
                    packageManager.queryIntentActivities(intent, 0)
                }
                val seen = LinkedHashMap<String, String>()
                for (ri in resolved) {
                    val pkg = ri.activityInfo?.packageName ?: continue
                    if (pkg == packageName || seen.containsKey(pkg)) continue
                    val label = try {
                        ri.loadLabel(packageManager)?.toString()?.takeIf { it.isNotBlank() } ?: pkg
                    } catch (_: Throwable) {
                        pkg
                    }
                    seen[pkg] = label
                }
                seen.entries
                    .sortedBy { it.value.lowercase() }
                    .map { it.key to it.value }
            }

            if (isFinishing || isDestroyed) return@launch
            if (apps.isEmpty()) {
                diagStatusText.text = "Hariç tutulabilecek uygulama listesi alınamadı."
                diagStatusText.setTextColor(Color.parseColor("#BDBDBD"))
                diagStatusText.visibility = View.VISIBLE
                return@launch
            }

            val excluded = getExcludedPackages()
            val labels = apps.map { it.second }.toTypedArray()
            val checked = BooleanArray(apps.size) { idx -> excluded.contains(apps[idx].first) }

            AlertDialog.Builder(this@SettingsActivity, android.R.style.Theme_DeviceDefault_Dialog_Alert)
                .setTitle("Hariç Tutulacak Uygulamalar")
                .setMultiChoiceItems(labels, checked) { _, which, isChecked ->
                    val pkg = apps[which].first
                    if (isChecked) excluded.add(pkg) else excluded.remove(pkg)
                }
                .setPositiveButton("Kaydet") { _, _ ->
                    getSharedPreferences(YolacVpnService.PREFS_NAME, Context.MODE_PRIVATE)
                        .edit()
                        .putStringSet(YolacVpnService.KEY_EXCLUDED_PACKAGES, HashSet(excluded))
                        .apply()
                    splitTunnelButton.text = splitTunnelButtonLabel()
                    if (YolacVpnService.stateFlow.value == YolacNative.STATE_ACTIVE) {
                        try {
                            startService(
                                Intent(this@SettingsActivity, YolacVpnService::class.java).apply {
                                    action = YolacVpnService.ACTION_REAPPLY
                                },
                            )
                        } catch (_: Throwable) {
                        }
                    }
                }
                .setNeutralButton("Temizle") { _, _ ->
                    getSharedPreferences(YolacVpnService.PREFS_NAME, Context.MODE_PRIVATE)
                        .edit()
                        .putStringSet(YolacVpnService.KEY_EXCLUDED_PACKAGES, emptySet())
                        .apply()
                    splitTunnelButton.text = splitTunnelButtonLabel()
                    if (YolacVpnService.stateFlow.value == YolacNative.STATE_ACTIVE) {
                        try {
                            startService(
                                Intent(this@SettingsActivity, YolacVpnService::class.java).apply {
                                    action = YolacVpnService.ACTION_REAPPLY
                                },
                            )
                        } catch (_: Throwable) {
                        }
                    }
                }
                .setNegativeButton("İptal", null)
                .show()
        }
    }

    private fun openBatteryOptimizationSettings() {
        try {
            startActivity(Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS))
        } catch (_: ActivityNotFoundException) {
            try {
                startActivity(
                    Intent(
                        Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                        Uri.parse("package:$packageName"),
                    ),
                )
            } catch (_: ActivityNotFoundException) {
            }
        }
    }

    private fun openAndroidNetworkSettings() {
        try {
            startActivity(Intent(Settings.ACTION_WIRELESS_SETTINGS))
        } catch (_: ActivityNotFoundException) {
            try {
                startActivity(Intent(Settings.ACTION_SETTINGS))
            } catch (_: ActivityNotFoundException) {
            }
        }
    }

    private fun runLiveDiagnostics() {
        if (runningDiagnostics) return
        runningDiagnostics = true
        diagButton.isEnabled = false
        diagButton.text = "Ağ ve DNS Hızı Ölçülüyor..."
        diagStatusText.text = "Şifreli DNS sunucuları ve IPv6 erişimi ölçülüyor..."
        diagStatusText.setTextColor(Color.parseColor("#BDBDBD"))
        diagStatusText.visibility = View.VISIBLE

        lifecycleScope.launch {
            val rawJson = withContext(Dispatchers.IO) {
                YolacNative.nativeRunDiagnosticsJson()
            }
            runningDiagnostics = false
            diagButton.isEnabled = true
            diagButton.text = "Ağ ve Hız Testi (DNS / IPv6)"
            refreshHealth()

            val parsed = HealthParser.parseDiagnosticResult(rawJson)
            diagStatusText.text = parsed.summary
            diagStatusText.setTextColor(
                if (parsed.ok) Color.parseColor("#2ECC71")
                else Color.parseColor("#E74C3C"),
            )
        }
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
                try {
                    startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(parsed.releaseUrl)))
                } catch (_: ActivityNotFoundException) {
                }
            }
        }
    }
}
