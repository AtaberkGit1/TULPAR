package org.yolac.app

import android.Manifest
import android.app.Activity
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.drawable.GradientDrawable
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.util.TypedValue
import android.view.Gravity
import android.view.View
import android.widget.Button
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.TextView
import androidx.activity.ComponentActivity
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.ContextCompat
import androidx.core.view.WindowCompat
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.launch
import kotlin.math.cos
import kotlin.math.sin

class MainActivity : ComponentActivity() {

    private lateinit var buttonView: YolacButtonView

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            startVpnService()
        } else {
            YolacNative.nativeReportPlatformError(YolacNative.ERROR_PERMISSION_DENIED)
            buttonView.state = YolacButtonView.UiState.ERROR
        }
    }

    private val notificationPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { _ ->
        requestVpnConsentAndStart()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        WindowCompat.setDecorFitsSystemWindows(window, false)
        window.statusBarColor = Color.BLACK
        window.navigationBarColor = Color.BLACK

        val density = resources.displayMetrics.density
        val container = FrameLayout(this).apply {
            setBackgroundColor(Color.BLACK)
        }

        buttonView = YolacButtonView(this)
        container.addView(
            buttonView,
            FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT,
                FrameLayout.LayoutParams.MATCH_PARENT,
            ),
        )

        // Small minimalist settings gear icon in top-right corner
        val gearSize = (44 * density).toInt()
        val settingsIcon = SettingsGearView(this).apply {
            contentDescription = "Ayarlar"
            setOnClickListener {
                startActivity(Intent(this@MainActivity, SettingsActivity::class.java))
            }
        }
        container.addView(
            settingsIcon,
            FrameLayout.LayoutParams(gearSize, gearSize).apply {
                gravity = Gravity.TOP or Gravity.END
                topMargin = (42 * density).toInt()
                marginEnd = (16 * density).toInt()
            },
        )

        // First-launch security warning overlay (no personal data stored, only local ack boolean)
        val prefs = getSharedPreferences("yolac_prefs", Context.MODE_PRIVATE)
        if (!prefs.getBoolean("security_warning_ack", false)) {
            val overlay = buildFirstLaunchSecurityOverlay(density) {
                prefs.edit().putBoolean("security_warning_ack", true).apply()
            }
            container.addView(
                overlay,
                FrameLayout.LayoutParams(
                    FrameLayout.LayoutParams.MATCH_PARENT,
                    FrameLayout.LayoutParams.MATCH_PARENT,
                ),
            )
        }

        setContentView(container)

        buttonView.setOnClickListener {
            onToggleClicked()
        }

        lifecycleScope.launch {
            YolacVpnService.stateFlow.collect { nativeState ->
                buttonView.state = when (nativeState) {
                    YolacNative.STATE_ACTIVE -> YolacButtonView.UiState.ACTIVE
                    YolacNative.STATE_ACTIVATING, YolacNative.STATE_DEACTIVATING -> YolacButtonView.UiState.TRANSITION
                    YolacNative.STATE_ERROR -> YolacButtonView.UiState.ERROR
                    else -> YolacButtonView.UiState.INACTIVE
                }
            }
        }
    }

    override fun onResume() {
        super.onResume()
        YolacVpnService.syncStateFromNative()
    }

    private fun buildFirstLaunchSecurityOverlay(
        density: Float,
        onAcknowledge: () -> Unit,
    ): View {
        val pad = (28 * density).toInt()
        val overlay = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER
            setBackgroundColor(Color.BLACK)
            setPadding(pad, pad, pad, pad)
            isClickable = true
        }
        val boxBg = GradientDrawable().apply {
            setColor(Color.parseColor("#110707"))
            setStroke((1.5f * density).toInt(), Color.parseColor("#8A2E2E"))
            cornerRadius = 10f * density
        }
        val msg = TextView(this).apply {
            text = YolacNative.SECURITY_WARNING_TR
            setTextColor(Color.WHITE)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 14.5f)
            val mp = (18 * density).toInt()
            setPadding(mp, mp, mp, mp)
            background = boxBg
        }
        val okBg = GradientDrawable().apply {
            setColor(Color.WHITE)
            cornerRadius = 8f * density
        }
        val okBtn = Button(this).apply {
            text = "Anladım"
            isAllCaps = false
            setTextColor(Color.BLACK)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 14f)
            background = okBg
            setOnClickListener {
                onAcknowledge()
                (overlay.parent as? FrameLayout)?.removeView(overlay)
            }
        }
        overlay.addView(
            msg,
            LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT,
            ),
        )
        overlay.addView(
            okBtn,
            LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                (48 * density).toInt(),
            ).apply {
                topMargin = (20 * density).toInt()
            },
        )
        return overlay
    }

    private fun onToggleClicked() {
        val current = YolacVpnService.stateFlow.value
        if (current == YolacNative.STATE_ACTIVATING || current == YolacNative.STATE_DEACTIVATING) {
            return
        }
        if (current == YolacNative.STATE_ACTIVE) {
            val stopIntent = Intent(this, YolacVpnService::class.java).apply {
                action = YolacVpnService.ACTION_STOP
            }
            startService(stopIntent)
            return
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
            != PackageManager.PERMISSION_GRANTED
        ) {
            notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
        } else {
            requestVpnConsentAndStart()
        }
    }

    private fun requestVpnConsentAndStart() {
        val prepareIntent = VpnService.prepare(this)
        if (prepareIntent != null) {
            vpnPermissionLauncher.launch(prepareIntent)
        } else {
            startVpnService()
        }
    }

    private fun startVpnService() {
        val startIntent = Intent(this, YolacVpnService::class.java).apply {
            action = YolacVpnService.ACTION_START
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(startIntent)
        } else {
            startService(startIntent)
        }
    }
}

private class SettingsGearView(context: Context) : View(context) {
    private val density = resources.displayMetrics.density
    private val paint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = Color.parseColor("#7A7A7A")
        style = Paint.Style.STROKE
        strokeWidth = 1.8f * density
        strokeCap = Paint.Cap.ROUND
    }

    init {
        isClickable = true
        isFocusable = true
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        val cx = width / 2f
        val cy = height / 2f
        val outerR = 9f * density
        val innerR = 4.2f * density
        canvas.drawCircle(cx, cy, innerR, paint)
        canvas.drawCircle(cx, cy, outerR * 0.78f, paint)
        for (i in 0 until 8) {
            val rad = Math.toRadians(i * 45.0)
            val x1 = cx + (outerR * 0.78f * cos(rad)).toFloat()
            val y1 = cy + (outerR * 0.78f * sin(rad)).toFloat()
            val x2 = cx + (outerR * 1.12f * cos(rad)).toFloat()
            val y2 = cy + (outerR * 1.12f * sin(rad)).toFloat()
            canvas.drawLine(x1, y1, x2, y2, paint)
        }
    }
}
