package org.yolac.app

import android.content.Context
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.RectF
import android.view.MotionEvent
import android.view.View
import kotlin.math.min

/**
 * Minimalist single centered circular toggle button matching docs/DESIGN_SPEC.md.
 * Restricts touch hit-testing to the circular button area so accidental background taps are ignored.
 */
class YolacButtonView(context: Context) : View(context) {

    enum class UiState {
        INACTIVE,
        TRANSITION,
        ACTIVE,
        ERROR,
    }

    var state: UiState = UiState.INACTIVE
        set(value) {
            if (field != value) {
                field = value
                updateContentDescription()
                invalidate()
            }
        }

    private val density = resources.displayMetrics.density
    private val fillPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.FILL
    }
    private val strokePaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeWidth = 2f * density
    }
    private val glyphPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeWidth = 3f * density
        strokeCap = Paint.Cap.ROUND
    }
    private val arcRect = RectF()
    private var trackingInsideCircle = false

    init {
        isClickable = true
        isFocusable = true
        setBackgroundColor(Color.BLACK)
        updateContentDescription()
    }

    private fun updateContentDescription() {
        contentDescription = when (state) {
            UiState.INACTIVE -> "TULPAR: Pasif. Korumayı açmak için dokunun."
            UiState.TRANSITION -> "TULPAR: İşlem yapılıyor."
            UiState.ACTIVE -> "TULPAR: Aktif. Korumayı kapatmak için dokunun."
            UiState.ERROR -> "TULPAR: Hata veya izin reddedildi. Tekrar deneyin."
        }
    }

    private fun buttonDiameterPx(): Float {
        val minDimDp = min(width, height) / density
        val targetDp = (minDimDp * 0.42f).coerceIn(160f, 220f)
        return targetDp * density
    }

    private fun isInsideButtonCircle(x: Float, y: Float): Boolean {
        val cx = width / 2f
        val cy = height / 2f
        val hitRadius = (buttonDiameterPx() / 2f) * 1.08f
        val dx = x - cx
        val dy = y - cy
        return (dx * dx + dy * dy) <= (hitRadius * hitRadius)
    }

    override fun onTouchEvent(event: MotionEvent): Boolean {
        when (event.actionMasked) {
            MotionEvent.ACTION_DOWN -> {
                if (!isInsideButtonCircle(event.x, event.y)) {
                    trackingInsideCircle = false
                    return false
                }
                trackingInsideCircle = true
                return true
            }
            MotionEvent.ACTION_UP -> {
                val fire = trackingInsideCircle && isInsideButtonCircle(event.x, event.y)
                trackingInsideCircle = false
                if (fire) {
                    performClick()
                }
                return fire
            }
            MotionEvent.ACTION_CANCEL -> {
                trackingInsideCircle = false
                return false
            }
        }
        return super.onTouchEvent(event)
    }

    override fun performClick(): Boolean {
        return super.performClick()
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        canvas.drawColor(Color.BLACK)

        if (width == 0 || height == 0) return

        val cx = width / 2f
        val cy = height / 2f
        val diameter = buttonDiameterPx()
        val radius = diameter / 2f

        val (fillColor, strokeColor, glyphColor) = when (state) {
            UiState.INACTIVE -> Triple(Color.BLACK, Color.parseColor("#444444"), Color.parseColor("#7A7A7A"))
            UiState.TRANSITION -> Triple(Color.BLACK, Color.parseColor("#999999"), Color.parseColor("#CCCCCC"))
            UiState.ACTIVE -> Triple(Color.WHITE, Color.WHITE, Color.BLACK)
            UiState.ERROR -> Triple(Color.BLACK, Color.parseColor("#C93B3B"), Color.parseColor("#C93B3B"))
        }

        fillPaint.color = fillColor
        canvas.drawCircle(cx, cy, radius, fillPaint)

        if (state != UiState.ACTIVE) {
            strokePaint.color = strokeColor
            canvas.drawCircle(cx, cy, radius - strokePaint.strokeWidth / 2f, strokePaint)
        }

        // Minimal power/open-path glyph
        glyphPaint.color = glyphColor
        val glyphRadius = radius * 0.28f
        arcRect.set(cx - glyphRadius, cy - glyphRadius, cx + glyphRadius, cy + glyphRadius)
        canvas.drawArc(arcRect, -55f, 290f, false, glyphPaint)
        canvas.drawLine(cx, cy - glyphRadius * 1.15f, cx, cy - glyphRadius * 0.15f, glyphPaint)
    }
}
