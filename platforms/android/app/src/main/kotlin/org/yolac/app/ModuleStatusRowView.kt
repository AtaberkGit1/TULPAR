package org.yolac.app

import android.content.Context
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.Path
import android.graphics.RectF
import android.view.Gravity
import android.view.View
import android.widget.HorizontalScrollView
import android.widget.LinearLayout
import kotlin.math.cos
import kotlin.math.sin

data class ModuleHealthItem(
    val id: Int,
    val name: String,
    val status: Int, // 0 = Gray (passive/unchecked), 1 = Green (healthy), 2 = Red (error)
    val detail: String,
)

/**
 * Single non-wrapping horizontal row of 7 minimalist module status icons.
 * Uses START child gravity + centered LinearLayout with isFillViewport=true so narrow screens
 * scroll smoothly without clipping the leftmost icon, while wide screens center cleanly.
 */
class ModuleStatusRowView(
    context: Context,
    private val onSelect: (ModuleHealthItem) -> Unit,
) : HorizontalScrollView(context) {

    private val density = resources.displayMetrics.density
    private val row = LinearLayout(context).apply {
        orientation = LinearLayout.HORIZONTAL
        gravity = Gravity.CENTER_VERTICAL or Gravity.CENTER_HORIZONTAL
        val pad = (8 * density).toInt()
        setPadding(pad, pad, pad, pad)
    }

    private var items: List<ModuleHealthItem> = emptyList()
    private var selectedId: Int? = null
    private val iconViews = mutableListOf<ModuleIconCell>()

    init {
        isHorizontalScrollBarEnabled = false
        isFillViewport = true
        setBackgroundColor(Color.BLACK)
        addView(
            row,
            LayoutParams(LayoutParams.WRAP_CONTENT, LayoutParams.WRAP_CONTENT).apply {
                gravity = Gravity.START
            },
        )
    }

    fun setSelectedModuleId(id: Int?) {
        selectedId = id
        refreshSelection()
    }

    fun updateModules(newItems: List<ModuleHealthItem>) {
        items = newItems
        if (iconViews.size != newItems.size) {
            row.removeAllViews()
            iconViews.clear()
            val sizePx = (48 * density).toInt()
            val marginPx = (5 * density).toInt()
            for (item in newItems) {
                val cell = ModuleIconCell(context, item.id).apply {
                    contentDescription = "${item.name}: ${item.detail}"
                    setOnClickListener {
                        selectedId = item.id
                        refreshSelection()
                        items.find { it.id == item.id }?.let(onSelect)
                    }
                }
                val lp = LinearLayout.LayoutParams(sizePx, sizePx).apply {
                    marginStart = marginPx
                    marginEnd = marginPx
                }
                row.addView(cell, lp)
                iconViews.add(cell)
            }
        }
        for (i in newItems.indices) {
            val item = newItems[i]
            val view = iconViews[i]
            view.status = item.status
            view.isSelectedCell = (selectedId == item.id)
            view.contentDescription = "${item.name}: ${item.detail}"
            view.invalidate()
        }
    }

    private fun refreshSelection() {
        for (i in items.indices) {
            if (i < iconViews.size) {
                iconViews[i].isSelectedCell = (selectedId == items[i].id)
                iconViews[i].invalidate()
            }
        }
    }
}

private class ModuleIconCell(
    context: Context,
    private val moduleId: Int,
) : View(context) {

    var status: Int = 0
    var isSelectedCell: Boolean = false

    private val density = resources.displayMetrics.density
    private val strokePaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeCap = Paint.Cap.ROUND
        strokeJoin = Paint.Join.ROUND
    }
    private val ringPaint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        style = Paint.Style.STROKE
        strokeWidth = 1.5f * density
    }
    private val rect = RectF()
    private val path = Path()

    init {
        isClickable = true
        isFocusable = true
        setBackgroundColor(Color.BLACK)
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        val cx = width / 2f
        val cy = height / 2f
        val radius = (minOf(width, height) / 2f) - 2f * density

        val color = when (status) {
            1 -> Color.parseColor("#2ECC71")
            2 -> Color.parseColor("#E74C3C")
            else -> Color.parseColor("#6E6E6E")
        }

        ringPaint.color = if (isSelectedCell) Color.WHITE else Color.parseColor("#262626")
        canvas.drawCircle(cx, cy, radius, ringPaint)

        strokePaint.color = color
        strokePaint.strokeWidth = 2f * density
        val r = radius * 0.44f
        path.reset()

        when (moduleId) {
            0 -> {
                path.moveTo(cx, cy - r)
                path.lineTo(cx + r * 0.85f, cy - r * 0.55f)
                path.lineTo(cx + r * 0.72f, cy + r * 0.35f)
                path.lineTo(cx, cy + r)
                path.lineTo(cx - r * 0.72f, cy + r * 0.35f)
                path.lineTo(cx - r * 0.85f, cy - r * 0.55f)
                path.close()
                canvas.drawPath(path, strokePaint)
            }
            1 -> {
                canvas.drawCircle(cx, cy, r, strokePaint)
                canvas.drawLine(cx - r, cy, cx + r, cy, strokePaint)
                rect.set(cx - r * 0.48f, cy - r, cx + r * 0.48f, cy + r)
                canvas.drawOval(rect, strokePaint)
            }
            2 -> {
                canvas.drawCircle(cx, cy, r, strokePaint)
                val d = r * 0.70f
                canvas.drawLine(cx - d, cy - d, cx + d, cy + d, strokePaint)
            }
            3 -> {
                canvas.drawLine(cx - r, cy, cx - r * 0.15f, cy, strokePaint)
                canvas.drawLine(cx - r * 0.15f, cy, cx + r * 0.85f, cy - r * 0.65f, strokePaint)
                canvas.drawLine(cx - r * 0.15f, cy, cx + r * 0.85f, cy + r * 0.65f, strokePaint)
            }
            4 -> {
                rect.set(cx - r * 0.75f, cy - r * 0.1f, cx + r * 0.75f, cy + r * 0.9f)
                canvas.drawRoundRect(rect, 2f * density, 2f * density, strokePaint)
                rect.set(cx - r * 0.45f, cy - r * 0.9f, cx + r * 0.45f, cy + r * 0.1f)
                canvas.drawArc(rect, 180f, 180f, false, strokePaint)
            }
            5 -> {
                path.moveTo(cx + r * 0.15f, cy - r)
                path.lineTo(cx - r * 0.6f, cy + r * 0.05f)
                path.lineTo(cx + r * 0.05f, cy + r * 0.05f)
                path.lineTo(cx - r * 0.15f, cy + r)
                path.lineTo(cx + r * 0.6f, cy - r * 0.05f)
                path.lineTo(cx - r * 0.05f, cy - r * 0.05f)
                path.close()
                canvas.drawPath(path, strokePaint)
            }
            else -> {
                rect.set(cx - r * 0.85f, cy - r * 0.85f, cx + r * 0.85f, cy + r * 0.85f)
                canvas.drawArc(rect, -40f, 290f, false, strokePaint)
                val ax = cx + (r * 0.85f * cos(Math.toRadians(-40.0))).toFloat()
                val ay = cy + (r * 0.85f * sin(Math.toRadians(-40.0))).toFloat()
                canvas.drawLine(ax, ay, ax - r * 0.45f, ay - r * 0.12f, strokePaint)
                canvas.drawLine(ax, ay, ax + r * 0.05f, ay - r * 0.48f, strokePaint)
            }
        }
    }
}
