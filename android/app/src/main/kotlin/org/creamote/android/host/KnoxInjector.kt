package org.creamote.android.host

import android.content.Context
import android.os.Build
import android.os.SystemClock
import android.util.Log
import android.view.InputDevice
import android.view.KeyEvent
import android.view.MotionEvent
import android.view.WindowManager

/**
 * Injection par l'API constructeur Samsung Knox (`RemoteInjection`) :
 * vrais événements tactiles et touches système (retour, accueil, applis
 * récentes), glisser en direct, sans service d'accessibilité.
 *
 * Disponible sur les appareils Samsung avec Knox, quand l'app est
 * administrateur de l'appareil, que la licence Knox (KPE) est activée et
 * que la permission `KNOX_REMOTE_CONTROL` est accordée. Le SDK Knox n'est
 * pas embarqué (licence Samsung) : ses classes sont appelées par réflexion
 * et l'injecteur n'est proposé que si elles répondent.
 */
class KnoxInjector private constructor(
    private val context: Context,
    private val remote: Any,
) : Injector {
    override val name = "Samsung Knox"
    private val injectPointer = remote.javaClass.getMethod(
        "injectPointerEvent", MotionEvent::class.java, Boolean::class.javaPrimitiveType,
    )
    private val injectKey = remote.javaClass.getMethod(
        "injectKeyEvent", KeyEvent::class.java, Boolean::class.javaPrimitiveType,
    )
    private var buttons = 0
    private var downTime = 0L
    private var meta = 0

    private fun screen(): Pair<Float, Float> {
        val wm = context.getSystemService(WindowManager::class.java)
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            val b = wm.maximumWindowMetrics.bounds
            b.width().toFloat() to b.height().toFloat()
        } else {
            val p = android.graphics.Point()
            @Suppress("DEPRECATION")
            wm.defaultDisplay.getRealSize(p)
            p.x.toFloat() to p.y.toFloat()
        }
    }

    private fun touch(action: Int, x: Float, y: Float, at: Long = SystemClock.uptimeMillis()) {
        val ev = MotionEvent.obtain(downTime, at, action, x, y, 0)
        ev.source = InputDevice.SOURCE_TOUCHSCREEN
        try {
            injectPointer.invoke(remote, ev, true)
        } catch (e: Exception) {
            Log.w(TAG, "Knox injectPointerEvent : ${e.cause ?: e}")
        } finally {
            ev.recycle()
        }
    }

    private fun systemKey(keycode: Int, pressed: Boolean) {
        val now = SystemClock.uptimeMillis()
        val ev = KeyEvent(now, now, if (pressed) KeyEvent.ACTION_DOWN else KeyEvent.ACTION_UP, keycode, 0, meta)
        try {
            injectKey.invoke(remote, ev, true)
        } catch (e: Exception) {
            Log.w(TAG, "Knox injectKeyEvent : ${e.cause ?: e}")
        }
    }

    override fun pointer(x: Float, y: Float, buttons: Int, wheelDx: Float, wheelDy: Float) {
        val (w, h) = screen()
        val px = (x * w).coerceIn(0f, w - 1)
        val py = (y * h).coerceIn(0f, h - 1)
        val was = this.buttons and 1 != 0
        val now = buttons and 1 != 0
        when {
            now && !was -> {
                downTime = SystemClock.uptimeMillis()
                touch(MotionEvent.ACTION_DOWN, px, py, downTime)
            }
            now && was -> touch(MotionEvent.ACTION_MOVE, px, py)
            !now && was -> touch(MotionEvent.ACTION_UP, px, py)
        }
        val pressed = buttons and this.buttons.inv()
        if (pressed and 2 != 0) tapKey(KeyEvent.KEYCODE_BACK)
        if (pressed and 4 != 0) tapKey(KeyEvent.KEYCODE_HOME)
        this.buttons = buttons
        if ((wheelDy != 0f || wheelDx != 0f) && !now) {
            // Molette : court balayage, doigt dans le sens inverse.
            val toX = (px - wheelDx * 0.12f * w).coerceIn(0f, w - 1)
            val toY = (py - wheelDy * 0.12f * h).coerceIn(0f, h - 1)
            downTime = SystemClock.uptimeMillis()
            touch(MotionEvent.ACTION_DOWN, px, py, downTime)
            for (i in 1..5) {
                val f = i / 5f
                touch(MotionEvent.ACTION_MOVE, px + (toX - px) * f, py + (toY - py) * f, downTime + i * 16L)
            }
            touch(MotionEvent.ACTION_UP, toX, toY, downTime + 100)
        }
    }

    private fun tapKey(keycode: Int) {
        systemKey(keycode, true)
        systemKey(keycode, false)
    }

    override fun key(keycode: Int, pressed: Boolean) {
        val modifier = when (keycode) {
            KeyEvent.KEYCODE_SHIFT_LEFT, KeyEvent.KEYCODE_SHIFT_RIGHT -> KeyEvent.META_SHIFT_ON
            KeyEvent.KEYCODE_CTRL_LEFT, KeyEvent.KEYCODE_CTRL_RIGHT -> KeyEvent.META_CTRL_ON
            KeyEvent.KEYCODE_ALT_LEFT, KeyEvent.KEYCODE_ALT_RIGHT -> KeyEvent.META_ALT_ON
            KeyEvent.KEYCODE_META_LEFT, KeyEvent.KEYCODE_META_RIGHT -> KeyEvent.META_META_ON
            else -> 0
        }
        if (modifier != 0) meta = if (pressed) meta or modifier else meta and modifier.inv()
        // Échap → retour, comme sur un clavier branché à un téléphone.
        systemKey(if (keycode == KeyEvent.KEYCODE_ESCAPE) KeyEvent.KEYCODE_BACK else keycode, pressed)
    }

    override fun releaseAll() {
        if (buttons and 1 != 0) {
            val (w, h) = screen()
            touch(MotionEvent.ACTION_CANCEL, w / 2, h / 2)
        }
        buttons = 0
        meta = 0
    }

    companion object {
        private const val TAG = "creamote"
        const val PERMISSION = "com.samsung.android.knox.permission.KNOX_REMOTE_CONTROL"

        /** Injecteur Knox si l'API répond sur cet appareil, sinon `null`. */
        fun open(context: Context): KnoxInjector? {
            if (!Build.MANUFACTURER.equals("samsung", ignoreCase = true)) return null
            if (context.checkSelfPermission(PERMISSION) != android.content.pm.PackageManager.PERMISSION_GRANTED) {
                return null
            }
            return try {
                val edmClass = Class.forName("com.samsung.android.knox.EnterpriseDeviceManager")
                val edm = edmClass.getMethod("getInstance", Context::class.java).invoke(null, context)
                val remote = edmClass.getMethod("getRemoteInjection").invoke(edm) ?: return null
                KnoxInjector(context, remote)
            } catch (e: ReflectiveOperationException) {
                null
            } catch (e: SecurityException) {
                Log.i(TAG, "Knox indisponible : ${e.message}")
                null
            }
        }
    }
}
