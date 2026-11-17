package org.creamote.android.host

import android.accessibilityservice.AccessibilityService
import android.accessibilityservice.GestureDescription
import android.graphics.Path
import android.os.Build
import android.os.Bundle
import android.os.SystemClock
import android.view.KeyCharacterMap
import android.view.KeyEvent
import android.view.WindowManager
import android.view.accessibility.AccessibilityNodeInfo

/**
 * Injection par le service d'accessibilité de Creamote (activé par
 * l'utilisateur dans les réglages) :
 *
 * - toucher : geste `dispatchGesture` rejoué au relâchement (tap, appui
 *   long, glisser) ;
 * - molette : balayage ; bouton droit : retour ; bouton du milieu : accueil ;
 * - clavier : `sendKeyEvent` par l'éditeur d'accessibilité (Android 13+),
 *   sinon texte ajouté au champ qui a le focus, Entrée, Retour arrière,
 *   Échap (retour).
 */
class AccessibilityInjector(private val service: AccessibilityService) : Injector {
    override val name = "service d'accessibilité"
    private val touch = TouchPath()
    private var buttons = 0
    private var meta = 0
    private val chars = KeyCharacterMap.load(KeyCharacterMap.VIRTUAL_KEYBOARD)

    private fun screenSize(): Pair<Float, Float> {
        val wm = service.getSystemService(WindowManager::class.java)
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

    override fun pointer(x: Float, y: Float, buttons: Int, wheelDx: Float, wheelDy: Float) {
        val (w, h) = screenSize()
        val px = (x * w).coerceIn(0f, w - 1)
        val py = (y * h).coerceIn(0f, h - 1)
        touch.update(px, py, buttons and 1 != 0, SystemClock.uptimeMillis())?.let(::dispatch)
        val pressed = buttons and this.buttons.inv()
        if (pressed and 2 != 0) service.performGlobalAction(AccessibilityService.GLOBAL_ACTION_BACK)
        if (pressed and 4 != 0) service.performGlobalAction(AccessibilityService.GLOBAL_ACTION_HOME)
        this.buttons = buttons
        if (wheelDy != 0f || wheelDx != 0f) {
            // Un cran ≈ 12 % de l'écran ; molette vers le bas → doigt vers le haut.
            val dy = (-wheelDy * 0.12f * h).coerceIn(-h / 2, h / 2)
            val dx = (-wheelDx * 0.12f * w).coerceIn(-w / 2, w / 2)
            val to = (px + dx).coerceIn(0f, w - 1) to (py + dy).coerceIn(0f, h - 1)
            dispatch(TouchPath.Gesture(listOf(px to py, to), 120))
        }
    }

    private fun dispatch(g: TouchPath.Gesture) {
        val path = Path().apply {
            moveTo(g.points.first().first, g.points.first().second)
            g.points.drop(1).forEach { (x, y) -> lineTo(x, y) }
        }
        val stroke = GestureDescription.StrokeDescription(path, 0, g.durationMs)
        service.dispatchGesture(GestureDescription.Builder().addStroke(stroke).build(), null, null)
    }

    override fun key(keycode: Int, pressed: Boolean) {
        val modifier = when (keycode) {
            KeyEvent.KEYCODE_SHIFT_LEFT, KeyEvent.KEYCODE_SHIFT_RIGHT -> KeyEvent.META_SHIFT_ON
            KeyEvent.KEYCODE_CTRL_LEFT, KeyEvent.KEYCODE_CTRL_RIGHT -> KeyEvent.META_CTRL_ON
            KeyEvent.KEYCODE_ALT_LEFT, KeyEvent.KEYCODE_ALT_RIGHT -> KeyEvent.META_ALT_ON
            KeyEvent.KEYCODE_META_LEFT, KeyEvent.KEYCODE_META_RIGHT -> KeyEvent.META_META_ON
            else -> 0
        }
        if (modifier != 0) {
            meta = if (pressed) meta or modifier else meta and modifier.inv()
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU && sendThroughIme(keycode, pressed)) return
        if (!pressed || modifier != 0) return
        when (keycode) {
            KeyEvent.KEYCODE_ESCAPE -> service.performGlobalAction(AccessibilityService.GLOBAL_ACTION_BACK)
            KeyEvent.KEYCODE_META_LEFT, KeyEvent.KEYCODE_META_RIGHT ->
                service.performGlobalAction(AccessibilityService.GLOBAL_ACTION_HOME)
            KeyEvent.KEYCODE_DEL -> editFocused { it.dropLast(1) }
            KeyEvent.KEYCODE_ENTER, KeyEvent.KEYCODE_NUMPAD_ENTER -> imeEnter()
            else -> {
                val c = chars.get(keycode, meta and KeyEvent.META_SHIFT_ON)
                if (c > 0) editFocused { it + c.toChar() }
            }
        }
    }

    private fun sendThroughIme(keycode: Int, pressed: Boolean): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return false
        val ic = service.inputMethod?.currentInputConnection ?: return false
        val now = SystemClock.uptimeMillis()
        val action = if (pressed) KeyEvent.ACTION_DOWN else KeyEvent.ACTION_UP
        ic.sendKeyEvent(KeyEvent(now, now, action, keycode, 0, meta))
        return true
    }

    private fun editFocused(change: (String) -> String) {
        val node = service.findFocus(AccessibilityNodeInfo.FOCUS_INPUT) ?: return
        if (!node.isEditable) return
        // Texte affiché quand le champ est vide (indice) : ne pas le reprendre.
        val current = if (node.isShowingHintText) "" else node.text?.toString().orEmpty()
        val args = Bundle().apply {
            putCharSequence(AccessibilityNodeInfo.ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE, change(current))
        }
        node.performAction(AccessibilityNodeInfo.ACTION_SET_TEXT, args)
    }

    private fun imeEnter() {
        val node = service.findFocus(AccessibilityNodeInfo.FOCUS_INPUT) ?: return
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            node.performAction(AccessibilityNodeInfo.AccessibilityAction.ACTION_IME_ENTER.id)
        } else {
            editFocused { it + "\n" }
        }
    }

    override fun releaseAll() {
        // Un geste non relâché n'a pas encore été rejoué : on l'abandonne.
        touch.reset()
        buttons = 0
        meta = 0
    }
}
