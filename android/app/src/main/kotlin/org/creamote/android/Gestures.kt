package org.creamote.android

import kotlin.math.abs
import kotlin.math.hypot

/**
 * Gestes tactiles → souris du poste distant (coordonnées en pixels de la
 * vue, normalisées par l'appelant).
 *
 * - toucher bref : clic gauche ;
 * - appui long sans bouger : clic droit ;
 * - glisser : bouton gauche enfoncé (sélection, glisser-déposer) ;
 * - deux doigts : molette, dans le sens du doigt (comme un pavé tactile).
 */
class Gestures(private val slopPx: Float, private val wheelStepPx: Float) {
    /** Position, boutons (bit 0 gauche, 1 droit), crans de molette. */
    data class Out(val x: Float, val y: Float, val buttons: Int, val wheelDy: Float, val wheelDx: Float = 0f)

    private enum class State { IDLE, PENDING, DRAGGING, DONE, SCROLLING }

    private var state = State.IDLE
    private var downX = 0f
    private var downY = 0f
    private var lastX = 0f
    private var lastY = 0f

    fun down(x: Float, y: Float): List<Out> {
        state = State.PENDING
        downX = x
        downY = y
        return emptyList()
    }

    fun move(x: Float, y: Float): List<Out> = when (state) {
        State.PENDING -> if (hypot(x - downX, y - downY) > slopPx) {
            state = State.DRAGGING
            listOf(Out(downX, downY, 1, 0f), Out(x, y, 1, 0f))
        } else {
            emptyList()
        }
        State.DRAGGING -> listOf(Out(x, y, 1, 0f))
        else -> emptyList()
    }

    fun up(x: Float, y: Float): List<Out> {
        val out = when (state) {
            State.PENDING -> listOf(Out(x, y, 1, 0f), Out(x, y, 0, 0f))
            State.DRAGGING -> listOf(Out(x, y, 0, 0f))
            else -> emptyList()
        }
        state = State.IDLE
        return out
    }

    /** Appelé quand le doigt est resté immobile assez longtemps. */
    fun longPress(): List<Out> {
        if (state != State.PENDING) return emptyList()
        state = State.DONE
        return listOf(Out(downX, downY, 2, 0f), Out(downX, downY, 0, 0f))
    }

    /** Un deuxième doigt se pose : `x`, `y` = milieu des deux doigts. */
    fun secondFinger(x: Float, y: Float): List<Out> {
        val out = if (state == State.DRAGGING) listOf(Out(x, y, 0, 0f)) else emptyList()
        state = State.SCROLLING
        lastX = x
        lastY = y
        return out
    }

    fun scroll(x: Float, y: Float): List<Out> {
        if (state != State.SCROLLING) return emptyList()
        // Doigts vers le haut → contenu vers le haut → molette vers le bas.
        val dy = (lastY - y) / wheelStepPx
        val dx = (lastX - x) / wheelStepPx
        if (abs(dy) < 0.25f && abs(dx) < 0.25f) return emptyList()
        lastX = x
        lastY = y
        return listOf(Out(x, y, 0, dy, dx))
    }

    fun cancel(x: Float, y: Float): List<Out> {
        val out = if (state == State.DRAGGING) listOf(Out(x, y, 0, 0f)) else emptyList()
        state = State.IDLE
        return out
    }
}
