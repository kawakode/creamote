package org.creamote.android.host

/**
 * Suit le bouton « toucher » du viewer et produit les gestes à rejouer :
 * un geste par appui, du point de départ au relâchement, avec sa durée.
 * Pure logique (testée sur la JVM).
 */
class TouchPath(private val maxPoints: Int = 64) {
    data class Gesture(val points: List<Pair<Float, Float>>, val durationMs: Long)

    private var points = mutableListOf<Pair<Float, Float>>()
    private var startMs = 0L
    private var down = false

    val isDown get() = down

    /** Rend le geste terminé, s'il y en a un. */
    fun update(x: Float, y: Float, pressed: Boolean, nowMs: Long): Gesture? {
        if (pressed && !down) {
            down = true
            startMs = nowMs
            points = mutableListOf(x to y)
            return null
        }
        if (pressed) {
            if (points.last() != (x to y) && points.size < maxPoints) points += x to y
            return null
        }
        if (!down) return null
        down = false
        if (points.last() != (x to y)) points += x to y
        // Durée minimale d'un toucher ; au-delà de 10 s, Android refuse.
        val duration = (nowMs - startMs).coerceIn(1, 10_000)
        return Gesture(points.toList(), duration)
    }

    fun reset() {
        down = false
        points.clear()
    }
}
