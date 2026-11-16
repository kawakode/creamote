package org.creamote.android

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class TextKeysTest {
    @Test
    fun usLayout() {
        assertEquals(TextKeys.Stroke(0x04, false), TextKeys.stroke('a'))
        assertEquals(TextKeys.Stroke(0x04, true), TextKeys.stroke('A'))
        assertEquals(TextKeys.Stroke(0x27, false), TextKeys.stroke('0'))
        assertEquals(TextKeys.Stroke(0x1F, true), TextKeys.stroke('@'))
        assertEquals(TextKeys.Stroke(0x38, true), TextKeys.stroke('?'))
        assertEquals(TextKeys.Stroke(TextKeys.ENTER, false), TextKeys.stroke('\n'))
        assertNull(TextKeys.stroke('é'))
    }

    @Test
    fun gestures() {
        val g = Gestures(slopPx = 10f, wheelStepPx = 40f)
        // Toucher bref : clic gauche à la position.
        assertEquals(emptyList(), g.down(0.5f, 0.5f))
        assertEquals(
            listOf(Gestures.Out(0.5f, 0.5f, 1, 0f), Gestures.Out(0.5f, 0.5f, 0, 0f)),
            g.up(0.5f, 0.5f),
        )
        // Appui long : clic droit.
        g.down(0.2f, 0.2f)
        assertEquals(
            listOf(Gestures.Out(0.2f, 0.2f, 2, 0f), Gestures.Out(0.2f, 0.2f, 0, 0f)),
            g.longPress(),
        )
        assertEquals(emptyList(), g.up(0.2f, 0.2f))
    }
}

class GesturesTest {
    @Test
    fun dragAndScroll() {
        val g = Gestures(slopPx = 10f, wheelStepPx = 40f)
        g.down(100f, 100f)
        // Sous le seuil : rien.
        assertEquals(emptyList(), g.move(105f, 100f))
        // Au-delà : bouton enfoncé au point de départ, puis glissé.
        assertEquals(
            listOf(Gestures.Out(100f, 100f, 1, 0f), Gestures.Out(130f, 100f, 1, 0f)),
            g.move(130f, 100f),
        )
        assertEquals(listOf(Gestures.Out(140f, 100f, 0, 0f)), g.up(140f, 100f))

        // Deux doigts qui montent de 40 px : un cran vers le bas.
        g.down(100f, 300f)
        assertEquals(emptyList(), g.secondFinger(100f, 300f))
        assertEquals(listOf(Gestures.Out(100f, 260f, 0, 1f)), g.scroll(100f, 260f))
        assertEquals(emptyList(), g.up(100f, 260f))
    }
}

class TouchPathTest {
    @Test
    fun tapAndSwipe() {
        val t = org.creamote.android.host.TouchPath()
        assertNull(t.update(10f, 10f, false, 0))
        assertNull(t.update(10f, 10f, true, 100))
        assertEquals(
            org.creamote.android.host.TouchPath.Gesture(listOf(10f to 10f), 50),
            t.update(10f, 10f, false, 150),
        )
        t.update(0f, 0f, true, 0)
        t.update(5f, 0f, true, 10)
        t.update(5f, 0f, true, 20)
        val g = t.update(9f, 0f, false, 30)!!
        assertEquals(listOf(0f to 0f, 5f to 0f, 9f to 0f), g.points)
        assertEquals(30, g.durationMs)
    }
}
