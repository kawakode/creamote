package org.creamote.android

/**
 * Caractères du clavier logiciel → touches physiques (usages HID) d'un
 * clavier QWERTY US, avec ou sans Maj.
 *
 * Le protocole transmet des touches physiques, interprétées selon la
 * disposition du host (comme un clavier branché) : le texte n'est fidèle
 * que si le host est en disposition US. Les caractères sans touche
 * (accents, emoji) sont ignorés.
 */
object TextKeys {
    const val SHIFT = 0xE1
    const val CTRL = 0xE0
    const val ALT = 0xE2
    const val META = 0xE3
    const val ENTER = 0x28
    const val ESCAPE = 0x29
    const val BACKSPACE = 0x2A
    const val TAB = 0x2B
    const val DELETE = 0x4C

    data class Stroke(val hid: Int, val shift: Boolean)

    private val table: Map<Char, Stroke> = buildMap {
        for (c in 'a'..'z') put(c, Stroke(0x04 + (c - 'a'), false))
        for (c in 'A'..'Z') put(c, Stroke(0x04 + (c - 'A'), true))
        "1234567890".forEachIndexed { i, c -> put(c, Stroke(0x1E + i, false)) }
        "!@#$%^&*()".forEachIndexed { i, c -> put(c, Stroke(0x1E + i, true)) }
        put('\n', Stroke(ENTER, false))
        put('\t', Stroke(TAB, false))
        put(' ', Stroke(0x2C, false))
        val pairs = listOf(
            Triple('-', '_', 0x2D), Triple('=', '+', 0x2E), Triple('[', '{', 0x2F),
            Triple(']', '}', 0x30), Triple('\\', '|', 0x31), Triple(';', ':', 0x33),
            Triple('\'', '"', 0x34), Triple('`', '~', 0x35), Triple(',', '<', 0x36),
            Triple('.', '>', 0x37), Triple('/', '?', 0x38),
        )
        for ((plain, shifted, hid) in pairs) {
            put(plain, Stroke(hid, false))
            put(shifted, Stroke(hid, true))
        }
    }

    fun stroke(c: Char): Stroke? = table[c]
}
