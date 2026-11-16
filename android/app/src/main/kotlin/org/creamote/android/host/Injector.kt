package org.creamote.android.host

/**
 * Injection des entrées du viewer sur cet appareil. Coordonnées
 * normalisées [0, 1] sur l'écran ; boutons : bit 0 toucher, bit 1 retour,
 * bit 2 accueil.
 */
interface Injector {
    val name: String
    fun pointer(x: Float, y: Float, buttons: Int, wheelDx: Float, wheelDy: Float)
    /** `keycode` : `KeyEvent.KEYCODE_*` équivalent à la touche physique. */
    fun key(keycode: Int, pressed: Boolean)
    fun releaseAll()
}

/** Aucune injection disponible (service d'accessibilité désactivé). */
object NoInjector : Injector {
    override val name = "aucune"
    override fun pointer(x: Float, y: Float, buttons: Int, wheelDx: Float, wheelDy: Float) {}
    override fun key(keycode: Int, pressed: Boolean) {}
    override fun releaseAll() {}
}
