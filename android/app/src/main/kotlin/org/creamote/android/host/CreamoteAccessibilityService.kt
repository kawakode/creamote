package org.creamote.android.host

import android.accessibilityservice.AccessibilityService
import android.view.accessibility.AccessibilityEvent

/**
 * Service d'accessibilité déclaré par l'app : seul moyen standard
 * d'injecter des gestes et du texte sur Android sans privilèges système.
 * Il ne consulte que le champ de saisie actif (texte reçu du viewer).
 */
class CreamoteAccessibilityService : AccessibilityService() {
    override fun onServiceConnected() {
        instance = this
    }

    override fun onUnbind(intent: android.content.Intent?): Boolean {
        instance = null
        return super.onUnbind(intent)
    }

    override fun onAccessibilityEvent(event: AccessibilityEvent?) {}

    override fun onInterrupt() {}

    companion object {
        @Volatile var instance: CreamoteAccessibilityService? = null
            private set

        val enabled get() = instance != null
    }
}
