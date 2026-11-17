package org.creamote.android.host

import android.content.Intent
import org.creamote.core.ConsentAnswer
import org.creamote.core.ConsentRequest
import java.util.concurrent.CompletableFuture

/**
 * État partagé entre le service du host, la demande de consentement et
 * l'écran d'accueil (même processus).
 */
object HostController {
    /** Autorisation MediaProjection accordée pour la session à venir. */
    data class ProjectionGrant(val resultCode: Int, val data: Intent)

    class PendingConsent(val request: ConsentRequest) {
        val answer = CompletableFuture<ConsentAnswer>()
    }

    @Volatile var pending: PendingConsent? = null
    @Volatile private var grant: ProjectionGrant? = null

    /** Dernier état affichable du host, et ses observateurs (thread principal). */
    @Volatile var status: String = ""
        private set
    @Volatile var running = false
        private set
    private val listeners = mutableSetOf<() -> Unit>()

    fun grantProjection(g: ProjectionGrant) {
        grant = g
    }

    /** L'autorisation ne sert qu'une fois (jeton à usage unique depuis Android 14). */
    fun takeProjection(): ProjectionGrant? = grant.also { grant = null }

    @Synchronized
    fun setStatus(text: String, running: Boolean) {
        this.status = text
        this.running = running
        listeners.toList().forEach { it() }
    }

    @Synchronized
    fun observe(listener: () -> Unit) {
        listeners += listener
    }

    @Synchronized
    fun forget(listener: () -> Unit) {
        listeners -= listener
    }
}
