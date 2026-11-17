package org.creamote.android.host

import android.app.admin.DeviceAdminReceiver
import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.util.Log

/** Récepteur d'administration de l'appareil, exigé par Knox pour la licence. */
class AdminReceiver : DeviceAdminReceiver()

/**
 * Activation de la licence Samsung Knox (KPE) qui débloque l'injection
 * directe ([KnoxInjector]). La clé est fournie par l'administrateur du parc
 * (portail Samsung Knox) ; Samsung la vérifie en ligne.
 */
object KnoxLicense {
    private const val TAG = "creamote"

    fun admin(context: Context) = ComponentName(context, AdminReceiver::class.java)

    fun isAdmin(context: Context): Boolean =
        context.getSystemService(DevicePolicyManager::class.java).isAdminActive(admin(context))

    /** Écran système demandant à l'utilisateur d'accorder l'administration. */
    fun requestAdmin(context: Context, explanation: String): Intent =
        Intent(DevicePolicyManager.ACTION_ADD_DEVICE_ADMIN)
            .putExtra(DevicePolicyManager.EXTRA_DEVICE_ADMIN, admin(context))
            .putExtra(DevicePolicyManager.EXTRA_ADD_EXPLANATION, explanation)

    val available: Boolean
        get() = runCatching { Class.forName("com.samsung.android.knox.license.KnoxEnterpriseLicenseManager") }.isSuccess

    /**
     * Demande l'activation ; le résultat arrive par la diffusion
     * `com.samsung.android.knox.intent.action.LICENSE_STATUS`. `false` si
     * Knox est absent ou refuse l'appel.
     */
    fun activate(context: Context, key: String): Boolean = try {
        val cls = Class.forName("com.samsung.android.knox.license.KnoxEnterpriseLicenseManager")
        val klm = cls.getMethod("getInstance", Context::class.java).invoke(null, context.applicationContext)
        cls.getMethod("activateLicense", String::class.java).invoke(klm, key.trim())
        true
    } catch (e: Exception) {
        Log.w(TAG, "licence Knox : ${e.cause ?: e}")
        false
    }
}
