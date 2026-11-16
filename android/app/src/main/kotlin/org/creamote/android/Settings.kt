package org.creamote.android

import android.content.Context
import org.creamote.core.ServerConfig

/** Réglages de l'utilisateur (préférences privées de l'app). */
class Settings(context: Context) {
    private val prefs = context.getSharedPreferences("creamote", Context.MODE_PRIVATE)

    var serverAddress: String
        get() = prefs.getString("server_address", "") ?: ""
        set(v) = prefs.edit().putString("server_address", v.trim()).apply()

    var serverPin: String
        get() = prefs.getString("server_pin", "") ?: ""
        set(v) = prefs.edit().putString("server_pin", v.trim()).apply()

    var apiUrl: String
        get() = prefs.getString("api_url", "") ?: ""
        set(v) = prefs.edit().putString("api_url", v.trim()).apply()

    var apiToken: String
        get() = prefs.getString("api_token", "") ?: ""
        set(v) = prefs.edit().putString("api_token", v.trim()).apply()

    var lastTarget: String
        get() = prefs.getString("last_target", "") ?: ""
        set(v) = prefs.edit().putString("last_target", v.trim()).apply()

    /** Jeton d'enrôlement du host (effacé une fois utilisé). */
    var enrollToken: String
        get() = prefs.getString("enroll_token", "") ?: ""
        set(v) = prefs.edit().putString("enroll_token", v.trim()).apply()

    /** Nom de l'appareil dans le parc. */
    var deviceName: String
        get() = prefs.getString("device_name", "") ?: ""
        set(v) = prefs.edit().putString("device_name", v.trim()).apply()

    val server: ServerConfig?
        get() = if (serverAddress.isEmpty() || serverPin.isEmpty()) null else ServerConfig(serverAddress, serverPin)
}
