package org.creamote.android

import android.app.Application
import android.content.Context
import android.util.Log
import org.creamote.core.Identity
import org.creamote.core.LogSink
import org.creamote.core.initLogging
import java.io.File

/** Identité de l'appareil et journal du cœur Rust, partagés par toute l'app. */
class CreamoteApp : Application() {
    lateinit var identity: Identity
        private set
    lateinit var settings: Settings
        private set

    override fun onCreate() {
        super.onCreate()
        initLogging(Logcat, if (BuildConfig.DEBUG) "debug" else "info")
        // Fichier privé de l'app (0600), exclu des sauvegardes.
        identity = Identity.loadOrCreate(File(filesDir, "device.identity").path)
        settings = Settings(this)
    }

    companion object {
        fun of(context: Context): CreamoteApp = context.applicationContext as CreamoteApp
    }
}

/** Journal Rust → logcat (étiquette « creamote »). */
private object Logcat : LogSink {
    override fun log(level: UByte, message: String) {
        val priority = when (level.toInt()) {
            0 -> Log.VERBOSE
            1 -> Log.DEBUG
            2 -> Log.INFO
            3 -> Log.WARN
            else -> Log.ERROR
        }
        Log.println(priority, "creamote", message)
    }
}
