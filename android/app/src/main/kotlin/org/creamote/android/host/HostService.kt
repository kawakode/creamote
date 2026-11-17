package org.creamote.android.host

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.hardware.display.DisplayManager
import android.media.projection.MediaProjection
import android.media.projection.MediaProjectionManager
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.util.Log
import android.view.WindowManager
import org.creamote.android.CreamoteApp
import org.creamote.android.MainActivity
import org.creamote.android.R
import org.creamote.core.ClipboardProvider
import org.creamote.core.ConsentAnswer
import org.creamote.core.ConsentRequest
import org.creamote.core.Display
import org.creamote.core.HostConfig
import org.creamote.core.HostDelegate
import org.creamote.core.HostStatus
import org.creamote.core.MobileException
import org.creamote.core.StreamInfo
import org.creamote.core.StreamRequest
import org.creamote.core.startHost
import java.io.File
import java.util.concurrent.TimeUnit
import kotlin.math.max
import kotlin.math.roundToInt
import org.creamote.core.HostService as CoreHost

/**
 * Service de premier plan du host : reste enregistré auprès du serveur,
 * demande le consentement, capture et encode l'écran pendant une session
 * et injecte les entrées.
 */
class HostService : Service(), HostDelegate {
    private val main = Handler(Looper.getMainLooper())
    @Volatile private var core: CoreHost? = null
    @Volatile private var encoder: ScreenEncoder? = null
    private var projection: MediaProjection? = null
    private var displayListener: DisplayManager.DisplayListener? = null
    private var injector: Injector = NoInjector
    private var injectorOwner: Any? = null
    private var destroyed = false

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopSelf()
            return START_NOT_STICKY
        }
        createChannels()
        HostController.setStatus(getString(R.string.host_starting), running = true)
        foreground(getString(R.string.host_starting), projection = false)
        if (core == null) {
            Thread(::startCore, "creamote-host-start").start()
        }
        return START_STICKY
    }

    private fun startCore() {
        val app = CreamoteApp.of(this)
        val s = app.settings
        val config = HostConfig(
            server = s.server,
            enrollmentPath = File(filesDir, "host.enrollment").path,
            enrollToken = s.enrollToken.ifEmpty { null },
            name = s.deviceName.ifEmpty { "${Build.MANUFACTURER} ${Build.MODEL}" },
            relayOnly = false,
            filesDir = null,
        )
        try {
            core = startHost(app.identity, config, this, AppClipboard(this))
            // Le jeton d'enrôlement ne sert qu'une fois.
            s.enrollToken = ""
        } catch (e: Exception) {
            val msg = (e as? MobileException)?.message ?: e.toString()
            HostController.setStatus(getString(R.string.error, msg), running = false)
            main.post { stopSelf() }
        }
    }

    override fun onDestroy() {
        destroyed = true
        releaseCapture()
        core?.stop()
        core = null
        HostController.setStatus(getString(R.string.host_stopped), running = false)
        super.onDestroy()
    }

    // --- Notification de premier plan ---

    private fun createChannels() {
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(
            NotificationChannel(CHANNEL_HOST, getString(R.string.channel_host), NotificationManager.IMPORTANCE_LOW),
        )
        nm.createNotificationChannel(
            NotificationChannel(CHANNEL_CONSENT, getString(R.string.channel_consent), NotificationManager.IMPORTANCE_HIGH),
        )
    }

    private fun foreground(text: String, projection: Boolean) {
        val open = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE,
        )
        val stop = PendingIntent.getService(
            this, 1, Intent(this, HostService::class.java).setAction(ACTION_STOP), PendingIntent.FLAG_IMMUTABLE,
        )
        val n = Notification.Builder(this, CHANNEL_HOST)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(getString(R.string.host_title))
            .setContentText(text)
            .setContentIntent(open)
            .setOngoing(true)
            .addAction(Notification.Action.Builder(null, getString(R.string.host_stop), stop).build())
            .build()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            var type = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
            } else {
                0
            }
            if (projection) type = type or ServiceInfo.FOREGROUND_SERVICE_TYPE_MEDIA_PROJECTION
            startForeground(NOTIFICATION_HOST, n, type)
        } else {
            startForeground(NOTIFICATION_HOST, n)
        }
    }

    // --- HostDelegate (threads du cœur) ---

    override fun onStatus(status: HostStatus) {
        val text = when (status) {
            is HostStatus.Online -> getString(R.string.host_online, core?.deviceId() ?: CreamoteApp.of(this).identity.deviceId())
            is HostStatus.Offline -> getString(R.string.host_offline, status.message, status.retrySeconds.toInt())
            is HostStatus.SessionStarted -> getString(
                R.string.host_session, status.userEmail ?: status.peerId, status.verificationCode,
            )
            is HostStatus.SessionEnded -> getString(R.string.host_session_ended)
            is HostStatus.Stopped -> getString(R.string.host_stopped)
        }
        HostController.setStatus(text, running = status !is HostStatus.Stopped)
        main.post {
            if (core != null || status !is HostStatus.Stopped) foreground(text, projection = encoder != null)
        }
    }

    override fun consent(request: ConsentRequest): ConsentAnswer {
        val pending = HostController.PendingConsent(request)
        HostController.pending = pending
        val intent = Intent(this, ConsentActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        val pi = PendingIntent.getActivity(this, 2, intent, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        val n = Notification.Builder(this, CHANNEL_CONSENT)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(getString(R.string.consent_title))
            .setContentText(getString(R.string.consent_device, request.viewerName, request.deviceId))
            .setCategory(Notification.CATEGORY_CALL)
            .setContentIntent(pi)
            .setFullScreenIntent(pi, true)
            .setAutoCancel(true)
            .setTimeoutAfter(TimeUnit.SECONDS.toMillis(30))
            .build()
        val nm = getSystemService(NotificationManager::class.java)
        nm.notify(NOTIFICATION_CONSENT, n)
        // Ouverture directe si Android l'autorise (app au premier plan).
        runCatching { startActivity(intent) }
        val answer = runCatching { pending.answer.get(28, TimeUnit.SECONDS) }.getOrDefault(ConsentAnswer.DENY)
        pending.answer.complete(ConsentAnswer.DENY)
        nm.cancel(NOTIFICATION_CONSENT)
        HostController.pending = null
        return answer
    }

    /** Taille de capture : écran réel réduit à 1920 px de grand côté, dimensions paires. */
    private fun captureSize(): Triple<Int, Int, Int> {
        val wm = getSystemService(WindowManager::class.java)
        val (w, h) = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            val b = wm.maximumWindowMetrics.bounds
            b.width() to b.height()
        } else {
            val p = android.graphics.Point()
            @Suppress("DEPRECATION")
            wm.defaultDisplay.getRealSize(p)
            p.x to p.y
        }
        val scale = minOf(1f, MAX_SIDE.toFloat() / max(w, h))
        val even = { v: Int -> ((v * scale).roundToInt() / 2 * 2).coerceAtLeast(2) }
        return Triple(even(w), even(h), resources.displayMetrics.densityDpi)
    }

    override fun screen(): Display {
        val (w, h, _) = captureSize()
        return Display(0u, "${Build.MANUFACTURER} ${Build.MODEL}", w.toUInt(), h.toUInt(), true)
    }

    override fun startStream(request: StreamRequest): StreamInfo {
        val grant = HostController.takeProjection()
            ?: throw MobileException.App(getString(R.string.no_projection))
        val result = CompletableFutureResult<StreamInfo>()
        main.post {
            try {
                // Android 14 : le service doit être de type mediaProjection
                // avant d'obtenir la projection.
                foreground(HostController.status, projection = true)
                val mpm = getSystemService(MediaProjectionManager::class.java)
                val p = mpm.getMediaProjection(grant.resultCode, grant.data)
                    ?: throw IllegalStateException(getString(R.string.no_projection))
                p.registerCallback(object : MediaProjection.Callback() {
                    override fun onStop() {
                        // Partage arrêté par l'utilisateur (barre d'état).
                        core?.endStream()
                        releaseCapture()
                    }
                }, main)
                projection = p
                val (w, h, dpi) = captureSize()
                val fps = request.fps.toInt().coerceIn(1, 60)
                val bitrate = if (request.bitrateBps > 0u) {
                    request.bitrateBps.toInt()
                } else {
                    (w.toLong() * h * fps / 10).coerceIn(1_000_000, 8_000_000).toInt()
                }
                val e = ScreenEncoder(
                    projection = p, fps = fps, bitrate = bitrate,
                    onFrame = { data, key, fw, fh -> core?.pushFrame(data, key, fw.toUInt(), fh.toUInt()) },
                    onError = { msg ->
                        Log.w(TAG, msg)
                        core?.endStream()
                    },
                )
                e.start(w, h, dpi)
                encoder = e
                watchRotation()
                result.complete(StreamInfo("MediaCodec ${e.encoderName}", bitrate.toUInt()))
            } catch (ex: Exception) {
                releaseCapture()
                result.fail(MobileException.App(ex.message ?: ex.toString()))
            }
        }
        return result.get()
    }

    private fun watchRotation() {
        val dm = getSystemService(DisplayManager::class.java)
        val l = object : DisplayManager.DisplayListener {
            override fun onDisplayChanged(displayId: Int) {
                if (displayId != android.view.Display.DEFAULT_DISPLAY) return
                val (w, h, dpi) = captureSize()
                encoder?.resize(w, h, dpi)
            }
            override fun onDisplayAdded(displayId: Int) {}
            override fun onDisplayRemoved(displayId: Int) {}
        }
        dm.registerDisplayListener(l, main)
        displayListener = l
    }

    private fun releaseCapture() {
        displayListener?.let { getSystemService(DisplayManager::class.java).unregisterDisplayListener(it) }
        displayListener = null
        encoder?.stop()
        encoder = null
        projection?.stop()
        projection = null
        if (core != null && !destroyed) foreground(HostController.status, projection = false)
    }

    override fun stopStream() {
        main.post { releaseCapture() }
    }

    override fun requestKeyframe() {
        encoder?.requestKeyframe()
    }

    override fun setBitrate(bps: UInt) {
        encoder?.setBitrate(bps.toInt())
    }

    private val knox: KnoxInjector? by lazy { KnoxInjector.open(this) }

    /** Injecteur courant : API constructeur si disponible, sinon accessibilité. */
    private fun injector(): Injector {
        knox?.let { return it }
        val service = CreamoteAccessibilityService.instance
        if (injectorOwner !== service) {
            injector = service?.let { AccessibilityInjector(it) } ?: NoInjector
            injectorOwner = service
        }
        return injector
    }

    override fun key(hid: UInt, androidKeycode: Int?, pressed: Boolean) {
        val code = androidKeycode ?: return
        main.post { injector().key(code, pressed) }
    }

    override fun pointer(x: Float, y: Float, buttons: UInt, wheelDx: Float, wheelDy: Float) {
        main.post { injector().pointer(x, y, buttons.toInt(), wheelDx, wheelDy) }
    }

    override fun releaseAll() {
        main.post { injector().releaseAll() }
    }

    companion object {
        const val ACTION_STOP = "org.creamote.android.STOP_HOST"
        private const val TAG = "creamote"
        private const val CHANNEL_HOST = "host"
        private const val CHANNEL_CONSENT = "consent"
        private const val NOTIFICATION_HOST = 1
        private const val NOTIFICATION_CONSENT = 2
        private const val MAX_SIDE = 1920

        fun start(context: Context) {
            context.startForegroundService(Intent(context, HostService::class.java))
        }

        fun stop(context: Context) {
            context.stopService(Intent(context, HostService::class.java))
        }
    }
}

/** Résultat produit sur le thread principal, attendu par un thread du cœur. */
private class CompletableFutureResult<T> {
    private val f = java.util.concurrent.CompletableFuture<T>()
    fun complete(v: T) = f.complete(v)
    fun fail(e: Exception) = f.completeExceptionally(e)
    fun get(): T = try {
        f.get(10, TimeUnit.SECONDS)
    } catch (e: java.util.concurrent.ExecutionException) {
        throw e.cause ?: e
    }
}

/** Presse-papier (texte) ; lisible seulement au premier plan depuis Android 10. */
private class AppClipboard(context: Context) : ClipboardProvider {
    private val cm = context.getSystemService(ClipboardManager::class.java)
    private val main = Handler(Looper.getMainLooper())

    override fun readText(): String? = runCatching {
        cm.primaryClip?.takeIf { it.itemCount > 0 }?.getItemAt(0)?.text?.toString()
    }.getOrNull()

    override fun writeText(text: String) {
        main.post { cm.setPrimaryClip(ClipData.newPlainText("Creamote", text)) }
    }
}
