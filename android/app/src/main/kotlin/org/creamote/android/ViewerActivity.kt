package org.creamote.android

import android.app.Activity
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.InputDevice
import android.view.KeyEvent
import android.view.MotionEvent
import android.view.SurfaceHolder
import android.view.ViewConfiguration
import android.view.WindowManager
import android.view.inputmethod.InputMethodManager
import android.widget.Button
import android.widget.TextView
import android.widget.Toast
import android.widget.ToggleButton
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.MainScope
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.creamote.core.ConnectRequest
import org.creamote.core.Display
import org.creamote.core.MobileException
import org.creamote.core.VideoConfig
import org.creamote.core.VideoFrame
import org.creamote.core.ViewerListener
import org.creamote.core.ViewerSession
import org.creamote.core.connect
import org.creamote.core.hidFromAndroidKeycode

/** Écran distant : affichage, gestes, clavier. */
class ViewerActivity : Activity(), ViewerListener, SurfaceHolder.Callback {
    private val scope = MainScope()
    private val main = Handler(Looper.getMainLooper())

    @Volatile private var session: ViewerSession? = null
    @Volatile private var decoder: VideoDecoder? = null
    private var config: VideoConfig? = null
    private var displays: List<Display> = emptyList()
    private var surfaceReady = false
    private var finished = false

    private lateinit var screen: RemoteScreenView
    private lateinit var status: TextView
    private lateinit var ctrl: ToggleButton
    private lateinit var alt: ToggleButton
    private lateinit var win: ToggleButton
    private lateinit var gestures: Gestures
    private val longPress = Runnable { send(gestures.longPress()) }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_viewer)
        window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        screen = findViewById(R.id.screen)
        status = findViewById(R.id.status)
        ctrl = findViewById(R.id.ctrl)
        alt = findViewById(R.id.alt)
        win = findViewById(R.id.win)
        val density = resources.displayMetrics.density
        gestures = Gestures(
            slopPx = ViewConfiguration.get(this).scaledTouchSlop.toFloat(),
            wheelStepPx = 40 * density,
        )

        screen.holder.addCallback(this)
        screen.setOnTouchListener { _, ev -> onTouch(ev) }
        screen.setOnGenericMotionListener { _, ev -> onMouse(ev) }
        screen.onText = ::typeText
        screen.onDelete = { n -> repeat(n) { tap(TextKeys.BACKSPACE) } }

        findViewById<Button>(R.id.keyboard).setOnClickListener {
            screen.requestFocus()
            getSystemService(InputMethodManager::class.java)
                .showSoftInput(screen, InputMethodManager.SHOW_IMPLICIT)
        }
        findViewById<Button>(R.id.esc).setOnClickListener { tap(TextKeys.ESCAPE) }
        findViewById<Button>(R.id.tab).setOnClickListener { tap(TextKeys.TAB) }
        findViewById<Button>(R.id.cad).setOnClickListener {
            val s = session ?: return@setOnClickListener
            listOf(TextKeys.CTRL, TextKeys.ALT, TextKeys.DELETE).forEach { s.key(it.toUInt(), true) }
            listOf(TextKeys.DELETE, TextKeys.ALT, TextKeys.CTRL).forEach { s.key(it.toUInt(), false) }
        }
        findViewById<Button>(R.id.nextDisplay).setOnClickListener { nextDisplay() }
        findViewById<Button>(R.id.disconnect).setOnClickListener { finish() }

        status.text = getString(R.string.connecting)
        open()
    }

    private fun open() {
        val app = CreamoteApp.of(this)
        val settings = app.settings
        val server = settings.server ?: return finish()
        val request = ConnectRequest(
            server = server,
            target = intent.getStringExtra(EXTRA_TARGET) ?: return finish(),
            apiUrl = settings.apiUrl.ifEmpty { null },
            apiToken = settings.apiToken.ifEmpty { null },
            viewOnly = intent.getBooleanExtra(EXTRA_VIEW_ONLY, false),
            displayName = "${android.os.Build.MANUFACTURER} ${android.os.Build.MODEL}",
        )
        scope.launch {
            val result = withContext(Dispatchers.IO) {
                runCatching { connect(app.identity, request, this@ViewerActivity, null) }
            }
            result.onSuccess { s ->
                if (finished) {
                    Thread { s.disconnect() }.start()
                    return@onSuccess
                }
                session = s
                val info = s.info()
                val path = getString(if (info.direct) R.string.path_direct else R.string.path_relay)
                status.text = getString(R.string.waiting_host, info.verificationCode) + "\n" + path
                if (info.maxSessionSeconds > 0u) {
                    val minutes = (info.maxSessionSeconds / 60u).toInt()
                    Toast.makeText(this@ViewerActivity, getString(R.string.relay_limit, minutes), Toast.LENGTH_LONG).show()
                }
            }.onFailure { e ->
                val msg = (e as? MobileException)?.message ?: e.toString()
                status.text = getString(R.string.error, msg)
            }
        }
    }

    override fun onDestroy() {
        finished = true
        scope.cancel()
        main.removeCallbacksAndMessages(null)
        decoder?.stop()
        decoder = null
        session?.let { s -> Thread { s.disconnect() }.start() }
        session = null
        super.onDestroy()
    }

    // --- Événements de session (thread du cœur) ---

    override fun onAccepted(granted: List<String>, displays: List<Display>) {
        runOnUiThread {
            this.displays = displays
            status.text = getString(R.string.gestures_help)
            main.postDelayed({ if (config != null) status.text = "" }, 4000)
        }
    }

    override fun onVideoConfig(config: VideoConfig) {
        runOnUiThread {
            val old = this.config
            this.config = config
            screen.setVideoSize(config.width.toInt(), config.height.toInt())
            if (old == null || old.width != config.width || old.height != config.height ||
                old.displayId != config.displayId
            ) {
                restartDecoder()
            }
        }
    }

    override fun onDisplays(displays: List<Display>) {
        runOnUiThread { this.displays = displays }
    }

    override fun onFrame(frame: VideoFrame) {
        val d = decoder
        if (d != null) {
            d.submit(frame)
        } else {
            // Pas encore de surface : acquitter pour ne pas bloquer le host ;
            // une image clé sera demandée au démarrage du décodeur.
            session?.ack(frame.frameId)
        }
    }

    override fun onEnded(reason: String, message: String) {
        runOnUiThread {
            decoder?.stop()
            decoder = null
            status.text = getString(R.string.session_ended, message.ifEmpty { reason })
        }
    }

    // --- Surface et décodeur ---

    override fun surfaceCreated(holder: SurfaceHolder) {
        surfaceReady = true
        restartDecoder()
    }

    override fun surfaceChanged(holder: SurfaceHolder, format: Int, width: Int, height: Int) {}

    override fun surfaceDestroyed(holder: SurfaceHolder) {
        surfaceReady = false
        decoder?.stop()
        decoder = null
    }

    private fun restartDecoder() {
        decoder?.stop()
        decoder = null
        val c = config ?: return
        if (!surfaceReady) return
        val d = VideoDecoder(
            surface = screen.holder.surface,
            width = c.width.toInt(),
            height = c.height.toInt(),
            onQueued = { id -> session?.ack(id) },
            onError = { msg ->
                android.util.Log.w("creamote", msg)
                main.post { if (!finished) restartDecoder() }
            },
        )
        decoder = d
        d.start()
        session?.requestKeyframe()
    }

    // --- Entrées ---

    private fun send(out: List<Gestures.Out>) {
        val s = session ?: return
        val c = config ?: return
        val w = screen.width.toFloat().coerceAtLeast(1f)
        val h = screen.height.toFloat().coerceAtLeast(1f)
        for (o in out) {
            s.pointer(c.displayId, o.x / w, o.y / h, o.buttons.toUInt(), o.wheelDx, o.wheelDy)
        }
    }

    private fun onTouch(ev: MotionEvent): Boolean {
        if (ev.isFromSource(InputDevice.SOURCE_MOUSE)) return onMouse(ev)
        when (ev.actionMasked) {
            MotionEvent.ACTION_DOWN -> {
                send(gestures.down(ev.x, ev.y))
                main.postDelayed(longPress, ViewConfiguration.getLongPressTimeout().toLong())
            }
            MotionEvent.ACTION_POINTER_DOWN -> {
                main.removeCallbacks(longPress)
                if (ev.pointerCount == 2) send(gestures.secondFinger(midX(ev), midY(ev)))
            }
            MotionEvent.ACTION_MOVE -> {
                if (ev.pointerCount >= 2) {
                    send(gestures.scroll(midX(ev), midY(ev)))
                } else {
                    val out = gestures.move(ev.x, ev.y)
                    if (out.isNotEmpty()) main.removeCallbacks(longPress)
                    send(out)
                }
            }
            MotionEvent.ACTION_UP -> {
                main.removeCallbacks(longPress)
                send(gestures.up(ev.x, ev.y))
            }
            MotionEvent.ACTION_CANCEL -> {
                main.removeCallbacks(longPress)
                send(gestures.cancel(ev.x, ev.y))
            }
        }
        return true
    }

    private fun midX(ev: MotionEvent) = (ev.getX(0) + ev.getX(1)) / 2
    private fun midY(ev: MotionEvent) = (ev.getY(0) + ev.getY(1)) / 2

    /** Souris (DeX, Chromebook, souris Bluetooth) : position et boutons réels. */
    private fun onMouse(ev: MotionEvent): Boolean {
        if (!ev.isFromSource(InputDevice.SOURCE_MOUSE)) return false
        var buttons = 0
        if (ev.buttonState and MotionEvent.BUTTON_PRIMARY != 0) buttons = buttons or 1
        if (ev.buttonState and MotionEvent.BUTTON_SECONDARY != 0) buttons = buttons or 2
        if (ev.buttonState and MotionEvent.BUTTON_TERTIARY != 0) buttons = buttons or 4
        val (wheelX, wheelY) = if (ev.actionMasked == MotionEvent.ACTION_SCROLL) {
            -ev.getAxisValue(MotionEvent.AXIS_HSCROLL) to -ev.getAxisValue(MotionEvent.AXIS_VSCROLL)
        } else {
            0f to 0f
        }
        send(listOf(Gestures.Out(ev.x, ev.y, buttons, wheelY, wheelX)))
        return true
    }

    /** Clavier matériel : touches physiques transmises telles quelles. */
    override fun dispatchKeyEvent(event: KeyEvent): Boolean {
        val s = session
        val fromKeyboard = event.device?.keyboardType == InputDevice.KEYBOARD_TYPE_ALPHABETIC
        if (s == null || (event.keyCode == KeyEvent.KEYCODE_BACK && !fromKeyboard)) {
            return super.dispatchKeyEvent(event)
        }
        val hid = hidFromAndroidKeycode(event.keyCode) ?: return super.dispatchKeyEvent(event)
        when (event.action) {
            KeyEvent.ACTION_DOWN -> s.key(hid, true)
            KeyEvent.ACTION_UP -> s.key(hid, false)
            else -> return super.dispatchKeyEvent(event)
        }
        return true
    }

    /** Appui bref, avec Maj et les modificateurs de la barre d'outils. */
    private fun tap(hid: Int, shift: Boolean = false) {
        val s = session ?: return
        val mods = buildList {
            if (ctrl.isChecked) add(TextKeys.CTRL)
            if (alt.isChecked) add(TextKeys.ALT)
            if (win.isChecked) add(TextKeys.META)
            if (shift) add(TextKeys.SHIFT)
        }
        mods.forEach { s.key(it.toUInt(), true) }
        s.key(hid.toUInt(), true)
        s.key(hid.toUInt(), false)
        mods.asReversed().forEach { s.key(it.toUInt(), false) }
        // Les modificateurs de la barre ne valent que pour une touche.
        ctrl.isChecked = false
        alt.isChecked = false
        win.isChecked = false
    }

    private fun typeText(text: String) {
        for (c in text) {
            val stroke = TextKeys.stroke(c) ?: continue
            tap(stroke.hid, stroke.shift)
        }
    }

    private fun nextDisplay() {
        val s = session ?: return
        if (displays.size < 2) return
        val current = displays.indexOfFirst { it.id == config?.displayId }
        s.selectDisplay(displays[(current + 1) % displays.size].id)
    }

    companion object {
        const val EXTRA_TARGET = "target"
        const val EXTRA_VIEW_ONLY = "view_only"
    }
}

