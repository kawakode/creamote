package org.creamote.core

import java.io.File
import java.nio.file.Files
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * Les liaisons Kotlin du cœur Rust, appelées comme le fera l'app Android :
 * un vrai creamote-server, un host et un viewer dans ce processus, les
 * rappels (`HostDelegate`, `ViewerListener`) écrits en Kotlin.
 */
class BindingsTest {
    private lateinit var dir: File
    private lateinit var server: Process
    private lateinit var serverConfig: ServerConfig

    @BeforeTest
    fun startServer() {
        dir = Files.createTempDirectory("creamote-jvm").toFile()
        server = ProcessBuilder(
            System.getProperty("creamote.server"),
            "--listen", "127.0.0.1:0",
            "--api-listen", "127.0.0.1:0",
            "--data-dir", dir.resolve("server").path,
        ).redirectErrorStream(true).start()
        val lines = server.inputStream.bufferedReader()
        var address: String? = null
        var pin: String? = null
        while (address == null || pin == null) {
            val line = lines.readLine() ?: error("le serveur s'est arrêté")
            if (line.startsWith("Écoute")) address = line.substringAfter(": ").substringBefore(" ")
            if (line.startsWith("Empreinte")) pin = line.substringAfter(": ").trim()
        }
        thread(isDaemon = true) { lines.forEachLine { } }
        serverConfig = ServerConfig(address, pin)
    }

    @AfterTest
    fun stopServer() {
        server.destroy()
        dir.deleteRecursively()
    }

    private class FakeApp : HostDelegate {
        @Volatile var service: HostService? = null
        @Volatile var streaming = false
        @Volatile var keyframe = false
        val status = LinkedBlockingQueue<HostStatus>()
        val input = LinkedBlockingQueue<String>()
        val consents = LinkedBlockingQueue<ConsentRequest>()

        override fun screen() = Display(0u, "Écran intégré", 720u, 1600u, true)

        override fun consent(request: ConsentRequest): ConsentAnswer {
            consents.add(request)
            return ConsentAnswer.CONTROL
        }

        override fun startStream(request: StreamRequest): StreamInfo {
            streaming = true
            thread(isDaemon = true) {
                var n = 0
                while (streaming) {
                    val key = keyframe.also { keyframe = false }
                    service!!.pushFrame(ByteArray(300) { n.toByte() }, key, 720u, 1600u)
                    n++
                    Thread.sleep(10)
                }
            }
            return StreamInfo("MediaCodec (JVM)", 2_000_000u)
        }

        override fun stopStream() {
            streaming = false
        }

        override fun requestKeyframe() {
            keyframe = true
        }

        override fun setBitrate(bps: UInt) {}

        override fun key(hid: UInt, androidKeycode: Int?, pressed: Boolean) {
            input.add("key $hid $androidKeycode $pressed")
        }

        override fun pointer(x: Float, y: Float, buttons: UInt, wheelDx: Float, wheelDy: Float) {
            input.add("pointer $x $y $buttons")
        }

        override fun releaseAll() {
            input.add("release")
        }

        override fun onStatus(status: HostStatus) {
            this.status.add(status)
        }
    }

    private class Listener : ViewerListener {
        val events = LinkedBlockingQueue<Any>()
        override fun onAccepted(granted: List<String>, displays: List<Display>) {
            events.add(granted)
        }
        override fun onVideoConfig(config: VideoConfig) {
            events.add(config)
        }
        override fun onDisplays(displays: List<Display>) {}
        override fun onFrame(frame: VideoFrame) {
            events.add(frame)
        }
        override fun onEnded(reason: String, message: String) {
            events.add("ended:$reason")
        }
    }

    private fun <T> LinkedBlockingQueue<T>.next(): T =
        poll(20, TimeUnit.SECONDS) ?: error("événement attendu")

    @Test
    fun hostAndViewerThroughKotlinCallbacks() {
        val hostId = Identity.loadOrCreate(dir.resolve("host.identity").path)
        val app = FakeApp()
        val service = startHost(
            hostId,
            HostConfig(serverConfig, dir.resolve("host.enrollment").path, null, "", false, null),
            app,
            null,
        )
        app.service = service
        assertTrue(app.status.next() is HostStatus.Online)

        val viewerId = Identity.loadOrCreate(dir.resolve("viewer.identity").path)
        val listener = Listener()
        val session = connect(
            viewerId,
            ConnectRequest(serverConfig, hostId.deviceId(), null, null, false, "Viewer JVM"),
            listener,
            null,
        )
        assertEquals(listOf("view_screen", "control"), listener.events.next())
        assertEquals(session.info().verificationCode, app.consents.next().verificationCode)
        val started = app.status.next() as HostStatus.SessionStarted
        assertEquals(viewerId.deviceId(), started.peerId)

        val config = listener.events.next() as VideoConfig
        assertEquals(720u, config.width)
        assertEquals(1600u, config.height)
        assertEquals("MediaCodec (JVM)", config.encoder)

        var frames = 0
        while (frames < 5) {
            val ev = listener.events.next()
            if (ev is VideoFrame) {
                if (frames == 0) assertTrue(ev.keyframe)
                session.ack(ev.frameId)
                frames++
            }
        }

        // Touche A : usage HID 4 → KeyEvent.KEYCODE_A (29).
        session.key(4u, true)
        session.pointer(0u, 0.25f, 0.5f, 1u, 0f, 0f)
        assertEquals("key 4 29 true", app.input.next())
        assertEquals("pointer 0.25 0.5 1", app.input.next())

        session.disconnect()
        while (listener.events.next() !is String) { /* images restantes */ }
        assertTrue(app.status.next() is HostStatus.SessionEnded)
        assertEquals("release", app.input.next())
        service.stop()
        assertTrue(app.status.next() is HostStatus.Stopped)
    }

    @Test
    fun keyMappingAndErrors() {
        assertEquals(29, androidKeycode(4u))
        assertEquals(0x2Au, hidFromAndroidKeycode(67))
        val id = Identity.loadOrCreate(dir.resolve("v.identity").path)
        assertEquals(9, id.deviceId().count { it.isDigit() })
        assertFailsWith<MobileException.Invalid> {
            connect(id, ConnectRequest(serverConfig, "12", null, null, true, "x"), Listener(), null)
        }
    }
}
