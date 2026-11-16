package org.creamote.android.host

import android.hardware.display.DisplayManager
import android.hardware.display.VirtualDisplay
import android.media.MediaCodec
import android.media.MediaCodecInfo
import android.media.MediaFormat
import android.media.projection.MediaProjection
import android.os.Build
import android.os.Bundle
import android.util.Log
import android.view.Surface

/**
 * Capture d'écran et encodage H.264 sans copie : MediaProjection rend dans
 * un VirtualDisplay dont la surface est l'entrée d'un encodeur MediaCodec
 * (matériel du constructeur). Les images encodées (Annex B, SPS/PPS devant
 * chaque image clé) sont remises à [onFrame].
 *
 * Rotation : [resize] change la taille sans recréer le VirtualDisplay
 * (interdit avec le même jeton de projection depuis Android 14).
 */
class ScreenEncoder(
    private val projection: MediaProjection,
    private val fps: Int,
    private var bitrate: Int,
    private val onFrame: (data: ByteArray, keyframe: Boolean, width: Int, height: Int) -> Unit,
    private val onError: (String) -> Unit,
) {
    private var display: VirtualDisplay? = null
    @Volatile private var codec: MediaCodec? = null
    private var thread: Thread? = null
    @Volatile private var running = false
    var width = 0
        private set
    var height = 0
        private set
    var encoderName = ""
        private set

    /** Démarre à la taille donnée (pixels, pairs). */
    fun start(width: Int, height: Int, densityDpi: Int) {
        running = true
        val surface = openCodec(width, height)
        display = projection.createVirtualDisplay(
            "Creamote", width, height, densityDpi,
            DisplayManager.VIRTUAL_DISPLAY_FLAG_AUTO_MIRROR, surface, null, null,
        )
    }

    /** Nouvelle taille (rotation) : nouvel encodeur, même VirtualDisplay. */
    fun resize(width: Int, height: Int, densityDpi: Int) {
        if (width == this.width && height == this.height) return
        closeCodec()
        val surface = openCodec(width, height)
        display?.resize(width, height, densityDpi)
        display?.surface = surface
    }

    fun requestKeyframe() {
        codec?.setParameters(Bundle().apply { putInt(MediaCodec.PARAMETER_KEY_REQUEST_SYNC_FRAME, 0) })
    }

    fun setBitrate(bps: Int) {
        bitrate = bps
        codec?.setParameters(Bundle().apply { putInt(MediaCodec.PARAMETER_KEY_VIDEO_BITRATE, bps) })
    }

    fun stop() {
        running = false
        closeCodec()
        display?.release()
        display = null
    }

    private fun openCodec(width: Int, height: Int): Surface {
        this.width = width
        this.height = height
        val format = MediaFormat.createVideoFormat(MediaFormat.MIMETYPE_VIDEO_AVC, width, height).apply {
            setInteger(MediaFormat.KEY_COLOR_FORMAT, MediaCodecInfo.CodecCapabilities.COLOR_FormatSurface)
            setInteger(MediaFormat.KEY_BIT_RATE, bitrate)
            setInteger(MediaFormat.KEY_FRAME_RATE, fps)
            // Images clés à la demande du viewer ; une toutes les 10 s au plus.
            setInteger(MediaFormat.KEY_I_FRAME_INTERVAL, 10)
            // Écran immobile : une image toutes les 250 ms (sinon rien n'est produit).
            setLong(MediaFormat.KEY_REPEAT_PREVIOUS_FRAME_AFTER, 250_000)
            setInteger(MediaFormat.KEY_PROFILE, MediaCodecInfo.CodecProfileLevel.AVCProfileBaseline)
            setInteger(MediaFormat.KEY_LEVEL, MediaCodecInfo.CodecProfileLevel.AVCLevel41)
            setInteger(MediaFormat.KEY_BITRATE_MODE, MediaCodecInfo.EncoderCapabilities.BITRATE_MODE_VBR)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                setInteger(MediaFormat.KEY_LOW_LATENCY, 1)
            }
            // Pas d'images B : décodage sans réordonnancement.
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                setInteger(MediaFormat.KEY_MAX_B_FRAMES, 0)
            }
        }
        val c = MediaCodec.createEncoderByType(MediaFormat.MIMETYPE_VIDEO_AVC)
        c.configure(format, null, null, MediaCodec.CONFIGURE_FLAG_ENCODE)
        val surface = c.createInputSurface()
        c.start()
        encoderName = c.name
        codec = c
        thread = Thread({ drain(c, width, height) }, "creamote-encoder").also { it.start() }
        Log.i(TAG, "encodeur ${c.name} ${width}x$height ${bitrate / 1000} kbit/s")
        return surface
    }

    private fun closeCodec() {
        val c = codec ?: return
        codec = null
        thread?.interrupt()
        thread?.join(500)
        thread = null
        runCatching { c.stop() }
        c.release()
    }

    private fun drain(c: MediaCodec, width: Int, height: Int) {
        val info = MediaCodec.BufferInfo()
        var config: ByteArray? = null
        try {
            while (running && codec === c) {
                val index = c.dequeueOutputBuffer(info, 50_000)
                if (index < 0) continue
                val buf = c.getOutputBuffer(index)
                if (buf != null && info.size > 0) {
                    buf.position(info.offset)
                    buf.limit(info.offset + info.size)
                    val data = ByteArray(info.size).also { buf.get(it) }
                    if (info.flags and MediaCodec.BUFFER_FLAG_CODEC_CONFIG != 0) {
                        config = data
                    } else {
                        val key = info.flags and MediaCodec.BUFFER_FLAG_KEY_FRAME != 0
                        val out = if (key && config != null) config!! + data else data
                        onFrame(out, key, width, height)
                    }
                }
                c.releaseOutputBuffer(index, false)
            }
        } catch (e: IllegalStateException) {
            if (running && codec === c) onError("encodeur : ${e.message}")
        } catch (e: InterruptedException) {
            // Arrêt.
        }
    }

    private companion object {
        const val TAG = "creamote"
    }
}
