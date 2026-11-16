package org.creamote.android

import android.media.MediaCodec
import android.media.MediaFormat
import android.os.Build
import android.util.Log
import android.view.Surface
import org.creamote.core.VideoFrame
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit

/**
 * Décodeur H.264 MediaCodec (matériel du constructeur) rendant dans la
 * surface de l'écran distant. Un thread par décodeur ; recréé à chaque
 * changement de taille.
 *
 * L'image est acquittée dès qu'elle est confiée au décodeur : certains
 * décodeurs retiennent plusieurs images avant d'en rendre une, ce qui
 * bloquerait le host (3 images en vol au plus).
 */
class VideoDecoder(
    private val surface: Surface,
    private val width: Int,
    private val height: Int,
    private val onQueued: (frameId: ULong) -> Unit,
    private val onError: (String) -> Unit,
) {
    private val frames = LinkedBlockingQueue<VideoFrame>()
    @Volatile private var running = true
    private val thread = Thread(::run, "creamote-decoder")

    fun start() = thread.start()

    fun submit(frame: VideoFrame) {
        frames.add(frame)
    }

    fun stop() {
        running = false
        thread.interrupt()
    }

    private fun run() {
        val codec = try {
            val format = MediaFormat.createVideoFormat(MediaFormat.MIMETYPE_VIDEO_AVC, width, height)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                format.setInteger(MediaFormat.KEY_LOW_LATENCY, 1)
            }
            MediaCodec.createDecoderByType(MediaFormat.MIMETYPE_VIDEO_AVC).apply {
                configure(format, surface, null, 0)
                start()
            }
        } catch (e: Exception) {
            onError("décodeur H.264 indisponible : ${e.message}")
            return
        }
        Log.i(TAG, "décodeur ${codec.name} ${width}x$height")
        val info = MediaCodec.BufferInfo()
        var waitingKeyframe = true
        var pending: VideoFrame? = null
        try {
            while (running) {
                val frame = pending ?: frames.poll(10, TimeUnit.MILLISECONDS)
                pending = null
                if (frame != null) {
                    if (waitingKeyframe && !frame.keyframe) {
                        // Rien à décoder avant une image clé ; acquitter pour
                        // ne pas bloquer le host.
                        onQueued(frame.frameId)
                    } else {
                        val index = codec.dequeueInputBuffer(5_000)
                        if (index < 0) {
                            pending = frame
                        } else {
                            val buf = codec.getInputBuffer(index)!!
                            buf.clear()
                            buf.put(frame.data)
                            val flags = if (frame.keyframe) MediaCodec.BUFFER_FLAG_KEY_FRAME else 0
                            codec.queueInputBuffer(index, 0, frame.data.size, frame.timestampUs.toLong(), flags)
                            waitingKeyframe = false
                            onQueued(frame.frameId)
                        }
                    }
                }
                while (true) {
                    val out = codec.dequeueOutputBuffer(info, 0)
                    if (out >= 0) {
                        codec.releaseOutputBuffer(out, true)
                    } else if (out == MediaCodec.INFO_TRY_AGAIN_LATER) {
                        break
                    }
                }
            }
        } catch (e: InterruptedException) {
            // Arrêt demandé.
        } catch (e: Exception) {
            if (running) onError("décodage : ${e.message}")
        } finally {
            runCatching { codec.stop() }
            codec.release()
        }
    }

    private companion object {
        const val TAG = "creamote"
    }
}
