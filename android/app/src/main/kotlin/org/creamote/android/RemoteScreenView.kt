package org.creamote.android

import android.content.Context
import android.text.InputType
import android.util.AttributeSet
import android.view.SurfaceView
import android.view.View
import android.view.inputmethod.BaseInputConnection
import android.view.inputmethod.EditorInfo
import android.view.inputmethod.InputConnection

/**
 * Surface de décodage de l'écran distant, au rapport largeur/hauteur de
 * cet écran (bandes noires autour), et cible du clavier logiciel.
 */
class RemoteScreenView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
) : SurfaceView(context, attrs) {
    private var videoWidth = 0
    private var videoHeight = 0

    /** Texte tapé au clavier logiciel (déjà validé par l'IME). */
    var onText: ((String) -> Unit)? = null
    /** Effacements demandés par l'IME (touche retour arrière). */
    var onDelete: ((Int) -> Unit)? = null

    init {
        isFocusable = true
        isFocusableInTouchMode = true
    }

    fun setVideoSize(width: Int, height: Int) {
        if (width == videoWidth && height == videoHeight) return
        videoWidth = width
        videoHeight = height
        requestLayout()
    }

    override fun onMeasure(widthMeasureSpec: Int, heightMeasureSpec: Int) {
        val maxW = View.MeasureSpec.getSize(widthMeasureSpec)
        val maxH = View.MeasureSpec.getSize(heightMeasureSpec)
        if (videoWidth <= 0 || videoHeight <= 0 || maxW == 0 || maxH == 0) {
            setMeasuredDimension(maxW, maxH)
            return
        }
        val scale = minOf(maxW.toFloat() / videoWidth, maxH.toFloat() / videoHeight)
        setMeasuredDimension((videoWidth * scale).toInt(), (videoHeight * scale).toInt())
    }

    override fun onCheckIsTextEditor() = true

    override fun onCreateInputConnection(outAttrs: EditorInfo): InputConnection {
        // Pas de suggestions ni de correction : chaque caractère part tel quel.
        outAttrs.inputType = InputType.TYPE_CLASS_TEXT or
            InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD or
            InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
        outAttrs.imeOptions = EditorInfo.IME_FLAG_NO_FULLSCREEN or EditorInfo.IME_FLAG_NO_EXTRACT_UI
        return object : BaseInputConnection(this, false) {
            override fun commitText(text: CharSequence, newCursorPosition: Int): Boolean {
                onText?.invoke(text.toString())
                return true
            }

            override fun deleteSurroundingText(beforeLength: Int, afterLength: Int): Boolean {
                onDelete?.invoke(maxOf(beforeLength, 1))
                return true
            }
        }
    }
}
