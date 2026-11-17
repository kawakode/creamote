package org.creamote.android.host

import android.app.Activity
import android.content.Intent
import android.media.projection.MediaProjectionManager
import android.os.Build
import android.os.Bundle
import android.view.WindowManager
import android.widget.Button
import android.widget.TextView
import org.creamote.android.R
import org.creamote.core.ConsentAnswer

/**
 * Demande à l'utilisateur présent s'il accepte la connexion, puis
 * l'autorisation système de capture d'écran (MediaProjection), demandée à
 * chaque session.
 */
class ConsentActivity : Activity() {
    private var choice: ConsentAnswer? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O_MR1) {
            setShowWhenLocked(true)
            setTurnScreenOn(true)
        } else {
            @Suppress("DEPRECATION")
            window.addFlags(
                WindowManager.LayoutParams.FLAG_SHOW_WHEN_LOCKED or
                    WindowManager.LayoutParams.FLAG_TURN_SCREEN_ON,
            )
        }
        window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        val pending = HostController.pending
        if (pending == null || pending.answer.isDone) {
            finish()
            return
        }
        setContentView(R.layout.activity_consent)
        val r = pending.request
        val who = r.userEmail?.let { "$it\n" }.orEmpty() +
            getString(R.string.consent_device, r.viewerName, r.deviceId)
        findViewById<TextView>(R.id.consentWho).text = who
        findViewById<TextView>(R.id.consentCode).text = r.verificationCode
        findViewById<TextView>(R.id.consentFingerprint).text = r.fingerprint
        val control = findViewById<Button>(R.id.consentControl)
        control.isEnabled = "control" in r.permissions
        control.setOnClickListener { askProjection(ConsentAnswer.CONTROL) }
        findViewById<Button>(R.id.consentView).setOnClickListener { askProjection(ConsentAnswer.VIEW_ONLY) }
        findViewById<Button>(R.id.consentDeny).setOnClickListener { answer(ConsentAnswer.DENY) }
        pending.answer.whenComplete { _, _ -> runOnUiThread { if (choice == null) finish() } }
    }

    private fun askProjection(answer: ConsentAnswer) {
        choice = answer
        val mpm = getSystemService(MediaProjectionManager::class.java)
        @Suppress("DEPRECATION")
        startActivityForResult(mpm.createScreenCaptureIntent(), REQUEST_PROJECTION)
    }

    @Deprecated("API Activity simple, sans androidx")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        @Suppress("DEPRECATION")
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode != REQUEST_PROJECTION) return
        if (resultCode == RESULT_OK && data != null) {
            HostController.grantProjection(HostController.ProjectionGrant(resultCode, data))
            answer(choice ?: ConsentAnswer.DENY)
        } else {
            answer(ConsentAnswer.DENY)
        }
    }

    private fun answer(a: ConsentAnswer) {
        HostController.pending?.answer?.complete(a)
        finish()
    }

    override fun onDestroy() {
        // Fermée sans réponse (retour, autre app) : refus.
        if (isFinishing && choice == null) HostController.pending?.answer?.complete(ConsentAnswer.DENY)
        super.onDestroy()
    }

    private companion object {
        const val REQUEST_PROJECTION = 1
    }
}
