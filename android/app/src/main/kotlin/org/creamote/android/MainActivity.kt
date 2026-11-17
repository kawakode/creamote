package org.creamote.android

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.provider.Settings as SystemSettings
import android.view.View
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.Switch
import android.widget.TextView
import android.widget.Toast
import org.creamote.android.host.CreamoteAccessibilityService
import org.creamote.android.host.HostController
import org.creamote.android.host.HostService
import org.creamote.android.host.KnoxInjector
import org.creamote.android.host.KnoxLicense

/** Accueil : ID de l'appareil, connexion à un autre appareil, partage, serveur. */
class MainActivity : Activity() {
    private lateinit var settings: Settings
    private lateinit var share: Switch
    private lateinit var hostStatus: TextView
    private lateinit var accessibility: TextView
    private val onHostStatus: () -> Unit = { runOnUiThread(::showHost) }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        val app = CreamoteApp.of(this)
        settings = app.settings

        findViewById<TextView>(R.id.myId).text = app.identity.deviceId()
        findViewById<TextView>(R.id.myFingerprint).text =
            getString(R.string.fingerprint, app.identity.fingerprint())

        val address = findViewById<EditText>(R.id.serverAddress)
        val pin = findViewById<EditText>(R.id.serverPin)
        val apiUrl = findViewById<EditText>(R.id.apiUrl)
        val apiToken = findViewById<EditText>(R.id.apiToken)
        val target = findViewById<EditText>(R.id.targetId)
        val viewOnly = findViewById<CheckBox>(R.id.viewOnly)
        val status = findViewById<TextView>(R.id.status)
        address.setText(settings.serverAddress)
        pin.setText(settings.serverPin)
        apiUrl.setText(settings.apiUrl)
        apiToken.setText(settings.apiToken)
        target.setText(settings.lastTarget)

        share = findViewById(R.id.share)
        hostStatus = findViewById(R.id.hostStatus)
        accessibility = findViewById(R.id.accessibility)
        val deviceName = findViewById<EditText>(R.id.deviceName)
        val enrollToken = findViewById<EditText>(R.id.enrollToken)
        deviceName.setText(settings.deviceName)
        share.setOnClickListener {
            if (share.isChecked) {
                settings.serverAddress = address.text.toString()
                settings.serverPin = pin.text.toString()
                settings.deviceName = deviceName.text.toString()
                settings.enrollToken = enrollToken.text.toString()
                enrollToken.setText("")
                askNotifications()
                HostService.start(this)
            } else {
                HostService.stop(this)
            }
        }
        findViewById<Button>(R.id.openAccessibility).setOnClickListener {
            startActivity(Intent(SystemSettings.ACTION_ACCESSIBILITY_SETTINGS))
        }

        // Samsung Knox : licence activée par l'administrateur du parc.
        if (KnoxLicense.available) findViewById<View>(R.id.knoxGroup).visibility = View.VISIBLE
        val knoxKey = findViewById<EditText>(R.id.knoxKey)
        findViewById<Button>(R.id.knoxActivate).setOnClickListener {
            if (!KnoxLicense.isAdmin(this)) {
                @Suppress("DEPRECATION")
                startActivityForResult(
                    KnoxLicense.requestAdmin(this, getString(R.string.knox_admin_explanation)), REQUEST_ADMIN,
                )
                return@setOnClickListener
            }
            val ok = KnoxLicense.activate(this, knoxKey.text.toString())
            Toast.makeText(
                this, getString(if (ok) R.string.knox_requested else R.string.knox_unavailable), Toast.LENGTH_LONG,
            ).show()
            if (ok) knoxKey.setText("")
        }

        findViewById<Button>(R.id.connect).setOnClickListener {
            settings.serverAddress = address.text.toString()
            settings.serverPin = pin.text.toString()
            settings.apiUrl = apiUrl.text.toString()
            settings.apiToken = apiToken.text.toString()
            val id = target.text.toString().filter { it.isDigit() }
            if (settings.server == null) {
                status.text = getString(R.string.error, getString(R.string.server_section))
                address.requestFocus()
                return@setOnClickListener
            }
            if (id.length != 9) {
                status.text = getString(R.string.error, getString(R.string.target_id))
                target.requestFocus()
                return@setOnClickListener
            }
            settings.lastTarget = id
            status.text = ""
            startActivity(
                Intent(this, ViewerActivity::class.java)
                    .putExtra(ViewerActivity.EXTRA_TARGET, id)
                    .putExtra(ViewerActivity.EXTRA_VIEW_ONLY, viewOnly.isChecked),
            )
        }
    }

    override fun onResume() {
        super.onResume()
        HostController.observe(onHostStatus)
        showHost()
    }

    override fun onPause() {
        HostController.forget(onHostStatus)
        super.onPause()
    }

    private fun showHost() {
        share.isChecked = HostController.running
        hostStatus.text = HostController.status
        accessibility.text = getString(
            when {
                KnoxInjector.open(this) != null -> R.string.knox_active
                CreamoteAccessibilityService.enabled -> R.string.accessibility_on
                else -> R.string.accessibility_off
            },
        )
    }

    private companion object {
        const val REQUEST_ADMIN = 2
    }

    /** Android 13+ : notification du service et demandes de connexion. */
    private fun askNotifications() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 1)
        }
    }
}
