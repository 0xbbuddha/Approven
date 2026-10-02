package com.approven.app

import android.content.Intent
import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.biometric.BiometricPrompt
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import com.approven.app.protocol.ApproveMessage
import com.approven.app.protocol.KeyCode

/**
 * Shows one approval or enrollment request and, on Approve, asks for a
 * biometric check before signing.
 *
 * launchMode singleInstance in the manifest means a second request
 * while this screen is already around does not stack a second copy -
 * Android instead redelivers the new Intent to the *same* instance
 * through onNewIntent, skipping onCreate entirely. The first version
 * only ever read its extras in onCreate, so a request that arrived
 * while an older instance was still alive (even one the user had
 * already finished looking at - the instance was just never destroyed)
 * showed the previous request's data, or nothing new at all. All of
 * the request fields now live in Compose state that onNewIntent
 * updates the same way onCreate does, and every piece of per-request
 * state (status, showActions) resets alongside it.
 */
class ApprovalActivity : FragmentActivity() {
    private enum class Kind { APPROVE, ENROLL }

    private var kind by mutableStateOf(Kind.APPROVE)
    private var id by mutableStateOf("")
    private var host by mutableStateOf("")
    private var user by mutableStateOf("")
    private var service by mutableStateOf("")
    private var tty by mutableStateOf("")
    private var rhost by mutableStateOf("")
    private var time by mutableStateOf(0L)
    private var nonce by mutableStateOf("")

    private var status by mutableStateOf("")
    private var showActions by mutableStateOf(true)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        applyIntent(intent)

        setContent {
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    Column(
                        modifier = Modifier.fillMaxSize().padding(24.dp),
                        verticalArrangement = Arrangement.Center,
                    ) {
                        if (kind == Kind.APPROVE) {
                            Text("Approve $service for $user on $host?")
                            if (tty.isNotEmpty()) Text("Terminal: $tty")
                            if (rhost.isNotEmpty()) Text("From: $rhost")
                        } else {
                            Text("Use this phone to approve sudo for $user on $host?")
                        }
                        Text(status)
                        if (showActions) {
                            Button(onClick = {
                                showActions = false
                                if (kind == Kind.APPROVE) {
                                    doApprove(id, host, user, service, tty, rhost, time, nonce)
                                } else {
                                    doEnroll(id, host, user, time, nonce)
                                }
                            }) { Text("Approve") }
                            Button(onClick = {
                                if (kind == Kind.APPROVE) {
                                    sendInBackground(WireMessage(type = "approve_response", id = id, approved = false)) { finish() }
                                } else {
                                    finish()
                                }
                            }) { Text("Deny") }
                        }
                    }
                }
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        applyIntent(intent)
    }

    private fun applyIntent(i: Intent) {
        kind = if (i.getStringExtra("kind") == "enroll") Kind.ENROLL else Kind.APPROVE
        id = i.getStringExtra("id") ?: ""
        host = i.getStringExtra("host") ?: ""
        user = i.getStringExtra("user") ?: ""
        service = i.getStringExtra("service") ?: ""
        tty = i.getStringExtra("tty") ?: ""
        rhost = i.getStringExtra("rhost") ?: ""
        time = i.getLongExtra("time", 0)
        nonce = i.getStringExtra("nonce") ?: ""
        // A fresh request, including one redelivered to this same
        // instance: whatever a previous request left behind (an error
        // message, the actions already hidden after an earlier
        // approve/deny) must not bleed into this one.
        status = ""
        showActions = true
    }

    /**
     * ConnectionManager.send writes to a live socket, which Android
     * forbids on the main thread (NetworkOnMainThreadException) - every
     * call site here runs from a BiometricPrompt callback or a Compose
     * click handler, both of which are the main thread. onDone always
     * runs back on the main thread, since it is UI state.
     */
    private fun sendInBackground(msg: WireMessage, onDone: (Boolean) -> Unit) {
        Thread {
            val ok = ConnectionManager.send(msg)
            runOnUiThread { onDone(ok) }
        }.start()
    }

    private fun doApprove(id: String, host: String, user: String, service: String, tty: String, rhost: String, time: Long, nonce: String) {
        val message = try {
            ApproveMessage.bytesOf(ApproveMessage.ApproveRequest(host, user, service, tty, rhost, time, nonce))
        } catch (e: Exception) {
            status = "Could not build the request: ${e.message}"
            return
        }
        val signature = try {
            CryptoKeys.newSignatureForSigning()
        } catch (e: Exception) {
            status = "No key enrolled on this phone for sudo approval."
            return
        }

        val prompt = BiometricPrompt(
            this,
            ContextCompat.getMainExecutor(this),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    val sig = result.cryptoObject?.signature ?: return
                    sig.update(message)
                    val bytes = sig.sign()
                    sendInBackground(WireMessage(type = "approve_response", id = id, approved = true, signature = bytes)) { ok ->
                        if (!ok) {
                            status = "Lost the connection to the computer before the approval could be sent. Try again."
                            showActions = false
                        } else {
                            finish()
                        }
                    }
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    sendInBackground(WireMessage(type = "approve_response", id = id, approved = false)) { finish() }
                }
            },
        )
        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Approve sudo")
            .setSubtitle("$service for $user on $host")
            .setNegativeButtonText("Cancel")
            .build()
        prompt.authenticate(info, BiometricPrompt.CryptoObject(signature))
    }

    private fun doEnroll(id: String, host: String, user: String, time: Long, nonce: String) {
        val pub = try {
            CryptoKeys.generateKey()
        } catch (e: Exception) {
            status = "Could not create a key: ${e.message}"
            return
        }
        val keyHash = KeyCode.keyHash(pub)
        val message = try {
            ApproveMessage.bytesOf(ApproveMessage.EnrollRequest(host, user, keyHash, time, nonce))
        } catch (e: Exception) {
            CryptoKeys.deleteKey()
            status = "Could not build the enrollment: ${e.message}"
            return
        }
        val signature = CryptoKeys.newSignatureForSigning()

        val prompt = BiometricPrompt(
            this,
            ContextCompat.getMainExecutor(this),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    val sig = result.cryptoObject?.signature ?: return
                    sig.update(message)
                    val bytes = sig.sign()
                    sendInBackground(
                        WireMessage(type = "enroll_response", id = id, publicKeyDer = pub.encoded, signature = bytes),
                    ) { ok ->
                        if (!ok) {
                            CryptoKeys.deleteKey()
                            status = "Lost the connection to the computer before the key could be sent. Try again."
                            showActions = false
                        } else {
                            val code = KeyCode.keyCode(pub)
                            val store = PairingStore(this@ApprovalActivity)
                            store.pinnedFingerprint = ConnectionManager.lastServerFingerprint
                            store.enrolledUser = user
                            status = "Code: $code\nType this on the computer."
                            showActions = false
                        }
                    }
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    CryptoKeys.deleteKey()
                    status = "Cancelled."
                    showActions = false
                }
            },
        )
        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Enroll this phone")
            .setSubtitle("For sudo on $host")
            .setNegativeButtonText("Cancel")
            .build()
        prompt.authenticate(info, BiometricPrompt.CryptoObject(signature))
    }
}
