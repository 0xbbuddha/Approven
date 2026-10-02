package com.nothingapprove.app

import android.os.Bundle
import androidx.fragment.app.FragmentActivity
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
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import com.nothingapprove.app.protocol.ApproveMessage
import com.nothingapprove.app.protocol.KeyCode

/**
 * Shows one approval or enrollment request and, on Approve, asks for a
 * biometric check before signing. launchMode singleInstance in the
 * manifest: a second request while one is already on screen must not
 * stack a second copy of this activity on top of it.
 */
class ApprovalActivity : FragmentActivity() {
    private enum class Kind { APPROVE, ENROLL }

    private var status by mutableStateOf("")
    private var showActions by mutableStateOf(true)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val kind = if (intent.getStringExtra("kind") == "enroll") Kind.ENROLL else Kind.APPROVE
        val id = intent.getStringExtra("id") ?: ""
        val host = intent.getStringExtra("host") ?: ""
        val user = intent.getStringExtra("user") ?: ""
        val service = intent.getStringExtra("service") ?: ""
        val tty = intent.getStringExtra("tty") ?: ""
        val rhost = intent.getStringExtra("rhost") ?: ""
        val time = intent.getLongExtra("time", 0)
        val nonce = intent.getStringExtra("nonce") ?: ""

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
                                    ConnectionManager.send(WireMessage(type = "approve_response", id = id, approved = false))
                                }
                                finish()
                            }) { Text("Deny") }
                        }
                    }
                }
            }
        }
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
                    ConnectionManager.send(WireMessage(type = "approve_response", id = id, approved = true, signature = bytes))
                    finish()
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    ConnectionManager.send(WireMessage(type = "approve_response", id = id, approved = false))
                    finish()
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
                    ConnectionManager.send(
                        WireMessage(type = "enroll_response", id = id, publicKeyDer = pub.encoded, signature = bytes),
                    )
                    val code = KeyCode.keyCode(pub)
                    val store = PairingStore(this@ApprovalActivity)
                    store.pinnedFingerprint = ConnectionManager.lastServerFingerprint
                    store.enrolledUser = user
                    status = "Code: $code\nType this on the computer."
                    showActions = false
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
