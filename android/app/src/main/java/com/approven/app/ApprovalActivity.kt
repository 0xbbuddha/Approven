package com.approven.app

import android.app.NotificationManager
import android.content.Intent
import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.biometric.BiometricPrompt
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.spring
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.scaleIn
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import com.approven.app.protocol.ApproveMessage
import com.approven.app.protocol.KeyCode
import java.text.DateFormat
import java.util.Date
import kotlinx.coroutines.delay

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
 * state (phase, message, code) resets alongside it.
 */
class ApprovalActivity : FragmentActivity() {
    private enum class Kind { APPROVE, ENROLL }

    private var kind by mutableStateOf(Kind.APPROVE)
    private var id by mutableStateOf("")
    private var host by mutableStateOf("")
    private var user by mutableStateOf("")
    private var service by mutableStateOf("")
    private var command by mutableStateOf("")
    private var tty by mutableStateOf("")
    private var rhost by mutableStateOf("")
    private var time by mutableStateOf(0L)
    private var nonce by mutableStateOf("")

    /** Where this screen is in one request's life; [message] and [code] belong to the phase that sets them. */
    private enum class Phase { ASK, WAITING, CODE, DONE, ERROR, EXPIRED }

    private var phase by mutableStateOf(Phase.ASK)
    private var message by mutableStateOf("")
    private var code by mutableStateOf("")

    /** When the computer stops waiting (its own 20 s / 60 s), by this phone's clock. */
    private var deadline by mutableStateOf(0L)
    private var window = APPROVE_WINDOW_MS
    private var prompt: BiometricPrompt? = null

    private companion object {
        // The computer's own waits: approve-helper's 20 s, the daemon's 60 s for enroll.
        const val APPROVE_WINDOW_MS = 20_000L
        const val ENROLL_WINDOW_MS = 60_000L
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        applyIntent(intent)

        enableEdgeToEdge()
        setContent { ApprovenTheme { Screen() } }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        applyIntent(intent)
    }

    private fun applyIntent(i: Intent) {
        if (i.getStringExtra("kind") == "enroll_result") {
            // A reply to the enrollment this screen already showed a
            // code for, not a new request - leave the request fields
            // alone and just report what the computer side decided.
            kind = Kind.ENROLL
            val ok = i.getBooleanExtra("ok", false)
            val error = i.getStringExtra("error") ?: ""
            if (ok) {
                phase = Phase.DONE
                message = "This phone now approves sudo for $user on $host."
            } else {
                fail("Enrollment failed: $error")
            }
            return
        }
        kind = if (i.getStringExtra("kind") == "enroll") Kind.ENROLL else Kind.APPROVE
        id = i.getStringExtra("id") ?: ""
        host = i.getStringExtra("host") ?: ""
        user = i.getStringExtra("user") ?: ""
        service = i.getStringExtra("service") ?: ""
        command = i.getStringExtra("command") ?: ""
        tty = i.getStringExtra("tty") ?: ""
        rhost = i.getStringExtra("rhost") ?: ""
        time = i.getLongExtra("time", 0)
        nonce = i.getStringExtra("nonce") ?: ""
        // A fresh request, including one redelivered to this same
        // instance: whatever a previous request left behind (an error
        // message, the actions already hidden after an earlier
        // approve/deny) must not bleed into this one.
        phase = Phase.ASK
        message = ""
        code = ""
        window = if (kind == Kind.ENROLL) ENROLL_WINDOW_MS else APPROVE_WINDOW_MS
        deadline = System.currentTimeMillis() + window
    }

    override fun onResume() {
        super.onResume()
        // The screen itself is up: the alert that brought it here would
        // otherwise linger in the shade after the request is long gone.
        getSystemService(NotificationManager::class.java).cancel(ConnectionService.ALERT_NOTIFICATION_ID)
    }

    /** The computer stopped waiting (its cancel, or this phone's own clock): nothing left to sign. */
    private fun expire() {
        if (phase != Phase.ASK && phase != Phase.WAITING) return
        // Only WAITING has generated a new key; in ASK the old, still enrolled one must stay.
        val newKeyMade = kind == Kind.ENROLL && phase == Phase.WAITING
        phase = Phase.EXPIRED
        message = "The computer stopped waiting. Run the command again."
        prompt?.cancelAuthentication()
        if (newKeyMade) CryptoKeys.deleteKey()
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

    private fun doApprove(id: String, host: String, user: String, service: String, command: String, tty: String, rhost: String, time: Long, nonce: String) {
        val message = try {
            ApproveMessage.bytesOf(ApproveMessage.ApproveRequest(host, user, service, command, tty, rhost, time, nonce))
        } catch (e: Exception) {
            fail("Could not build the request: ${e.message}")
            return
        }
        val signature = try {
            CryptoKeys.newSignatureForSigning()
        } catch (e: Exception) {
            fail("No key enrolled on this phone for sudo approval.")
            return
        }

        prompt = BiometricPrompt(
            this,
            ContextCompat.getMainExecutor(this),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    if (phase == Phase.EXPIRED) return
                    val sig = result.cryptoObject?.signature ?: return fail("The fingerprint check did not unlock the key. Try again.")
                    sig.update(message)
                    val bytes = sig.sign()
                    sendInBackground(WireMessage(type = "approve_response", id = id, approved = true, signature = bytes)) { ok ->
                        if (!ok) {
                            fail("Lost the connection to the computer before the approval could be sent. Try again.")
                        } else {
                            log(approved = true)
                            finish()
                        }
                    }
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    if (phase == Phase.EXPIRED) return // our own cancelAuthentication()
                    log(approved = false)
                    sendInBackground(WireMessage(type = "approve_response", id = id, approved = false)) { finish() }
                }
            },
        )
        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Approve sudo")
            .setSubtitle("${command.ifEmpty { service }} · code ${ApproveMessage.checkCode(nonce)}")
            .setNegativeButtonText("Cancel")
            .build()
        prompt?.authenticate(info, BiometricPrompt.CryptoObject(signature))
    }

    private fun doEnroll(id: String, host: String, user: String, time: Long, nonce: String) {
        val pub = try {
            CryptoKeys.generateKey()
        } catch (e: Exception) {
            fail("Could not create a key: ${e.message}")
            return
        }
        val keyHash = KeyCode.keyHash(pub)
        // Both ends of the connection this request arrived on, as this
        // phone saw them: the computer compares them with its own view,
        // so a man in the middle makes the enrollment fail instead of
        // leaving this phone pinned to the impostor.
        val serverCert = ConnectionManager.lastServerFingerprint
        val message = try {
            ApproveMessage.bytesOf(
                ApproveMessage.EnrollRequest(host, user, keyHash, CryptoKeys.tlsCertHash(), serverCert ?: "", time, nonce),
            )
        } catch (e: Exception) {
            CryptoKeys.deleteKey()
            fail("Could not build the enrollment: ${e.message}")
            return
        }
        val signature = CryptoKeys.newSignatureForSigning()

        prompt = BiometricPrompt(
            this,
            ContextCompat.getMainExecutor(this),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    if (phase == Phase.EXPIRED) return
                    val sig = result.cryptoObject?.signature ?: return fail("The fingerprint check did not unlock the key. Try again.")
                    sig.update(message)
                    val bytes = sig.sign()
                    sendInBackground(
                        WireMessage(type = "enroll_response", id = id, publicKeyDer = pub.encoded, signature = bytes),
                    ) { ok ->
                        if (!ok) {
                            CryptoKeys.deleteKey()
                            fail("Lost the connection to the computer before the key could be sent. Try again.")
                        } else {
                            code = KeyCode.keyCode(pub)
                            val store = PairingStore(this@ApprovalActivity)
                            store.pinnedFingerprint = serverCert
                            store.enrolledUser = user
                            phase = Phase.CODE
                        }
                    }
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    if (phase == Phase.EXPIRED) return // our own cancelAuthentication(); key already gone
                    CryptoKeys.deleteKey()
                    fail("Enrollment cancelled.")
                }
            },
        )
        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Enroll this phone")
            .setSubtitle("For sudo on $host")
            .setNegativeButtonText("Cancel")
            .build()
        prompt?.authenticate(info, BiometricPrompt.CryptoObject(signature))
    }

    private fun fail(msg: String) {
        phase = Phase.ERROR
        message = msg
    }

    private fun log(approved: Boolean) =
        PairingStore(this).log(PairingStore.Event(System.currentTimeMillis(), command.ifEmpty { service }, user, host, approved))

    private fun deny() {
        if (kind == Kind.APPROVE) {
            log(approved = false)
            sendInBackground(WireMessage(type = "approve_response", id = id, approved = false)) { finish() }
        } else {
            finish()
        }
    }

    @Composable
    private fun Screen() {
        val cancelled by ConnectionManager.cancelled.collectAsState()
        LaunchedEffect(cancelled, id) { if (cancelled == id && id.isNotEmpty()) expire() }
        var now by remember { mutableLongStateOf(System.currentTimeMillis()) }
        LaunchedEffect(deadline) {
            while (System.currentTimeMillis() < deadline) {
                now = System.currentTimeMillis()
                delay(100)
            }
            now = deadline
            expire()
        }
        val left = (deadline - now).coerceAtLeast(0)

        val accent = when (phase) {
            Phase.ERROR -> Coral
            Phase.EXPIRED -> Amber
            else -> Mint
        }
        Column(
            Modifier
                .fillMaxSize()
                .safeDrawingPadding()
                .padding(horizontal = 24.dp, vertical = 16.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Text(
                if (kind == Kind.APPROVE) "SUDO REQUEST" else "NEW PAIRING",
                color = accent,
                fontSize = 12.sp,
                fontWeight = FontWeight.Bold,
                letterSpacing = 2.sp,
                modifier = Modifier.clip(CircleShape).background(accent.copy(alpha = 0.12f)).padding(horizontal = 14.dp, vertical = 6.dp),
            )
            Spacer(Modifier.weight(1f))

            AnimatedContent(
                phase,
                transitionSpec = { (fadeIn() + scaleIn(spring(Spring.DampingRatioMediumBouncy))) togetherWith fadeOut() },
                label = "phase",
            ) { p ->
                Column(Modifier.fillMaxWidth(), horizontalAlignment = Alignment.CenterHorizontally) {
                    when (p) {
                        Phase.DONE -> Badge(Icons.Filled.Check, Mint)
                        Phase.ERROR -> Badge(Icons.Filled.Close, Coral)
                        Phase.EXPIRED -> Badge(Icons.Filled.Refresh, Amber)
                        else -> PulsingLogo(Mint, active = true, size = 180.dp)
                    }
                    Spacer(Modifier.height(16.dp))
                    Text(
                        when (p) {
                            Phase.ASK, Phase.WAITING -> if (kind == Kind.APPROVE) "Allow sudo?" else "Pair this phone?"
                            Phase.CODE -> "Almost there"
                            Phase.DONE -> "All set!"
                            Phase.ERROR -> "Hmm, that didn't work"
                            Phase.EXPIRED -> "Too late!"
                        },
                        color = Color.White,
                        fontSize = 30.sp,
                        fontWeight = FontWeight.Bold,
                        textAlign = TextAlign.Center,
                    )
                    Spacer(Modifier.height(6.dp))
                    Text(
                        when (p) {
                            Phase.ASK, Phase.WAITING ->
                                if (kind == Kind.APPROVE) "$user wants root on $host"
                                else "Use this phone to approve sudo for $user on $host"
                            Phase.CODE -> "Type this code in the terminal running enroll"
                            else -> message
                        },
                        color = Muted,
                        fontSize = 16.sp,
                        textAlign = TextAlign.Center,
                    )
                }
            }

            if (phase == Phase.ASK || phase == Phase.WAITING) {
                Spacer(Modifier.height(16.dp))
                Countdown(left, window)
            }
            Spacer(Modifier.height(24.dp))
            when (phase) {
                Phase.ASK, Phase.WAITING -> if (kind == Kind.APPROVE) Details()
                Phase.CODE -> KeyCodeView(code)
                else -> Unit
            }
            Spacer(Modifier.weight(1f))
            Spacer(Modifier.height(24.dp))

            when (phase) {
                Phase.ASK -> {
                    PrimaryButton(if (kind == Kind.APPROVE) "Approve with fingerprint" else "Pair with fingerprint") {
                        phase = Phase.WAITING
                        if (kind == Kind.APPROVE) {
                            doApprove(id, host, user, service, command, tty, rhost, time, nonce)
                        } else {
                            doEnroll(id, host, user, time, nonce)
                        }
                    }
                    Spacer(Modifier.height(10.dp))
                    GhostButton("Deny") { deny() }
                }
                Phase.WAITING -> CircularProgressIndicator(color = Mint)
                Phase.CODE -> Text("Waiting for the computer…", color = Muted, fontSize = 14.sp)
                Phase.DONE, Phase.ERROR, Phase.EXPIRED -> PrimaryButton(if (phase == Phase.DONE) "Done" else "Close") { finish() }
            }
        }
    }

    @Composable
    private fun Details() {
        CheckCode(ApproveMessage.checkCode(nonce))
        Spacer(Modifier.height(12.dp))
        if (command.isNotEmpty()) {
            Text(
                "# $command",
                color = Mint,
                fontFamily = FontFamily.Monospace,
                fontSize = 15.sp,
                maxLines = 3,
                modifier = Modifier.fillMaxWidth().clip(RoundedCornerShape(16.dp)).background(Card).padding(16.dp),
            )
            Spacer(Modifier.height(12.dp))
        }
        Panel {
            InfoRow("Service", service)
            InfoRow("User", user)
            InfoRow("Computer", host)
            if (tty.isNotEmpty()) InfoRow("Terminal", tty, mono = true)
            if (rhost.isNotEmpty()) InfoRow("From", rhost, mono = true)
            if (time > 0) InfoRow("Asked at", DateFormat.getTimeInstance(DateFormat.MEDIUM).format(Date(time * 1000)))
        }
    }
}

@Composable
private fun Badge(icon: ImageVector, color: Color) {
    Box(Modifier.size(180.dp), contentAlignment = Alignment.Center) {
        Box(Modifier.size(140.dp).clip(CircleShape).background(color.copy(alpha = 0.12f)), contentAlignment = Alignment.Center) {
            Box(Modifier.size(96.dp).clip(CircleShape).background(color), contentAlignment = Alignment.Center) {
                Icon(icon, null, tint = Ink, modifier = Modifier.size(56.dp))
            }
        }
    }
}

/** The enrollment code ("XXXX XXXX XXXX XXXX") on two lines, big enough to read across a desk. */
@Composable
private fun KeyCodeView(code: String) {
    Column(
        Modifier.fillMaxWidth().clip(RoundedCornerShape(24.dp)).background(Card).padding(vertical = 24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        code.split(" ").chunked(2).forEach { line ->
            Text(
                line.joinToString("  "),
                color = Mint,
                fontSize = 32.sp,
                fontWeight = FontWeight.Bold,
                fontFamily = FontFamily.Monospace,
                letterSpacing = 2.sp,
            )
        }
    }
}

/**
 * The code the terminal printed for its own request. Something else
 * running as the user can start a sudo at the same moment; it can't
 * make its request carry the code the user's terminal shows.
 */
@Composable
private fun CheckCode(code: String) {
    Row(
        Modifier.fillMaxWidth().clip(RoundedCornerShape(16.dp)).background(Amber.copy(alpha = 0.12f)).padding(horizontal = 16.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text("Your terminal must show", color = Amber, fontSize = 14.sp, modifier = Modifier.weight(1f))
        Text(code, color = Amber, fontSize = 24.sp, fontWeight = FontWeight.Bold, fontFamily = FontFamily.Monospace, letterSpacing = 3.sp)
    }
}

/** Time left before the computer gives up, turning coral in the last 5 seconds. */
@Composable
private fun Countdown(leftMs: Long, windowMs: Long) {
    val color = if (leftMs < 5_000) Coral else Mint
    Column(Modifier.fillMaxWidth(), horizontalAlignment = Alignment.CenterHorizontally) {
        LinearProgressIndicator(
            progress = { leftMs.toFloat() / windowMs },
            modifier = Modifier.fillMaxWidth().height(6.dp).clip(CircleShape),
            color = color,
            trackColor = CardHigh,
            drawStopIndicator = {},
        )
        Spacer(Modifier.height(6.dp))
        Text("${(leftMs + 999) / 1000}s left", color = color, fontSize = 13.sp, fontWeight = FontWeight.SemiBold)
    }
}
