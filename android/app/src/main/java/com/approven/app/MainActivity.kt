package com.approven.app

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.text.format.DateUtils
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.animateColorAsState
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
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
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import com.approven.app.ConnectionManager.State

/**
 * Home screen: live connection status, the paired computer, and the
 * recent approvals. Pairing itself still has no UI beyond "connect and
 * wait": the enrollment prompt happens in [ApprovalActivity] once the
 * computer's `enroll` command sends its request over this connection.
 */
class MainActivity : ComponentActivity() {
    private val requestNotificationPermission = registerForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { /* Nothing to branch on: an approval still works through the status
          notification's tap target if this was denied, just without the
          immediate full-screen alert - the one actual requirement is that
          the manifest-declared permission has been asked at all. */
    }

    private lateinit var store: PairingStore

    // Re-read on every resume: ApprovalActivity writes these while this screen sits underneath.
    private var enrolled by mutableStateOf(false)
    private var history by mutableStateOf(emptyList<PairingStore.Event>())

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        store = PairingStore(this)

        // Required since Android 13 (API 33): without this, every
        // notification from this app is silently dropped, including the
        // full-screen-intent alert an approval request depends on to
        // ever reach the screen. This is exactly what made the first
        // real end-to-end approval attempt show nothing on the phone.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            requestNotificationPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
        }

        setContent { ApprovenTheme { Home() } }

        if (store.computerHost != null) connect()
    }

    override fun onResume() {
        super.onResume()
        enrolled = store.isEnrolled
        history = store.history
    }

    private fun connect() = startForegroundService(Intent(this, ConnectionService::class.java))

    private fun disconnect() = startService(Intent(this, ConnectionService::class.java).setAction(ConnectionService.ACTION_DISCONNECT))

    @Composable
    private fun Home() {
        val state by ConnectionManager.state.collectAsState()
        var host by remember { mutableStateOf(store.computerHost ?: "") }
        var port by remember { mutableStateOf(store.computerPort.toString()) }
        var editing by remember { mutableStateOf(false) }
        var confirmForget by remember { mutableStateOf(false) }

        val test by ConnectionManager.test.collectAsState()
        val ready = enrolled && state == State.CONNECTED
        // Connected but not enrolled is not "ready": nothing can be approved yet.
        val color by animateColorAsState(
            when {
                ready -> Mint
                state == State.OFFLINE -> Muted
                else -> Amber
            },
            label = "status",
        )

        Column(
            Modifier
                .fillMaxSize()
                .safeDrawingPadding()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 20.dp, vertical = 16.dp),
        ) {
            Wordmark()

            Column(Modifier.fillMaxWidth().padding(vertical = 16.dp), horizontalAlignment = Alignment.CenterHorizontally) {
                Box(
                    Modifier
                        .clip(CircleShape)
                        .clickable(enabled = ready, onClickLabel = "Test sudo") { ConnectionManager.requestTest() },
                ) {
                    PulsingLogo(color, active = state != State.OFFLINE, size = 220.dp)
                }
                Text(
                    when (state) {
                        State.CONNECTED -> if (enrolled) "Ready to approve" else "Not paired yet"
                        State.CONNECTING -> "Looking for your computer…"
                        State.OFFLINE -> "Offline"
                    },
                    fontSize = 26.sp,
                    fontWeight = FontWeight.Bold,
                    color = Color.White,
                )
                Spacer(Modifier.height(4.dp))
                Text(
                    when {
                        ready -> "sudo for ${store.enrolledUser} on ${store.computerHost}"
                        state == State.CONNECTED -> "Run sudo approve-cli enroll on the computer"
                        store.computerHost != null -> "${store.computerHost}:${store.computerPort}"
                        else -> "Pair a computer to get started"
                    },
                    color = Muted,
                    fontSize = 15.sp,
                )
                Spacer(Modifier.height(16.dp))
                StatusChip(
                    when {
                        ready -> "Connected"
                        state == State.CONNECTED -> "Connected · not paired"
                        state == State.CONNECTING -> "Connecting"
                        else -> "Not connected"
                    },
                    color,
                )
                if (ready) {
                    Spacer(Modifier.height(12.dp))
                    TestStatus(test)
                }
            }

            if (!enrolled) {
                SectionLabel("Pair a computer")
                Panel {
                    AddressFields(host, port, { host = it }, { port = it })
                    Spacer(Modifier.height(16.dp))
                    PrimaryButton(if (state == State.OFFLINE) "Connect" else "Reconnect") {
                        saveAddress(host, port)
                        connect()
                    }
                    Spacer(Modifier.height(20.dp))
                    Step(1, "Connect to the computer's LAN IP, port 17165.")
                    Step(2, "On the computer, run", "sudo approve-cli enroll")
                    Step(3, "Approve here with your fingerprint.")
                    Step(4, "Type the code this phone shows into the terminal.")
                    if (store.computerHost != null) {
                        TextButton(onClick = { confirmForget = true }, modifier = Modifier.align(Alignment.CenterHorizontally)) {
                            Text("Forget this computer", color = Coral)
                        }
                    }
                }
            } else {
                SectionLabel("Paired computer")
                Panel {
                    InfoRow("Computer", "${store.computerHost}:${store.computerPort}")
                    InfoRow("User", store.enrolledUser ?: "")
                    InfoRow("Certificate", store.pinnedFingerprint?.take(16)?.chunked(4)?.joinToString(" ") ?: "", mono = true)

                    AnimatedVisibility(editing) {
                        Column(Modifier.padding(top = 12.dp)) {
                            AddressFields(host, port, { host = it }, { port = it })
                        }
                    }
                    Spacer(Modifier.height(16.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                        if (editing) {
                            PrimaryButton("Save", Modifier.weight(1f)) {
                                saveAddress(host, port)
                                editing = false
                                connect() // a new target takes over the old connection by itself
                            }
                        } else if (state == State.OFFLINE) {
                            PrimaryButton("Reconnect", Modifier.weight(1f)) { connect() }
                        } else {
                            GhostButton("Disconnect", Modifier.weight(1f)) { disconnect() }
                        }
                        GhostButton(if (editing) "Cancel" else "Edit address", Modifier.weight(1f)) { editing = !editing }
                    }
                    TextButton(onClick = { confirmForget = true }, modifier = Modifier.align(Alignment.CenterHorizontally)) {
                        Text("Forget this computer", color = Coral)
                    }
                }
            }

            SectionLabel("Recent activity")
            Panel {
                if (history.isEmpty()) {
                    Text("Nothing yet.", color = Color.White, fontWeight = FontWeight.SemiBold)
                    Spacer(Modifier.height(4.dp))
                    Text("Try it from a terminal:", color = Muted, fontSize = 14.sp)
                    Spacer(Modifier.height(8.dp))
                    Code("sudo -k && sudo true")
                } else {
                    history.forEachIndexed { i, e ->
                        if (i > 0) Spacer(Modifier.height(14.dp))
                        HistoryRow(e)
                    }
                }
            }
            Spacer(Modifier.height(24.dp))
        }

        if (confirmForget) {
            AlertDialog(
                onDismissRequest = { confirmForget = false },
                containerColor = CardHigh,
                title = { Text("Forget this computer?") },
                text = { Text("This phone's key is deleted. Run `sudo approve-cli remove` on the computer too, then pair again to use Approven.") },
                confirmButton = {
                    TextButton(onClick = {
                        confirmForget = false
                        disconnect()
                        CryptoKeys.deleteAll()
                        store.clear()
                        enrolled = false
                        history = emptyList()
                        host = ""
                    }) { Text("Forget", color = Coral) }
                },
                dismissButton = { TextButton(onClick = { confirmForget = false }) { Text("Keep") } },
            )
        }
    }

    private fun saveAddress(host: String, port: String) {
        store.computerHost = host.trim()
        store.computerPort = port.toIntOrNull() ?: store.computerPort
    }
}

/** The "tap the logo" test: a hint, then what the computer's `sudo true` came back with. */
@Composable
private fun TestStatus(test: ConnectionManager.Test) {
    val (text, color) = when (test) {
        ConnectionManager.Test.Idle -> "Tap the logo to test sudo" to Muted
        ConnectionManager.Test.Running -> "Running sudo true… approve it here" to Amber
        is ConnectionManager.Test.Done ->
            if (test.ok) "✓ sudo true worked" to Mint else "✗ ${test.error.ifEmpty { "sudo true failed" }}" to Coral
    }
    Text(text, color = color, fontSize = 14.sp, fontWeight = FontWeight.Medium)
}

@Composable
private fun StatusChip(label: String, color: Color) {
    Row(
        Modifier.clip(CircleShape).background(color.copy(alpha = 0.12f)).padding(horizontal = 14.dp, vertical = 6.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Box(Modifier.size(8.dp).clip(CircleShape).background(color))
        Spacer(Modifier.width(8.dp))
        Text(
            label,
            color = color,
            fontSize = 13.sp,
            fontWeight = FontWeight.SemiBold,
        )
    }
}

@Composable
private fun AddressFields(host: String, port: String, onHost: (String) -> Unit, onPort: (String) -> Unit) {
    val colors = OutlinedTextFieldDefaults.colors(
        focusedBorderColor = Mint,
        unfocusedBorderColor = CardHigh,
        focusedLabelColor = Mint,
        cursorColor = Mint,
    )
    Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
        OutlinedTextField(
            host, onHost, Modifier.weight(1f),
            label = { Text("Computer IP") },
            singleLine = true,
            shape = RoundedCornerShape(16.dp),
            colors = colors,
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
        )
        OutlinedTextField(
            port, { v -> onPort(v.filter { it.isDigit() }.take(5)) }, Modifier.width(96.dp),
            label = { Text("Port") },
            singleLine = true,
            shape = RoundedCornerShape(16.dp),
            colors = colors,
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
        )
    }
}

@Composable
fun PrimaryButton(text: String, modifier: Modifier = Modifier.fillMaxWidth(), onClick: () -> Unit) {
    Button(
        onClick, modifier.height(52.dp),
        shape = RoundedCornerShape(16.dp),
        colors = ButtonDefaults.buttonColors(containerColor = Mint, contentColor = Ink),
    ) { Text(text, fontWeight = FontWeight.Bold, fontSize = 16.sp) }
}

@Composable
fun GhostButton(text: String, modifier: Modifier = Modifier.fillMaxWidth(), onClick: () -> Unit) {
    OutlinedButton(
        onClick, modifier.height(52.dp),
        shape = RoundedCornerShape(16.dp),
        border = androidx.compose.foundation.BorderStroke(1.dp, CardHigh),
        colors = ButtonDefaults.outlinedButtonColors(contentColor = Color.White),
    ) { Text(text, fontWeight = FontWeight.SemiBold) }
}

@Composable
fun InfoRow(label: String, value: String, mono: Boolean = false) {
    Row(Modifier.fillMaxWidth().padding(vertical = 6.dp), verticalAlignment = Alignment.CenterVertically) {
        Text(label, color = Muted, fontSize = 14.sp, modifier = Modifier.width(110.dp))
        Text(
            value,
            color = Color.White,
            fontSize = 15.sp,
            fontWeight = FontWeight.Medium,
            fontFamily = if (mono) FontFamily.Monospace else FontFamily.Default,
        )
    }
}

@Composable
private fun Code(text: String) {
    Text(
        "$ $text",
        color = Mint,
        fontFamily = FontFamily.Monospace,
        fontSize = 14.sp,
        modifier = Modifier.fillMaxWidth().clip(RoundedCornerShape(12.dp)).background(Ink).padding(12.dp),
    )
}

@Composable
private fun Step(n: Int, text: String, code: String? = null) {
    Row(Modifier.padding(vertical = 6.dp)) {
        Box(Modifier.size(26.dp).clip(CircleShape).background(Mint.copy(alpha = 0.15f)), contentAlignment = Alignment.Center) {
            Text("$n", color = Mint, fontWeight = FontWeight.Bold, fontSize = 13.sp)
        }
        Spacer(Modifier.width(12.dp))
        Column(Modifier.padding(top = 3.dp)) {
            Text(text, color = Color.White, fontSize = 14.sp)
            if (code != null) {
                Spacer(Modifier.height(6.dp))
                Code(code)
            }
        }
    }
}

@Composable
private fun HistoryRow(e: PairingStore.Event) {
    val c = if (e.approved) Mint else Coral
    Row(verticalAlignment = Alignment.CenterVertically) {
        Box(Modifier.size(36.dp).clip(CircleShape).background(c.copy(alpha = 0.15f)), contentAlignment = Alignment.Center) {
            Icon(if (e.approved) Icons.Filled.Check else Icons.Filled.Close, null, tint = c, modifier = Modifier.size(20.dp))
        }
        Spacer(Modifier.width(12.dp))
        Column(Modifier.weight(1f)) {
            Text(
                "${e.service.ifEmpty { "sudo" }} · ${e.user}",
                color = Color.White, fontWeight = FontWeight.SemiBold, fontSize = 15.sp,
            )
            Text(e.host, color = Muted, fontSize = 13.sp)
        }
        Text(
            DateUtils.getRelativeTimeSpanString(e.time, System.currentTimeMillis(), DateUtils.MINUTE_IN_MILLIS).toString(),
            color = Muted, fontSize = 12.sp,
        )
    }
}
