package com.approven.app

import android.Manifest
import android.app.NotificationManager
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.net.Uri
import android.os.Bundle
import android.provider.Settings
import android.text.format.DateUtils
import android.widget.Toast
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
import com.approven.app.protocol.PairingUri
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.codescanner.GmsBarcodeScannerOptions
import com.google.mlkit.vision.codescanner.GmsBarcodeScanning
import java.util.UUID

/**
 * Home screen: live status, the known computers, adding one (QR code or
 * by hand), and the recent approvals. Enrollment itself happens in
 * [ApprovalActivity] once a computer's `enroll` command sends its
 * request over the connection made here.
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

    // Re-read on every resume and after every change: ApprovalActivity writes the store while this screen sits underneath.
    private var computers by mutableStateOf(emptyList<PairingStore.Computer>())
    private var history by mutableStateOf(emptyList<PairingStore.Event>())
    private var fullScreenBlocked by mutableStateOf(false)

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

        if (store.computers.isNotEmpty()) sync()
    }

    override fun onResume() {
        super.onResume()
        reload()
        // Not granted by default since Android 14: without it a request
        // never opens on its own, it only waits in the notification shade.
        fullScreenBlocked = Build.VERSION.SDK_INT >= 34 &&
            !getSystemService(NotificationManager::class.java).canUseFullScreenIntent()
    }

    private fun reload() {
        computers = store.computers
        history = store.history
    }

    /** Applies a change to the list: the service connects every listed computer and drops the rest. */
    private fun sync() {
        reload()
        startForegroundService(Intent(this, ConnectionService::class.java))
    }

    private fun scanQr() {
        val options = GmsBarcodeScannerOptions.Builder().setBarcodeFormats(Barcode.FORMAT_QR_CODE).build()
        GmsBarcodeScanning.getClient(this, options).startScan()
            .addOnSuccessListener { code ->
                val p = PairingUri.parse(code.rawValue.orEmpty())
                if (p == null) toast("That is not an Approven pairing code.") else addComputer(p.host, p.port, p.name, p.fingerprint)
            }
            .addOnFailureListener { toast("The QR scanner is not available: ${it.message}") }
    }

    /**
     * A computer already in the list - same pinned certificate, or same
     * address - is updated in place (a new QR code after its IP changed)
     * rather than added twice. A different certificate for it means a
     * reinstalled daemon: its old pairing no longer counts.
     */
    private fun addComputer(host: String, port: Int, name: String, pin: String?) {
        val existing = store.computers.firstOrNull { (pin != null && it.pin == pin) || (it.host == host && it.port == port) }
        store.save(
            when {
                existing == null -> PairingStore.Computer(UUID.randomUUID().toString(), host, port, name, pin)
                pin != null && existing.pin != pin -> existing.copy(host = host, port = port, pin = pin, user = null, paused = false)
                else -> existing.copy(host = host, port = port, paused = false)
            },
        )
        sync()
    }

    private fun forget(c: PairingStore.Computer) {
        store.remove(c.id)
        ConnectionManager.disconnect(c.id)
        // The keys are shared by every computer; only the last one going takes them along.
        if (store.computers.isEmpty()) CryptoKeys.deleteAll()
        sync()
    }

    private fun toast(text: String) = Toast.makeText(this, text, Toast.LENGTH_LONG).show()

    @Composable
    private fun Home() {
        val states by ConnectionManager.states.collectAsState()
        val test by ConnectionManager.test.collectAsState()
        var adding by remember { mutableStateOf(false) }
        var host by remember { mutableStateOf("") }
        var port by remember { mutableStateOf(PairingStore.DEFAULT_PORT.toString()) }
        var confirmForget by remember { mutableStateOf<PairingStore.Computer?>(null) }

        fun stateOf(c: PairingStore.Computer) = states[c.id] ?: State.OFFLINE
        val ready = computers.filter { it.enrolled && stateOf(it) == State.CONNECTED }
        val unpaired = computers.any { !it.enrolled && stateOf(it) == State.CONNECTED }
        val connecting = computers.any { stateOf(it) == State.CONNECTING }
        // Connected but not enrolled is not "ready": nothing can be approved yet.
        val color by animateColorAsState(
            when {
                ready.isNotEmpty() -> Mint
                unpaired || connecting -> Amber
                else -> Muted
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
                        .clickable(enabled = ready.isNotEmpty(), onClickLabel = "Test sudo") { ConnectionManager.requestTest(ready.first().id) },
                ) {
                    PulsingLogo(color, active = ready.isNotEmpty() || unpaired || connecting, size = 220.dp)
                }
                Text(
                    when {
                        computers.isEmpty() -> "Add a computer"
                        ready.isNotEmpty() -> "Ready to approve"
                        unpaired -> "Not paired yet"
                        connecting -> "Looking for your computer…"
                        else -> "Offline"
                    },
                    fontSize = 26.sp,
                    fontWeight = FontWeight.Bold,
                    color = Color.White,
                )
                Spacer(Modifier.height(4.dp))
                Text(
                    when {
                        ready.isNotEmpty() -> "sudo on ${ready.joinToString { it.name }}"
                        unpaired -> "Run sudo approve-cli enroll on the computer"
                        computers.isEmpty() -> "Scan the code from sudo approve-cli enroll"
                        else -> "${computers.size} computer${if (computers.size > 1) "s" else ""} known"
                    },
                    color = Muted,
                    fontSize = 15.sp,
                )
                if (ready.isNotEmpty()) {
                    Spacer(Modifier.height(12.dp))
                    TestStatus(test)
                }
            }

            if (fullScreenBlocked) {
                Panel(Modifier.padding(bottom = 8.dp)) {
                    Text("Let requests open on their own", color = Amber, fontWeight = FontWeight.Bold, fontSize = 16.sp)
                    Spacer(Modifier.height(4.dp))
                    Text(
                        "Android does not let Approven show a request full screen yet, so it only waits in your notifications.",
                        color = Color.White, fontSize = 14.sp,
                    )
                    Spacer(Modifier.height(12.dp))
                    PrimaryButton("Allow full-screen alerts") {
                        startActivity(Intent(Settings.ACTION_MANAGE_APP_USE_FULL_SCREEN_INTENT, Uri.parse("package:$packageName")))
                    }
                }
            }

            if (computers.isNotEmpty()) {
                SectionLabel("Computers")
                computers.forEach { c ->
                    ComputerCard(c, stateOf(c), onForget = { confirmForget = c })
                    Spacer(Modifier.height(12.dp))
                }
            }

            SectionLabel("Add a computer")
            Panel {
                Step(1, "On the computer, run", "sudo approve-cli enroll")
                Step(2, "Scan the QR code it shows.")
                Step(3, "Approve here with your fingerprint, then type the code this phone shows into the terminal.")
                Spacer(Modifier.height(12.dp))
                PrimaryButton("Scan QR code") { scanQr() }
                Spacer(Modifier.height(10.dp))
                AnimatedVisibility(adding) {
                    Column {
                        AddressFields(host, port, { host = it }, { port = it })
                        Spacer(Modifier.height(10.dp))
                        PrimaryButton("Connect") {
                            val h = host.trim()
                            if (h.isNotEmpty()) {
                                addComputer(h, port.toIntOrNull() ?: PairingStore.DEFAULT_PORT, h, null)
                                adding = false
                                host = ""
                            }
                        }
                        Spacer(Modifier.height(10.dp))
                    }
                }
                GhostButton(if (adding) "Cancel" else "Enter the address by hand") { adding = !adding }
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

        confirmForget?.let { c ->
            AlertDialog(
                onDismissRequest = { confirmForget = null },
                containerColor = CardHigh,
                title = { Text("Forget ${c.name}?") },
                text = { Text("This phone stops approving for it. Run `sudo approve-cli remove` on that computer too.") },
                confirmButton = {
                    TextButton(onClick = {
                        confirmForget = null
                        forget(c)
                    }) { Text("Forget", color = Coral) }
                },
                dismissButton = { TextButton(onClick = { confirmForget = null }) { Text("Keep") } },
            )
        }
    }

    @Composable
    private fun ComputerCard(c: PairingStore.Computer, state: State, onForget: () -> Unit) {
        var editing by remember(c.id) { mutableStateOf(false) }
        var host by remember(c.id) { mutableStateOf(c.host) }
        var port by remember(c.id) { mutableStateOf(c.port.toString()) }
        val (label, color) = when {
            c.paused -> "Paused" to Muted
            state == State.CONNECTED && c.enrolled -> "Connected" to Mint
            state == State.CONNECTED -> "Not paired" to Amber
            state == State.CONNECTING -> "Connecting" to Amber
            else -> "Offline" to Muted
        }
        Panel {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text(c.name, color = Color.White, fontWeight = FontWeight.Bold, fontSize = 18.sp)
                    Text("${c.host}:${c.port}", color = Muted, fontSize = 13.sp)
                }
                StatusChip(label, color)
            }
            Spacer(Modifier.height(8.dp))
            if (c.enrolled) {
                InfoRow("User", c.user.orEmpty())
                InfoRow("Certificate", c.pin.orEmpty().take(16).chunked(4).joinToString(" "), mono = true)
            } else {
                Text("Not paired yet: run sudo approve-cli enroll on it.", color = Amber, fontSize = 14.sp)
            }
            AnimatedVisibility(editing) {
                Column(Modifier.padding(top = 12.dp)) {
                    AddressFields(host, port, { host = it }, { port = it })
                }
            }
            Spacer(Modifier.height(16.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                if (editing) {
                    PrimaryButton("Save", Modifier.weight(1f)) {
                        store.update(c.id) { it.copy(host = host.trim(), port = port.toIntOrNull() ?: it.port) }
                        editing = false
                        sync() // a new target takes over the old connection by itself
                    }
                } else if (c.paused || state == State.OFFLINE) {
                    PrimaryButton("Reconnect", Modifier.weight(1f)) {
                        store.update(c.id) { it.copy(paused = false) }
                        sync()
                    }
                } else {
                    GhostButton("Disconnect", Modifier.weight(1f)) {
                        store.update(c.id) { it.copy(paused = true) }
                        sync()
                    }
                }
                GhostButton(if (editing) "Cancel" else "Edit address", Modifier.weight(1f)) { editing = !editing }
            }
            TextButton(onClick = onForget, modifier = Modifier.align(Alignment.CenterHorizontally)) {
                Text("Forget this computer", color = Coral)
            }
        }
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
