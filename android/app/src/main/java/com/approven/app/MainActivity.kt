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
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
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
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ModalBottomSheet
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
import androidx.compose.ui.text.rememberTextMeasurer
import androidx.compose.ui.text.drawText
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.graphics.RectangleShape
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.draw.drawWithContent
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.draw.clipToBounds
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.PathEffect
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextDecoration
import androidx.compose.ui.text.style.TextOverflow
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
        var selected by remember { mutableStateOf<String?>(null) }

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
                .padding(vertical = 16.dp),
        ) {
            Box(Modifier.padding(horizontal = 20.dp)) { Wordmark() }

            Column(Modifier.fillMaxWidth().padding(16.dp), horizontalAlignment = Alignment.CenterHorizontally) {
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
                Row(
                    Modifier
                        .padding(horizontal = 20.dp)
                        .fillMaxWidth()
                        .background(Amber.copy(alpha = 0.08f))
                        .drawBehind { drawRect(Amber, size = androidx.compose.ui.geometry.Size(3.dp.toPx(), size.height)) }
                        .clickable { startActivity(Intent(Settings.ACTION_MANAGE_APP_USE_FULL_SCREEN_INTENT, Uri.parse("package:$packageName"))) }
                        .padding(horizontal = 16.dp, vertical = 14.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text("Requests can't pop up on their own yet", color = Color.White, fontSize = 14.sp, modifier = Modifier.weight(1f))
                    Text("Allow →", color = Amber, fontWeight = FontWeight.Bold, fontSize = 14.sp)
                }
            }

            Label("machines", "${ready.size}/${computers.size} online".takeIf { computers.isNotEmpty() })
            LazyRow(
                contentPadding = PaddingValues(horizontal = 20.dp),
                horizontalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                items(computers, key = { it.id }) { c ->
                    // Hostname match: what the daemon puts in a request is what enrollment named the computer.
                    val last = history.firstOrNull { it.host == c.name && it.approved }?.service
                    MachineCard(c, stateOf(c), last) { selected = c.id }
                }
                item { PairCard { scanQr() } }
            }
            Text(
                if (adding) "cancel" else "or type an address instead of scanning",
                color = Muted,
                fontSize = 13.sp,
                textDecoration = TextDecoration.Underline,
                modifier = Modifier.padding(horizontal = 24.dp, vertical = 14.dp).clickable { adding = !adding },
            )
            AnimatedVisibility(adding) {
                Column(Modifier.padding(horizontal = 20.dp)) {
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
                }
            }

            val denied = history.count { !it.approved }
            Label("activity", if (history.isEmpty()) null else "${history.size - denied} ✓  $denied ✕")
            Column(Modifier.padding(horizontal = 20.dp)) {
                DotMatrix(history)
                Spacer(Modifier.height(16.dp))
                if (history.isEmpty()) {
                    Text(
                        if (ready.isNotEmpty()) "nothing yet · tap the logo to try one" else "nothing yet",
                        color = Muted, fontFamily = FontFamily.Monospace, fontSize = 13.sp,
                    )
                } else {
                    ActivityLog(history.take(4))
                }
            }
            Spacer(Modifier.height(32.dp))
        }

        computers.firstOrNull { it.id == selected }?.let { c ->
            ComputerSheet(c, stateOf(c), ready = c in ready, onDismiss = { selected = null }, onForget = {
                selected = null
                confirmForget = c
            })
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

    /**
     * Actions for one computer, out of the way until its row is tapped:
     * the list itself stays a calm column of names and states.
     */
    @OptIn(ExperimentalMaterial3Api::class)
    @Composable
    private fun ComputerSheet(c: PairingStore.Computer, state: State, ready: Boolean, onDismiss: () -> Unit, onForget: () -> Unit) {
        var editing by remember(c.id) { mutableStateOf(false) }
        var host by remember(c.id) { mutableStateOf(c.host) }
        var port by remember(c.id) { mutableStateOf(c.port.toString()) }
        ModalBottomSheet(
            onDismissRequest = onDismiss,
            containerColor = Card,
            shape = RectangleShape,
            dragHandle = { Box(Modifier.fillMaxWidth().height(1.dp).background(Mint.copy(alpha = 0.55f))) },
        ) {
            Column(Modifier.padding(horizontal = 24.dp).padding(top = 20.dp, bottom = 24.dp)) {
                Text(c.name, color = Color.White, fontSize = 24.sp, fontWeight = FontWeight.Bold)
                Text(
                    listOfNotNull(c.user?.let { "$it@${c.host}:${c.port}" } ?: "${c.host}:${c.port}", c.pin?.take(16)?.chunked(4)?.joinToString(" ")).joinToString("\n"),
                    color = Muted, fontFamily = FontFamily.Monospace, fontSize = 13.sp, lineHeight = 20.sp,
                )
                Spacer(Modifier.height(20.dp))
                if (editing) {
                    AddressFields(host, port, { host = it }, { port = it })
                    Spacer(Modifier.height(12.dp))
                    PrimaryButton("Save address") {
                        store.update(c.id) { it.copy(host = host.trim(), port = port.toIntOrNull() ?: it.port) }
                        editing = false
                        sync() // a new target takes over the old connection by itself
                    }
                } else {
                    if (ready) SheetAction("test sudo", Mint) { ConnectionManager.requestTest(c.id); onDismiss() }
                    if (c.paused || state == State.OFFLINE) {
                        SheetAction("reconnect", Color.White) {
                            store.update(c.id) { it.copy(paused = false) }
                            sync()
                            onDismiss()
                        }
                    } else {
                        SheetAction("disconnect", Color.White) {
                            store.update(c.id) { it.copy(paused = true) }
                            sync()
                            onDismiss()
                        }
                    }
                    SheetAction("edit address", Color.White) { editing = true }
                    SheetAction("forget", Coral, onClick = onForget)
                }
            }
        }
    }
}

/** A quiet mono label with a right-aligned summary, instead of a big section title. */
@Composable
private fun Label(title: String, summary: String?) {
    Row(Modifier.fillMaxWidth().padding(start = 24.dp, end = 24.dp, top = 28.dp, bottom = 12.dp)) {
        Text(title, color = Muted, fontFamily = FontFamily.Monospace, fontSize = 13.sp, modifier = Modifier.weight(1f))
        if (summary != null) Text(summary, color = Muted, fontFamily = FontFamily.Monospace, fontSize = 13.sp)
    }
}

private val MachineWidth = 248.dp
private val MachineHeight = 168.dp
private val MonoSmall = TextStyle(fontFamily = FontFamily.Monospace, fontSize = 12.sp)

/**
 * A terminal-UI window, the way btop or htop draw their panels: a
 * hairline square frame with the title (and an optional tag) set into
 * its top edge. The shape every panel on this screen uses.
 */
@Composable
private fun TuiFrame(
    title: String,
    tag: String?,
    color: Color,
    modifier: Modifier = Modifier,
    dashed: Boolean = false,
    content: @Composable ColumnScope.() -> Unit,
) {
    val measurer = rememberTextMeasurer()
    Column(
        modifier
            .drawWithContent {
                drawContent()
                val t = measurer.measure(" $title ", MonoSmall.copy(color = Color.White, fontWeight = FontWeight.Bold))
                val g = tag?.let { measurer.measure(" $it ", MonoSmall.copy(color = color)) }
                val y = t.size.height / 2f
                val inset = 10.dp.toPx()
                val stroke = 1.dp.toPx()
                val effect = if (dashed) PathEffect.dashPathEffect(floatArrayOf(6.dp.toPx(), 5.dp.toPx())) else null
                val line = color.copy(alpha = 0.55f)
                fun seg(a: Offset, b: Offset) = drawLine(line, a, b, stroke, pathEffect = effect)
                val left = stroke / 2
                val right = size.width - stroke / 2
                val bottom = size.height - stroke / 2
                val tagStart = g?.let { right - inset - it.size.width } ?: right
                seg(Offset(left, y), Offset(inset, y))
                seg(Offset(inset + t.size.width, y), Offset(tagStart, y))
                if (g != null) seg(Offset(tagStart + g.size.width, y), Offset(right, y))
                seg(Offset(right, y), Offset(right, bottom))
                seg(Offset(right, bottom), Offset(left, bottom))
                seg(Offset(left, bottom), Offset(left, y))
                drawText(t, topLeft = Offset(inset, 0f))
                if (g != null) drawText(g, topLeft = Offset(tagStart, 0f))
            }
            .padding(start = 16.dp, end = 16.dp, top = 26.dp, bottom = 14.dp),
        content = content,
    )
}

/**
 * A computer as its own little terminal: its prompt, the last command
 * this phone approved there, and a cursor that blinks while it is online.
 */
@Composable
private fun MachineCard(c: PairingStore.Computer, state: State, lastCommand: String?, onClick: () -> Unit) {
    val (label, color) = when {
        c.paused -> "paused" to Muted
        state == State.CONNECTED && c.enrolled -> "online" to Mint
        state == State.CONNECTED -> "pairing" to Amber
        state == State.CONNECTING -> "searching" to Amber
        else -> "offline" to Muted
    }
    val live = state == State.CONNECTED && !c.paused
    TuiFrame(c.name, label, color, Modifier.width(MachineWidth).height(MachineHeight).clickable(onClick = onClick)) {
        Text("${c.user ?: "?"}@${c.name}:~", color = color, fontFamily = FontFamily.Monospace, fontSize = 12.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
        Spacer(Modifier.height(6.dp))
        val line = when {
            !c.enrolled && live -> "sudo approve-cli enroll"
            live -> lastCommand.orEmpty()
            else -> ""
        }
        Text(
            buildAnnotatedString {
                withStyle(SpanStyle(color = Muted)) { append("$ ") }
                append(line)
                if (live) withStyle(SpanStyle(color = color.copy(alpha = cursorAlpha()))) { append("█") }
            },
            color = Color.White, fontFamily = FontFamily.Monospace, fontSize = 14.sp, lineHeight = 20.sp, maxLines = 3, overflow = TextOverflow.Ellipsis,
        )
        Spacer(Modifier.weight(1f))
        Text(
            if (live) "${c.host}:${c.port}" else if (c.paused) "# paused" else "# connection lost",
            color = Muted, fontFamily = FontFamily.Monospace, fontSize = 11.sp, maxLines = 1,
        )
    }
}

/** A terminal cursor's blink: fully on, then off, no fade. */
@Composable
private fun cursorAlpha(): Float {
    val t = rememberInfiniteTransition(label = "cursor")
    val v by t.animateFloat(0f, 1f, infiniteRepeatable(tween(1000, easing = LinearEasing)), label = "blink")
    return if (v < 0.5f) 1f else 0f
}

/** The empty slot at the end of the row, dashed, over the logo's ridges: where the next computer goes. */
@Composable
private fun PairCard(onClick: () -> Unit) {
    TuiFrame(
        "new",
        "+",
        Mint,
        Modifier
            .width(MachineWidth)
            .height(MachineHeight)
            .clipToBounds()
            .drawBehind {
                val center = Offset(size.width * 0.98f, size.height * 1.12f)
                for (i in 1..8) {
                    drawCircle(Mint.copy(alpha = 0.16f - i * 0.016f), radius = i * 20.dp.toPx(), center = center, style = Stroke(width = 5.dp.toPx()))
                }
            }
            .clickable(onClick = onClick),
        dashed = true,
    ) {
        Text(
            buildAnnotatedString {
                withStyle(SpanStyle(color = Muted)) { append("$ ") }
                append("sudo approve-cli enroll")
            },
            color = Color.White, fontFamily = FontFamily.Monospace, fontSize = 13.sp,
        )
        Spacer(Modifier.weight(1f))
        Text("> scan the code", color = Mint, fontFamily = FontFamily.Monospace, fontSize = 15.sp, fontWeight = FontWeight.Bold)
    }
}

/**
 * The recent decisions as a strip of pixels - mint approved, coral
 * denied, newest on the left, empty slots dim - so a denial stands out
 * before reading a single line.
 */
@Composable
private fun DotMatrix(history: List<PairingStore.Event>) {
    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
        repeat(PairingStore.HISTORY_SIZE) { i ->
            val e = history.getOrNull(i)
            Box(
                Modifier.size(9.dp).background(
                    when {
                        e == null -> CardHigh
                        e.approved -> Mint
                        else -> Coral
                    },
                ),
            )
        }
    }
}

@Composable
private fun SheetAction(text: String, color: Color, onClick: () -> Unit) {
    Text(
        "> $text",
        color = color,
        fontFamily = FontFamily.Monospace,
        fontSize = 16.sp,
        modifier = Modifier.fillMaxWidth().clickable(onClick = onClick).padding(vertical = 13.dp),
    )
}

/** Approvals as a terminal-style log, grouped by day. */
@Composable
private fun ActivityLog(history: List<PairingStore.Event>) {
    val timeFormat = remember { java.text.DateFormat.getTimeInstance(java.text.DateFormat.SHORT) }
    history.groupBy { dayLabel(it.time) }.forEach { (day, events) ->
        Text(day, color = Muted, fontSize = 12.sp, fontFamily = FontFamily.Monospace, modifier = Modifier.padding(top = 10.dp, bottom = 4.dp))
        events.forEach { e ->
            Row(Modifier.fillMaxWidth().padding(vertical = 6.dp), verticalAlignment = Alignment.CenterVertically) {
                Box(Modifier.width(3.dp).height(18.dp).background(if (e.approved) Mint else Coral))
                Spacer(Modifier.width(12.dp))
                Text(timeFormat.format(java.util.Date(e.time)), color = Muted, fontFamily = FontFamily.Monospace, fontSize = 13.sp)
                Spacer(Modifier.width(12.dp))
                Text(
                    e.service.ifEmpty { "sudo" },
                    color = if (e.approved) Color.White else Muted,
                    fontFamily = FontFamily.Monospace,
                    fontSize = 14.sp,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f),
                )
                Spacer(Modifier.width(8.dp))
                Text(e.host, color = Muted, fontSize = 12.sp)
            }
        }
    }
}

private fun dayLabel(time: Long): String = when {
    DateUtils.isToday(time) -> "today"
    DateUtils.isToday(time + DateUtils.DAY_IN_MILLIS) -> "yesterday"
    else -> java.text.DateFormat.getDateInstance(java.text.DateFormat.MEDIUM).format(java.util.Date(time)).lowercase()
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
            shape = RectangleShape,
            colors = colors,
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
        )
        OutlinedTextField(
            port, { v -> onPort(v.filter { it.isDigit() }.take(5)) }, Modifier.width(96.dp),
            label = { Text("Port") },
            singleLine = true,
            shape = RectangleShape,
            colors = colors,
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
        )
    }
}

@Composable
fun PrimaryButton(text: String, modifier: Modifier = Modifier.fillMaxWidth(), onClick: () -> Unit) {
    Button(
        onClick, modifier.height(52.dp),
        shape = RectangleShape,
        colors = ButtonDefaults.buttonColors(containerColor = Mint, contentColor = Ink),
    ) { Text(text, fontWeight = FontWeight.Bold, fontSize = 16.sp) }
}

@Composable
fun GhostButton(text: String, modifier: Modifier = Modifier.fillMaxWidth(), onClick: () -> Unit) {
    OutlinedButton(
        onClick, modifier.height(52.dp),
        shape = RectangleShape,
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

