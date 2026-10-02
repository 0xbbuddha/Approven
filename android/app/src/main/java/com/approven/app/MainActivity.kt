package com.approven.app

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat

/**
 * Pairing and status screen. Pairing itself has no UI beyond "connect
 * and wait": the actual enrollment prompt (biometric check, key code)
 * happens in [ApprovalActivity] once the computer's `enroll` command
 * sends its request over the connection this screen opens.
 */
class MainActivity : ComponentActivity() {
    private val requestNotificationPermission = registerForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { /* Nothing to branch on: an approval still works through the status
          notification's tap target if this was denied, just without the
          immediate full-screen alert - the one actual requirement is that
          the manifest-declared permission has been asked at all. */
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val store = PairingStore(this)

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

        setContent {
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    var host by remember { mutableStateOf(store.computerHost ?: "") }
                    var port by remember { mutableStateOf(store.computerPort.toString()) }
                    var status by remember { mutableStateOf(if (store.isEnrolled) "Enrolled for ${store.enrolledUser}" else "Not enrolled") }

                    Column(
                        modifier = Modifier.fillMaxSize().padding(24.dp),
                        verticalArrangement = Arrangement.Center,
                    ) {
                        Text("Approven")
                        Text(status)
                        OutlinedTextField(value = host, onValueChange = { host = it }, label = { Text("Computer IP") })
                        OutlinedTextField(value = port, onValueChange = { port = it }, label = { Text("Port") })
                        Button(onClick = {
                            store.computerHost = host
                            store.computerPort = port.toIntOrNull() ?: store.computerPort
                            startForegroundService(Intent(this@MainActivity, ConnectionService::class.java))
                            status = "Connecting..."
                        }) { Text("Connect") }

                        if (store.isEnrolled) {
                            Button(onClick = {
                                CryptoKeys.deleteKey()
                                store.clear()
                                status = "Not enrolled"
                            }) { Text("Forget this computer") }
                        }
                    }
                }
            }
        }

        if (store.computerHost != null) {
            startForegroundService(Intent(this, ConnectionService::class.java))
        }
    }
}
