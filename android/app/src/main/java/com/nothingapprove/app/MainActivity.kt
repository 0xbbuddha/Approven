package com.nothingapprove.app

import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

/**
 * Pairing and status screen. Pairing itself has no UI beyond "connect
 * and wait": the actual enrollment prompt (biometric check, key code)
 * happens in [ApprovalActivity] once the computer's `enroll` command
 * sends its request over the connection this screen opens.
 */
class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val store = PairingStore(this)

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
                        Text("Nothing Approve")
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
