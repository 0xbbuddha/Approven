package com.nothingapprove.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.os.IBinder

/**
 * Keeps [ConnectionManager] connected while the phone is reachable, so
 * an approval request can arrive at any time, not just while the app is
 * on screen. A foreground service with a persistent notification is
 * what lets Android let this socket live in the background at all, and
 * also what lets the user see at a glance whether it actually is.
 */
class ConnectionService : Service() {
    companion object {
        private const val CHANNEL_ID = "nothing-approve-connection"
        private const val NOTIFICATION_ID = 1
        const val ACTION_DISCONNECT = "com.nothingapprove.app.DISCONNECT"
    }

    private var connecting = false

    override fun onCreate() {
        super.onCreate()
        createChannel()
        startForeground(NOTIFICATION_ID, buildNotification("Not connected"))

        ConnectionManager.setListener(object : ConnectionManager.Listener {
            override fun onConnected() {
                connecting = false
                updateNotification("Connected to ${PairingStore(this@ConnectionService).computerHost}")
            }

            override fun onDisconnected() {
                updateNotification(if (connecting) "Connecting..." else "Not connected")
                if (!stoppedByUser) reconnectSoon()
            }

            override fun onApproveRequest(msg: WireMessage) {
                launchApproval(msg)
            }

            override fun onEnrollRequest(msg: WireMessage) {
                launchEnroll(msg)
            }
        })

        connectIfConfigured()
    }

    private var stoppedByUser = false

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_DISCONNECT) {
            stoppedByUser = true
            ConnectionManager.disconnect()
            updateNotification("Not connected")
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return START_NOT_STICKY
        }
        stoppedByUser = false
        connectIfConfigured()
        return START_STICKY
    }

    override fun onDestroy() {
        ConnectionManager.setListener(null)
        ConnectionManager.disconnect()
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private fun connectIfConfigured() {
        val store = PairingStore(this)
        val host = store.computerHost ?: return
        connecting = true
        updateNotification("Connecting...")
        ConnectionManager.connect(host, store.computerPort, store.pinnedFingerprint, store.deviceId, store.deviceName)
    }

    private fun reconnectSoon() {
        // A short, fixed backoff is enough for v1: the common case is a
        // Wi-Fi blip or the computer sleeping, not a permanently gone
        // peer. A phone that never finds the computer again just stays
        // in "Not connected", which status already shows truthfully.
        android.os.Handler(mainLooper).postDelayed({ if (!stoppedByUser) connectIfConfigured() }, 5000)
    }

    private fun launchApproval(msg: WireMessage) {
        val intent = Intent(this, ApprovalActivity::class.java).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            putExtra("kind", "approve")
            putExtra("id", msg.id)
            putExtra("host", msg.host)
            putExtra("user", msg.user)
            putExtra("service", msg.service)
            putExtra("tty", msg.tty)
            putExtra("rhost", msg.rhost)
            putExtra("time", msg.time)
            putExtra("nonce", msg.nonce)
        }
        startActivity(intent)
    }

    private fun launchEnroll(msg: WireMessage) {
        val intent = Intent(this, ApprovalActivity::class.java).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            putExtra("kind", "enroll")
            putExtra("id", msg.id)
            putExtra("host", msg.host)
            putExtra("user", msg.user)
            putExtra("time", msg.time)
            putExtra("nonce", msg.nonce)
        }
        startActivity(intent)
    }

    private fun createChannel() {
        val mgr = getSystemService(NotificationManager::class.java)
        mgr.createNotificationChannel(
            // LOW, not MIN: the whole point raised was that this
            // notification needs to actually be seen at a glance, not
            // just exist. LOW still makes no sound and does not peek.
            NotificationChannel(CHANNEL_ID, "Computer connection", NotificationManager.IMPORTANCE_LOW),
        )
    }

    private fun buildNotification(status: String): Notification {
        val openApp = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE,
        )
        val disconnect = PendingIntent.getService(
            this, 0, Intent(this, ConnectionService::class.java).setAction(ACTION_DISCONNECT),
            PendingIntent.FLAG_IMMUTABLE,
        )
        return Notification.Builder(this, CHANNEL_ID)
            .setContentTitle("Nothing Approve")
            .setContentText(status)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(openApp)
            .addAction(Notification.Action.Builder(null, "Disconnect", disconnect).build())
            .setOngoing(true)
            .build()
    }

    private fun updateNotification(status: String) {
        val mgr = getSystemService(NotificationManager::class.java)
        mgr.notify(NOTIFICATION_ID, buildNotification(status))
    }
}
