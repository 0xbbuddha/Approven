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
 * what lets Android let this socket live in the background at all.
 */
class ConnectionService : Service() {
    companion object {
        private const val CHANNEL_ID = "nothing-approve-connection"
        private const val NOTIFICATION_ID = 1
    }

    override fun onCreate() {
        super.onCreate()
        createChannel()
        startForeground(NOTIFICATION_ID, buildNotification("Not connected"))

        ConnectionManager.setListener(object : ConnectionManager.Listener {
            override fun onConnected() {
                updateNotification("Connected")
            }

            override fun onDisconnected() {
                updateNotification("Not connected")
                reconnectSoon()
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

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
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
        ConnectionManager.connect(host, store.computerPort, store.pinnedFingerprint, store.deviceId, store.deviceName)
    }

    private fun reconnectSoon() {
        // A short, fixed backoff is enough for v1: the common case is a
        // Wi-Fi blip or the computer sleeping, not a permanently gone
        // peer. A phone that never finds the computer again just stays
        // in "Not connected", which status already shows truthfully.
        android.os.Handler(mainLooper).postDelayed({ connectIfConfigured() }, 5000)
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
            NotificationChannel(CHANNEL_ID, "Computer connection", NotificationManager.IMPORTANCE_MIN),
        )
    }

    private fun buildNotification(status: String): Notification {
        val openApp = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE,
        )
        return Notification.Builder(this, CHANNEL_ID)
            .setContentTitle("Nothing Approve")
            .setContentText(status)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(openApp)
            .setOngoing(true)
            .build()
    }

    private fun updateNotification(status: String) {
        val mgr = getSystemService(NotificationManager::class.java)
        mgr.notify(NOTIFICATION_ID, buildNotification(status))
    }
}
