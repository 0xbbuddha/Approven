package com.approven.app

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
        private const val STATUS_CHANNEL_ID = "approven-connection"
        private const val ALERT_CHANNEL_ID = "approven-alert"
        private const val STATUS_NOTIFICATION_ID = 1
        private const val ALERT_NOTIFICATION_ID = 2
        private const val ENROLL_RESULT_NOTIFICATION_ID = 3
        const val ACTION_DISCONNECT = "com.approven.app.DISCONNECT"
    }

    private var connecting = false
    private var stoppedByUser = false

    override fun onCreate() {
        super.onCreate()
        createChannels()
        startForeground(STATUS_NOTIFICATION_ID, buildStatusNotification("Not connected"))

        ConnectionManager.setListener(object : ConnectionManager.Listener {
            override fun onConnected() {
                connecting = false
                updateStatusNotification("Connected to ${PairingStore(this@ConnectionService).computerHost}")
            }

            override fun onDisconnected() {
                updateStatusNotification(if (connecting) "Connecting..." else "Not connected")
                if (!stoppedByUser) reconnectSoon()
            }

            override fun onApproveRequest(msg: WireMessage) {
                alertApproval(msg)
            }

            override fun onEnrollRequest(msg: WireMessage) {
                alertEnroll(msg)
            }

            override fun onEnrollResult(msg: WireMessage) {
                notifyEnrollResult(msg)
            }
        })

        connectIfConfigured()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_DISCONNECT) {
            stoppedByUser = true
            ConnectionManager.disconnect()
            updateStatusNotification("Not connected")
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
        updateStatusNotification("Connecting...")
        ConnectionManager.connect(host, store.computerPort, store.pinnedFingerprint, store.deviceId, store.deviceName)
    }

    private fun reconnectSoon() {
        // A short, fixed backoff is enough for v1: the common case is a
        // Wi-Fi blip or the computer sleeping, not a permanently gone
        // peer. A phone that never finds the computer again just stays
        // in "Not connected", which status already shows truthfully.
        android.os.Handler(mainLooper).postDelayed({ if (!stoppedByUser) connectIfConfigured() }, 5000)
    }

    /**
     * A plain startActivity() from a Service that is not in the
     * foreground is silently blocked on modern Android - no crash, no
     * log, the Activity just never appears, which is exactly what made
     * the first real approval look like nothing happened at all. A
     * full-screen-intent notification is the one path Android still
     * lets a background process use to put an Activity on screen
     * immediately, the same mechanism an incoming call or an alarm
     * uses - everything else here (a normal tap-to-open notification)
     * remains blocked the same way startActivity was.
     */
    private fun alertApproval(msg: WireMessage) {
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
        showFullScreenAlert(intent, "Approve sudo?", "${msg.service} for ${msg.user} on ${msg.host} - tap to approve or deny")
    }

    private fun alertEnroll(msg: WireMessage) {
        val intent = Intent(this, ApprovalActivity::class.java).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            putExtra("kind", "enroll")
            putExtra("id", msg.id)
            putExtra("host", msg.host)
            putExtra("user", msg.user)
            putExtra("time", msg.time)
            putExtra("nonce", msg.nonce)
        }
        showFullScreenAlert(intent, "Enroll this phone?", "For sudo on ${msg.host}")
    }

    /**
     * The daemon sends this after the human finishes typing the code
     * on the computer - the earlier enroll_response ack only confirmed
     * the phone's signature reached the daemon, not that enrollment
     * actually completed. Without this, the phone's screen was stuck
     * forever on "type this on the computer" even after everything
     * succeeded. Updates the enrollment screen in place when it is
     * still around (the common case: the user is looking at the code
     * right now) and always posts a plain notification too, since a
     * background-started activity update can be silently dropped the
     * same way a fresh approval request's startActivity can be.
     */
    private fun notifyEnrollResult(msg: WireMessage) {
        val intent = Intent(this, ApprovalActivity::class.java).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            putExtra("kind", "enroll_result")
            putExtra("id", msg.id)
            putExtra("ok", msg.approved)
            putExtra("error", msg.error)
        }
        try {
            startActivity(intent)
        } catch (_: Exception) {
        }

        val text = if (msg.approved) "Enrolled successfully." else "Enrollment failed: ${msg.error}"
        val notification = Notification.Builder(this, STATUS_CHANNEL_ID)
            .setContentTitle("Approven")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setAutoCancel(true)
            .build()
        getSystemService(NotificationManager::class.java).notify(ENROLL_RESULT_NOTIFICATION_ID, notification)
    }

    private fun showFullScreenAlert(activityIntent: Intent, title: String, text: String) {
        val fullScreenPendingIntent = PendingIntent.getActivity(
            this, ALERT_NOTIFICATION_ID, activityIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val notification = Notification.Builder(this, ALERT_CHANNEL_ID)
            .setContentTitle(title)
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setPriority(Notification.PRIORITY_HIGH)
            .setCategory(Notification.CATEGORY_CALL)
            .setFullScreenIntent(fullScreenPendingIntent, true)
            .setContentIntent(fullScreenPendingIntent)
            .setAutoCancel(true)
            .build()
        val mgr = getSystemService(NotificationManager::class.java)
        mgr.notify(ALERT_NOTIFICATION_ID, notification)
    }

    private fun createChannels() {
        val mgr = getSystemService(NotificationManager::class.java)
        mgr.createNotificationChannel(
            // LOW, not MIN: the whole point raised was that this
            // notification needs to actually be seen at a glance, not
            // just exist. LOW still makes no sound and does not peek.
            NotificationChannel(STATUS_CHANNEL_ID, "Computer connection", NotificationManager.IMPORTANCE_LOW),
        )
        mgr.createNotificationChannel(
            // HIGH + a full-screen intent is what actually puts the
            // approval screen up from the background - anything less
            // than HIGH and Android may not honor the full-screen
            // intent at all, just queue a normal heads-up notification.
            NotificationChannel(ALERT_CHANNEL_ID, "Approval requests", NotificationManager.IMPORTANCE_HIGH).apply {
                enableVibration(true)
            },
        )
    }

    private fun buildStatusNotification(status: String): Notification {
        val openApp = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE,
        )
        val disconnect = PendingIntent.getService(
            this, 0, Intent(this, ConnectionService::class.java).setAction(ACTION_DISCONNECT),
            PendingIntent.FLAG_IMMUTABLE,
        )
        return Notification.Builder(this, STATUS_CHANNEL_ID)
            .setContentTitle("Approven")
            .setContentText(status)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(openApp)
            .addAction(Notification.Action.Builder(null, "Disconnect", disconnect).build())
            .setOngoing(true)
            .build()
    }

    private fun updateStatusNotification(status: String) {
        val mgr = getSystemService(NotificationManager::class.java)
        mgr.notify(STATUS_NOTIFICATION_ID, buildStatusNotification(status))
    }
}
