package com.approven.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.os.IBinder
import android.util.Log
import com.approven.app.protocol.ApproveMessage

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
        const val ALERT_NOTIFICATION_ID = 2
        private const val ENROLL_RESULT_NOTIFICATION_ID = 3
        const val ACTION_DISCONNECT = "com.approven.app.DISCONNECT"
    }

    private var stoppedByUser = false
    private val handler by lazy { android.os.Handler(mainLooper) }

    override fun onCreate() {
        super.onCreate()
        createChannels()
        startForeground(STATUS_NOTIFICATION_ID, buildStatusNotification("Not connected"))

        ConnectionManager.setListener(object : ConnectionManager.Listener {
            override fun onConnected(id: String) = refreshStatus()

            override fun onDisconnected(id: String) {
                refreshStatus()
                if (!stoppedByUser) {
                    reconnectSoon(id)
                    rediscover(id)
                }
            }

            override fun onApproveRequest(id: String, msg: WireMessage) = alertApproval(id, msg)

            override fun onEnrollRequest(id: String, msg: WireMessage) = alertEnroll(id, msg)

            override fun onEnrollResult(id: String, msg: WireMessage) = notifyEnrollResult(id, msg)

            override fun onCancel(id: String, msg: WireMessage) {
                // The computer gave up waiting: the alert would only lead to a dead request.
                getSystemService(NotificationManager::class.java).cancel(ALERT_NOTIFICATION_ID)
            }
        })

        sync()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_DISCONNECT) {
            stoppedByUser = true
            ConnectionManager.disconnectAll()
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return START_NOT_STICKY
        }
        stoppedByUser = false
        sync()
        return START_STICKY
    }

    override fun onDestroy() {
        ConnectionManager.setListener(null)
        ConnectionManager.disconnectAll()
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    /**
     * Brings the connections in line with [PairingStore]: every computer
     * that is not paused gets connected (a no-op when it already is),
     * every connection to a forgotten or paused one is dropped. The app
     * just restarts this service after changing the list.
     */
    private fun sync() {
        val store = PairingStore(this)
        val wanted = store.computers.filter { !it.paused }
        (ConnectionManager.linkIds - wanted.map { it.id }.toSet()).forEach(ConnectionManager::disconnect)
        wanted.forEach { ConnectionManager.connect(it, store.deviceId, store.deviceName) }
        refreshStatus()
    }

    private fun reconnectSoon(id: String) {
        // A short, fixed backoff: the common case is a Wi-Fi blip or the
        // computer sleeping, not a permanently gone peer.
        handler.postDelayed({
            val store = PairingStore(this)
            val c = store.computer(id)
            if (!stoppedByUser && c != null && !c.paused) ConnectionManager.connect(c, store.deviceId, store.deviceName)
        }, 5000)
    }

    private val lastDiscovery = mutableMapOf<String, Long>()

    /**
     * The saved address stopped answering: look for the computer on the
     * local network (mDNS, `_approven._tcp`, announced by the daemon
     * through avahi) and, if it turns up at a new address, move there.
     * Matched by the certificate fingerprint in its TXT record, never by
     * name - and the TLS pin still has the final say on connect. At most
     * once a minute per computer, so an offline one does not keep the
     * radio busy.
     */
    private fun rediscover(id: String) {
        val c = PairingStore(this).computer(id) ?: return
        val pin = c.pin ?: return
        val now = System.currentTimeMillis()
        if (now - (lastDiscovery[id] ?: 0) < 60_000) return
        lastDiscovery[id] = now

        val nsd = getSystemService(android.net.nsd.NsdManager::class.java)
        val discovery = object : android.net.nsd.NsdManager.DiscoveryListener {
            override fun onServiceFound(info: android.net.nsd.NsdServiceInfo) {
                @Suppress("DEPRECATION") // its replacement needs API 34; minSdk is 29
                nsd.resolveService(info, object : android.net.nsd.NsdManager.ResolveListener {
                    override fun onServiceResolved(r: android.net.nsd.NsdServiceInfo) {
                        val fp = r.attributes["fp"]?.toString(Charsets.UTF_8)
                        val host = r.host?.hostAddress ?: return
                        if (fp != pin || host == c.host) return
                        Log.i("ConnectionService", "[$id] found at $host over mDNS")
                        val store = PairingStore(this@ConnectionService)
                        store.update(id) { it.copy(host = host, port = r.port) }
                        handler.post { store.computer(id)?.let { ConnectionManager.connect(it, store.deviceId, store.deviceName) } }
                    }

                    override fun onResolveFailed(info: android.net.nsd.NsdServiceInfo, errorCode: Int) {}
                })
            }

            override fun onServiceLost(info: android.net.nsd.NsdServiceInfo) {}
            override fun onDiscoveryStarted(serviceType: String) {}
            override fun onDiscoveryStopped(serviceType: String) {}
            override fun onStartDiscoveryFailed(serviceType: String, errorCode: Int) {}
            override fun onStopDiscoveryFailed(serviceType: String, errorCode: Int) {}
        }
        try {
            nsd.discoverServices("_approven._tcp", android.net.nsd.NsdManager.PROTOCOL_DNS_SD, discovery)
            handler.postDelayed({ runCatching { nsd.stopServiceDiscovery(discovery) } }, 15_000)
        } catch (e: Exception) {
            Log.w("ConnectionService", "mDNS discovery failed: $e")
        }
    }

    private fun refreshStatus() {
        val store = PairingStore(this)
        val up = ConnectionManager.states.value.filterValues { it == ConnectionManager.State.CONNECTED }.keys
        val names = store.computers.filter { it.id in up }.map { it.name }
        updateStatusNotification(
            when {
                names.isEmpty() -> if (store.computers.isEmpty()) "No computer yet" else "Not connected"
                else -> "Connected to ${names.joinToString()}"
            },
        )
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
    private fun alertApproval(computer: String, msg: WireMessage) {
        val intent = Intent(this, ApprovalActivity::class.java).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            putExtra("computer", computer)
            putExtra("kind", "approve")
            putExtra("id", msg.id)
            putExtra("host", msg.host)
            putExtra("user", msg.user)
            putExtra("service", msg.service)
            putExtra("command", msg.command)
            putExtra("tty", msg.tty)
            putExtra("rhost", msg.rhost)
            putExtra("time", msg.time)
            putExtra("nonce", msg.nonce)
        }
        val what = msg.command.ifEmpty { msg.service }
        val title = if (msg.service == "sudo") "Approve sudo?" else "Approve admin access?"
        showFullScreenAlert(intent, "$title · ${ApproveMessage.checkCode(msg.nonce)}", "$what for ${msg.user} on ${msg.host}")
    }

    private fun alertEnroll(computer: String, msg: WireMessage) {
        val intent = Intent(this, ApprovalActivity::class.java).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            putExtra("computer", computer)
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
    private fun notifyEnrollResult(computer: String, msg: WireMessage) {
        val intent = Intent(this, ApprovalActivity::class.java).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            putExtra("computer", computer)
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
        // Shown directly when the app is on screen: Android allows that from
        // a visible app, and without full-screen-intent permission (not
        // granted by default since Android 14) the notification below
        // would only sit in the shade. From the background Android just
        // drops this call, and the notification is the way in.
        try {
            startActivity(activityIntent)
        } catch (_: Exception) {
        }
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
