package com.nothingapprove.app

import android.util.Log
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.OutputStream
import java.net.Socket
import java.security.MessageDigest
import java.security.cert.X509Certificate
import java.util.concurrent.Executors
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

/**
 * Owns the single TLS connection to the paired computer. A plain
 * singleton rather than something bound through the Service: the
 * approval UI (an Activity, which cannot easily bind to and block on a
 * Service synchronously) and the background Service both call into it
 * directly, which is fine for a single-process app with exactly one
 * live connection.
 *
 * Trust-on-first-use: with no pinned fingerprint yet (during
 * enrollment), any certificate is accepted - the real proof of trust at
 * that point is the human comparing the key code on both screens, the
 * same reference design docs/approve.md documents for the equivalent
 * step. Once enrollment records a fingerprint, every later connection
 * is rejected unless its certificate hashes to exactly that value.
 */
object ConnectionManager {
    private const val TAG = "ConnectionManager"

    interface Listener {
        fun onConnected() {}
        fun onDisconnected() {}
        fun onApproveRequest(msg: WireMessage) {}
        fun onEnrollRequest(msg: WireMessage) {}
    }

    @Volatile private var socket: Socket? = null
    @Volatile private var out: OutputStream? = null
    @Volatile private var listener: Listener? = null
    @Volatile private var connectedFingerprint: String? = null
    private val executor = Executors.newCachedThreadPool()
    private val writeLock = Any()

    fun setListener(l: Listener?) {
        listener = l
    }

    val isConnected: Boolean
        get() = socket?.isConnected == true && socket?.isClosed == false

    /**
     * Connects to host:port. When pinnedFingerprint is null (pairing),
     * any certificate is accepted and its fingerprint is made available
     * through [lastServerFingerprint] once connected, for the caller to
     * pin after a successful enrollment. When it is set, only that
     * exact certificate is accepted.
     */
    fun connect(host: String, port: Int, pinnedFingerprint: String?, deviceId: String, deviceName: String) {
        disconnect()
        executor.execute {
            try {
                val trustManager = pinningTrustManager(pinnedFingerprint)
                val context = SSLContext.getInstance("TLSv1.3")
                context.init(null, arrayOf<TrustManager>(trustManager), null)
                val raw = context.socketFactory.createSocket(host, port) as SSLSocket
                raw.startHandshake()

                val cert = raw.session.peerCertificates.firstOrNull() as? X509Certificate
                connectedFingerprint = cert?.let { sha256Hex(it.encoded) }

                socket = raw
                out = raw.getOutputStream()
                send(WireMessage(type = "hello", deviceId = deviceId, deviceName = deviceName))
                listener?.onConnected()

                val reader = BufferedReader(InputStreamReader(raw.getInputStream(), Charsets.UTF_8))
                while (true) {
                    val line = reader.readLine() ?: break
                    handleLine(line)
                }
            } catch (e: Exception) {
                Log.w(TAG, "connection ended: ${e.message}")
            } finally {
                socket = null
                out = null
                listener?.onDisconnected()
            }
        }
    }

    /** The fingerprint of the certificate presented by the most recent connection - read right after a successful enrollment, to pin it. */
    val lastServerFingerprint: String?
        get() = connectedFingerprint

    fun disconnect() {
        try {
            socket?.close()
        } catch (_: Exception) {
        }
        socket = null
        out = null
    }

    private fun handleLine(line: String) {
        if (line.isBlank()) return
        val msg = try {
            WireMessage.fromJson(line)
        } catch (e: Exception) {
            Log.w(TAG, "bad line from computer: $e")
            return
        }
        Log.d(TAG, "received: ${msg.type} id=${msg.id}")
        when (msg.type) {
            "approve_request" -> listener?.onApproveRequest(msg)
            "enroll_request" -> listener?.onEnrollRequest(msg)
            "cancel" -> Unit // the Activity's own timeout handles this today; nothing more to do yet
            else -> Log.w(TAG, "unknown message type: ${msg.type}")
        }
    }

    /** Returns whether the write actually succeeded - a silent failure here was the whole point of a request reaching the phone, getting approved, and the computer still seeing only a timeout. */
    fun send(msg: WireMessage): Boolean {
        val stream = out
        if (stream == null) {
            Log.w(TAG, "send(${msg.type}): no connection")
            return false
        }
        return try {
            synchronized(writeLock) {
                stream.write((msg.toJson() + "\n").toByteArray(Charsets.UTF_8))
                stream.flush()
            }
            Log.d(TAG, "sent: ${msg.type} id=${msg.id}")
            true
        } catch (e: Exception) {
            Log.w(TAG, "send(${msg.type}) failed: $e")
            false
        }
    }

    private fun sha256Hex(bytes: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(bytes)
        return digest.joinToString("") { "%02x".format(it) }
    }

    private fun pinningTrustManager(pinnedFingerprint: String?): X509TrustManager = object : X509TrustManager {
        override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {
            throw java.security.cert.CertificateException("client certificates are never expected")
        }

        override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {
            val leaf = chain?.firstOrNull()
                ?: throw java.security.cert.CertificateException("no certificate presented")
            if (pinnedFingerprint == null) return // trust-on-first-use: accepted, fingerprint read by the caller after connect
            val got = sha256Hex(leaf.encoded)
            if (got != pinnedFingerprint) {
                throw java.security.cert.CertificateException(
                    "the computer's certificate does not match the one pinned at enrollment",
                )
            }
        }

        override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
    }
}
