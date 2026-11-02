package com.approven.app

import android.util.Log
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.OutputStream
import java.net.Socket
import java.security.Principal
import java.security.PrivateKey
import java.security.cert.X509Certificate
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicInteger
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLEngine
import javax.net.ssl.TrustManager
import javax.net.ssl.X509ExtendedKeyManager
import javax.net.ssl.X509TrustManager
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

/**
 * Owns the single TLS connection to the paired computer. A plain
 * singleton rather than something bound through the Service: the
 * approval UI (an Activity, which cannot easily bind to and block on a
 * Service synchronously) and the background Service both call into it
 * directly, which is fine for a single-process app with exactly one
 * live connection.
 *
 * [connect] can legitimately be called more than once for the same
 * target - the Service calls it from both onCreate and onStartCommand,
 * and MainActivity calls it too on its own. A first version tore down
 * and reopened the socket on every call with no guard at all: 2 calls
 * arriving close together raced, each one's `disconnect()` capable of
 * closing the *other* call's freshly-opened socket, which produced a
 * connect/disconnect/reconnect churn roughly every 5 seconds (the
 * reconnect backoff) - and meant an approval signed in the few seconds
 * between 2 churns could find no connection left to send itself on.
 * [generation] fixes this: each call that actually proceeds to open a
 * socket owns a generation number, and every step after the connect
 * checks it still holds the current one before touching shared state
 * or deciding to reconnect - a stale call simply stops touching
 * anything instead of fighting the newer one for the same fields.
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
        fun onEnrollResult(msg: WireMessage) {}
        fun onCancel(msg: WireMessage) {}
    }

    @Volatile private var socket: Socket? = null
    @Volatile private var out: OutputStream? = null
    @Volatile private var listener: Listener? = null
    @Volatile private var connectedFingerprint: String? = null
    @Volatile private var target: Pair<String, Int>? = null
    // True from the moment a connect() call commits to opening a socket
    // until that attempt's connection (however long it lives) finally
    // ends - the one piece of state a second, concurrent call for the
    // same target actually needs to check before deciding to back off.
    @Volatile private var active = false
    private val generation = AtomicInteger(0)
    private val executor = Executors.newCachedThreadPool()
    private val writeLock = Any()
    private val stateLock = Any()

    enum class State { OFFLINE, CONNECTING, CONNECTED }

    private val _state = MutableStateFlow(State.OFFLINE)
    /** What the UI shows; the Listener above stays the Service's channel. */
    val state: StateFlow<State> = _state

    private val _cancelled = MutableStateFlow<String?>(null)
    /** ID of the last request the computer stopped waiting for - the approval screen closes on it. */
    val cancelled: StateFlow<String?> = _cancelled

    sealed interface Test {
        data object Idle : Test
        data object Running : Test
        data class Done(val ok: Boolean, val error: String) : Test
    }

    private val _test = MutableStateFlow<Test>(Test.Idle)
    /** The home screen's "tap the logo" test sudo. */
    val test: StateFlow<Test> = _test

    /** Asks the computer to run `sudo -k true`, which comes straight back here as an approval request. */
    fun requestTest() {
        if (_test.value == Test.Running) return
        _test.value = Test.Running
        executor.execute {
            if (!send(WireMessage(type = "test_sudo"))) {
                _test.value = Test.Done(false, "Not connected")
                return@execute
            }
            // The approval itself waits 20 s; a computer that never answers
            // (an older daemon ignores test_sudo) must not leave this spinning.
            Thread.sleep(TEST_TIMEOUT_MS)
            _test.compareAndSet(Test.Running, Test.Done(false, "No answer from the computer"))
        }
    }

    private const val TEST_TIMEOUT_MS = 40_000L

    fun setListener(l: Listener?) {
        listener = l
    }

    val isConnected: Boolean
        get() = socket?.isConnected == true && socket?.isClosed == false

    /**
     * Connects to host:port. A call for the same target while a
     * connection to it is already open or being established is a
     * no-op: the existing attempt owns the current generation and this
     * call has nothing to add. A call for a *different* target (the
     * user re-pairs to another computer) does take over, the same way
     * [disconnect] always does.
     */
    fun connect(host: String, port: Int, pinnedFingerprint: String?, deviceId: String, deviceName: String) {
        val myGen: Int
        synchronized(stateLock) {
            if (active && target == Pair(host, port)) {
                return // already connecting or connected to this exact target
            }
            target = Pair(host, port)
            active = true
            myGen = generation.incrementAndGet()
            _state.value = State.CONNECTING
            try {
                socket?.close()
            } catch (_: Exception) {
            }
            socket = null
            out = null
        }

        executor.execute {
            try {
                val trustManager = pinningTrustManager(pinnedFingerprint)
                val context = SSLContext.getInstance("TLSv1.3")
                context.init(arrayOf(clientKeyManager()), arrayOf<TrustManager>(trustManager), null)
                val raw = context.socketFactory.createSocket(host, port) as SSLSocket
                raw.startHandshake()

                if (!stillCurrent(myGen)) {
                    raw.close()
                    return@execute
                }

                val cert = raw.session.peerCertificates.firstOrNull() as? X509Certificate
                val fingerprint = cert?.let { sha256Hex(it.encoded) }

                synchronized(stateLock) {
                    if (!stillCurrent(myGen)) {
                        raw.close()
                        return@execute
                    }
                    socket = raw
                    out = raw.getOutputStream()
                    connectedFingerprint = fingerprint
                    _state.value = State.CONNECTED
                }
                send(WireMessage(type = "hello", deviceId = deviceId, deviceName = deviceName))
                listener?.onConnected()

                val reader = BufferedReader(InputStreamReader(raw.getInputStream(), Charsets.UTF_8))
                while (stillCurrent(myGen)) {
                    val line = reader.readLine() ?: break
                    handleLine(line)
                }
            } catch (e: Exception) {
                Log.w(TAG, "connection ended: ${e.message}")
            } finally {
                if (stillCurrent(myGen)) {
                    synchronized(stateLock) {
                        if (stillCurrent(myGen)) {
                            socket = null
                            out = null
                            active = false
                            _state.value = State.OFFLINE
                            if (_test.value == Test.Running) _test.value = Test.Done(false, "Connection lost")
                        }
                    }
                    listener?.onDisconnected()
                }
            }
        }
    }

    private fun stillCurrent(myGen: Int) = generation.get() == myGen

    /** The fingerprint of the certificate presented by the most recent connection - read right after a successful enrollment, to pin it. */
    val lastServerFingerprint: String?
        get() = connectedFingerprint

    fun disconnect() {
        synchronized(stateLock) {
            generation.incrementAndGet() // invalidates any in-flight connect()'s loop and cleanup
            target = null
            active = false
            _state.value = State.OFFLINE
            try {
                socket?.close()
            } catch (_: Exception) {
            }
            socket = null
            out = null
        }
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
            "enroll_result" -> listener?.onEnrollResult(msg)
            "cancel" -> {
                _cancelled.value = msg.id
                listener?.onCancel(msg)
            }
            "test_result" -> _test.value = Test.Done(msg.approved, msg.error)
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

    private fun sha256Hex(bytes: ByteArray) = CryptoKeys.sha256Hex(bytes)

    /** Always presents [CryptoKeys.tlsIdentity]: the computer refuses a phone without a client certificate. */
    private fun clientKeyManager(): X509ExtendedKeyManager {
        val (key, cert) = CryptoKeys.tlsIdentity()
        val alias = CryptoKeys.TLS_ALIAS
        return object : X509ExtendedKeyManager() {
            override fun chooseClientAlias(keyType: Array<out String>?, issuers: Array<out Principal>?, socket: Socket?) = alias
            override fun chooseEngineClientAlias(keyType: Array<out String>?, issuers: Array<out Principal>?, engine: SSLEngine?) = alias
            override fun getClientAliases(keyType: String?, issuers: Array<out Principal>?) = arrayOf(alias)
            override fun getCertificateChain(a: String?): Array<X509Certificate> = arrayOf(cert)
            override fun getPrivateKey(a: String?): PrivateKey = key
            override fun getServerAliases(keyType: String?, issuers: Array<out Principal>?): Array<String>? = null
            override fun chooseServerAlias(keyType: String?, issuers: Array<out Principal>?, socket: Socket?): String? = null
        }
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
