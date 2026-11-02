package com.approven.app

import android.util.Log
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.OutputStream
import java.net.Socket
import java.security.Principal
import java.security.PrivateKey
import java.security.cert.X509Certificate
import java.util.concurrent.ConcurrentHashMap
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
import kotlinx.coroutines.flow.update

/**
 * Owns one TLS connection per known computer ([Link]), keyed by the
 * computer's id in [PairingStore]. A plain singleton rather than
 * something bound through the Service: the approval UI (an Activity,
 * which cannot easily bind to and block on a Service synchronously) and
 * the background Service both call into it directly.
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
 * Trust-on-first-use, only for an address typed by hand: with no
 * pinned fingerprint yet (a scanned QR code always brings one), any
 * certificate is accepted - the real proof of trust at
 * that point is the human comparing the key code on both screens, the
 * same reference design docs/approve.md documents for the equivalent
 * step. Once enrollment records a fingerprint, every later connection
 * is rejected unless its certificate hashes to exactly that value.
 */
object ConnectionManager {
    private const val TAG = "ConnectionManager"
    private const val TEST_TIMEOUT_MS = 40_000L

    /** Every callback names the computer ([PairingStore.Computer.id]) it came from. */
    interface Listener {
        fun onConnected(id: String) {}
        fun onDisconnected(id: String) {}
        fun onApproveRequest(id: String, msg: WireMessage) {}
        fun onEnrollRequest(id: String, msg: WireMessage) {}
        fun onEnrollResult(id: String, msg: WireMessage) {}
        fun onCancel(id: String, msg: WireMessage) {}
    }

    enum class State { OFFLINE, CONNECTING, CONNECTED }

    sealed interface Test {
        data object Idle : Test
        data object Running : Test
        data class Done(val ok: Boolean, val error: String) : Test
    }

    @Volatile private var listener: Listener? = null
    private val links = ConcurrentHashMap<String, Link>()
    private val executor = Executors.newCachedThreadPool()

    private val _states = MutableStateFlow<Map<String, State>>(emptyMap())
    /** Each computer's connection state; a computer with no entry is offline. */
    val states: StateFlow<Map<String, State>> = _states

    private val _cancelled = MutableStateFlow<String?>(null)
    /** ID of the last request a computer stopped waiting for - the approval screen closes on it. */
    val cancelled: StateFlow<String?> = _cancelled

    private val _test = MutableStateFlow<Test>(Test.Idle)
    /** The home screen's "tap the logo" test sudo. */
    val test: StateFlow<Test> = _test

    fun setListener(l: Listener?) {
        listener = l
    }

    /** Connects to a computer; a no-op when that exact target is already connected or connecting. */
    fun connect(c: PairingStore.Computer, deviceId: String, deviceName: String) =
        links.getOrPut(c.id) { Link(c.id) }.connect(c.host, c.port, c.pin, deviceId, deviceName)

    fun disconnect(id: String) {
        links.remove(id)?.disconnect()
        _states.update { it - id }
    }

    fun disconnectAll() = links.keys.toList().forEach(::disconnect)

    /** Ids this manager currently holds a connection (or attempt) for. */
    val linkIds: Set<String> get() = links.keys.toSet()

    fun send(id: String, msg: WireMessage): Boolean = links[id]?.send(msg) ?: false

    /** The certificate fingerprint of a computer's current connection - pinned right after enrollment. */
    fun serverFingerprint(id: String): String? = links[id]?.connectedFingerprint

    /** Asks a computer to run `sudo -k true`, which comes straight back here as an approval request. */
    fun requestTest(id: String) {
        if (_test.value == Test.Running) return
        _test.value = Test.Running
        executor.execute {
            if (!send(id, WireMessage(type = "test_sudo"))) {
                _test.value = Test.Done(false, "Not connected")
                return@execute
            }
            // The approval itself waits 20 s; a computer that never answers
            // (an older daemon ignores test_sudo) must not leave this spinning.
            Thread.sleep(TEST_TIMEOUT_MS)
            _test.compareAndSet(Test.Running, Test.Done(false, "No answer from the computer"))
        }
    }

    private fun setState(id: String, s: State) = _states.update { it + (id to s) }

    /**
     * One computer's connection. [connect] can legitimately be called more
     * than once for the same target - the Service calls it from both
     * onCreate and onStartCommand. [generation] keeps 2 such calls from
     * fighting: each call that actually opens a socket owns a generation
     * number, and every step after the connect checks it still holds the
     * current one before touching shared state or deciding to reconnect.
     */
    private class Link(val id: String) {
        @Volatile private var socket: Socket? = null
        @Volatile private var out: OutputStream? = null
        @Volatile var connectedFingerprint: String? = null
        @Volatile private var target: Pair<String, Int>? = null
        // True from the moment a connect() commits to opening a socket
        // until that attempt's connection finally ends.
        @Volatile private var active = false
        private val generation = AtomicInteger(0)
        private val writeLock = Any()
        private val stateLock = Any()

        fun connect(host: String, port: Int, pinnedFingerprint: String?, deviceId: String, deviceName: String) {
            val myGen: Int
            synchronized(stateLock) {
                if (active && target == Pair(host, port)) {
                    return // already connecting or connected to this exact target
                }
                target = Pair(host, port)
                active = true
                myGen = generation.incrementAndGet()
                setState(id, State.CONNECTING)
                try {
                    socket?.close()
                } catch (_: Exception) {
                }
                socket = null
                out = null
            }

            executor.execute {
                try {
                    val context = SSLContext.getInstance("TLSv1.3")
                    context.init(arrayOf(clientKeyManager()), arrayOf<TrustManager>(pinningTrustManager(pinnedFingerprint)), null)
                    val raw = context.socketFactory.createSocket(host, port) as SSLSocket
                    raw.startHandshake()

                    val cert = raw.session.peerCertificates.firstOrNull() as? X509Certificate
                    synchronized(stateLock) {
                        if (!stillCurrent(myGen)) {
                            raw.close()
                            return@execute
                        }
                        socket = raw
                        out = raw.getOutputStream()
                        connectedFingerprint = cert?.let { sha256Hex(it.encoded) }
                        setState(id, State.CONNECTED)
                    }
                    send(WireMessage(type = "hello", deviceId = deviceId, deviceName = deviceName))
                    listener?.onConnected(id)

                    val reader = BufferedReader(InputStreamReader(raw.getInputStream(), Charsets.UTF_8))
                    while (stillCurrent(myGen)) {
                        val line = reader.readLine() ?: break
                        handleLine(line)
                    }
                } catch (e: Exception) {
                    Log.w(TAG, "[$id] connection ended: ${e.message}")
                } finally {
                    if (stillCurrent(myGen)) {
                        synchronized(stateLock) {
                            if (stillCurrent(myGen)) {
                                socket = null
                                out = null
                                active = false
                                setState(id, State.OFFLINE)
                                _test.compareAndSet(Test.Running, Test.Done(false, "Connection lost"))
                            }
                        }
                        listener?.onDisconnected(id)
                    }
                }
            }
        }

        private fun stillCurrent(myGen: Int) = generation.get() == myGen

        fun disconnect() {
            synchronized(stateLock) {
                generation.incrementAndGet() // invalidates any in-flight connect()'s loop and cleanup
                target = null
                active = false
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
                Log.w(TAG, "[$id] bad line from computer: $e")
                return
            }
            Log.d(TAG, "[$id] received: ${msg.type} id=${msg.id}")
            when (msg.type) {
                "approve_request" -> listener?.onApproveRequest(id, msg)
                "enroll_request" -> listener?.onEnrollRequest(id, msg)
                "enroll_result" -> listener?.onEnrollResult(id, msg)
                "cancel" -> {
                    _cancelled.value = msg.id
                    listener?.onCancel(id, msg)
                }
                "test_result" -> _test.value = Test.Done(msg.approved, msg.error)
                else -> Log.w(TAG, "[$id] unknown message type: ${msg.type}")
            }
        }

        /** Returns whether the write actually succeeded - a silent failure here was the whole point of a request reaching the phone, getting approved, and the computer still seeing only a timeout. */
        fun send(msg: WireMessage): Boolean {
            val stream = out
            if (stream == null) {
                Log.w(TAG, "[$id] send(${msg.type}): no connection")
                return false
            }
            return try {
                synchronized(writeLock) {
                    stream.write((msg.toJson() + "\n").toByteArray(Charsets.UTF_8))
                    stream.flush()
                }
                Log.d(TAG, "[$id] sent: ${msg.type} id=${msg.id}")
                true
            } catch (e: Exception) {
                Log.w(TAG, "[$id] send(${msg.type}) failed: $e")
                false
            }
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
