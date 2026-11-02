package com.approven.app.protocol

/**
 * Builds and validates the exact bytes this phone signs to approve a
 * sudo request, and the bytes it signs to enroll a key. Must produce
 * byte-identical output to the Go side (internal/protocol/message.go)
 * for the same fields, or a signature never verifies on the computer.
 */
object ApproveMessage {
    const val APPROVE_VERSION = "approven-v2"
    const val ENROLL_VERSION = "approven-enroll-v2"
    const val MAX_FIELD_LEN = 256
    const val NONCE_HEX_LEN = 64

    private val NONCE_RE = Regex("^[0-9a-f]{64}$")
    private val KEY_HASH_RE = Regex("^[0-9a-f]{64}$")

    class InvalidFieldException(message: String) : Exception(message)

    data class ApproveRequest(
        val host: String,
        val user: String,
        val service: String,
        val command: String,
        val tty: String,
        val rhost: String,
        val time: Long,
        val nonce: String,
    )

    data class EnrollRequest(
        val host: String,
        val user: String,
        val keyHash: String,
        /** SHA-256 hex of this phone's TLS client certificate. */
        val clientCert: String,
        /** SHA-256 hex of the server certificate this connection actually saw. */
        val serverCert: String,
        val time: Long,
        val nonce: String,
    )

    private fun checkField(name: String, value: String, optional: Boolean = false) {
        if (value.isEmpty()) {
            if (optional) return
            throw InvalidFieldException("$name: empty")
        }
        if (value.toByteArray(Charsets.UTF_8).size > MAX_FIELD_LEN) {
            throw InvalidFieldException("$name: longer than $MAX_FIELD_LEN bytes")
        }
        for (c in value) {
            if (c.code < 0x20 || c.code == 0x7f) {
                throw InvalidFieldException("$name: contains a control character")
            }
        }
    }

    private fun checkNonce(nonce: String) {
        if (!NONCE_RE.matches(nonce)) {
            throw InvalidFieldException("nonce: must be $NONCE_HEX_LEN lowercase hex digits")
        }
    }

    private fun checkTime(t: Long) {
        if (t < 1 || t > (1L shl 40)) throw InvalidFieldException("time: out of range")
    }

    /** Same as the Go side's protocol.CheckCode: the code the terminal prints for this request. */
    fun checkCode(nonce: String): String = if (nonce.length < 4) "" else nonce.substring(0, 4).uppercase()

    /** The exact bytes to sign for [r]. Throws [InvalidFieldException] first if any field is invalid. */
    fun bytesOf(r: ApproveRequest): ByteArray {
        checkField("host", r.host)
        checkField("user", r.user)
        checkField("service", r.service)
        checkField("command", r.command, optional = true)
        checkField("tty", r.tty, optional = true)
        checkField("rhost", r.rhost, optional = true)
        checkTime(r.time)
        checkNonce(r.nonce)
        return buildString {
            append(APPROVE_VERSION).append('\n')
            append("host=").append(r.host).append('\n')
            append("user=").append(r.user).append('\n')
            append("service=").append(r.service).append('\n')
            append("command=").append(r.command).append('\n')
            append("tty=").append(r.tty).append('\n')
            append("rhost=").append(r.rhost).append('\n')
            append("time=").append(r.time).append('\n')
            append("nonce=").append(r.nonce).append('\n')
        }.toByteArray(Charsets.UTF_8)
    }

    /** The exact bytes to sign for [r]. Throws [InvalidFieldException] first if any field is invalid. */
    fun bytesOf(r: EnrollRequest): ByteArray {
        checkField("host", r.host)
        checkField("user", r.user)
        for ((name, h) in listOf("key" to r.keyHash, "client" to r.clientCert, "server" to r.serverCert)) {
            if (!KEY_HASH_RE.matches(h)) throw InvalidFieldException("$name: must be 64 lowercase hex digits")
        }
        checkTime(r.time)
        checkNonce(r.nonce)
        return buildString {
            append(ENROLL_VERSION).append('\n')
            append("host=").append(r.host).append('\n')
            append("user=").append(r.user).append('\n')
            append("key=").append(r.keyHash).append('\n')
            append("client=").append(r.clientCert).append('\n')
            append("server=").append(r.serverCert).append('\n')
            append("time=").append(r.time).append('\n')
            append("nonce=").append(r.nonce).append('\n')
        }.toByteArray(Charsets.UTF_8)
    }
}
