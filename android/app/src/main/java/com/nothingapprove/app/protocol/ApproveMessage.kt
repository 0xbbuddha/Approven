package com.nothingapprove.app.protocol

/**
 * Builds and validates the exact bytes this phone signs to approve a
 * sudo request, and the bytes it signs to enroll a key. Must produce
 * byte-identical output to the Go side (internal/protocol/message.go)
 * for the same fields, or a signature never verifies on the computer.
 */
object ApproveMessage {
    const val APPROVE_VERSION = "nothing-approve-v1"
    const val ENROLL_VERSION = "nothing-approve-enroll-v1"
    const val MAX_FIELD_LEN = 256
    const val NONCE_HEX_LEN = 64

    private val NONCE_RE = Regex("^[0-9a-f]{64}$")
    private val KEY_HASH_RE = Regex("^[0-9a-f]{64}$")

    class InvalidFieldException(message: String) : Exception(message)

    data class ApproveRequest(
        val host: String,
        val user: String,
        val service: String,
        val tty: String,
        val rhost: String,
        val time: Long,
        val nonce: String,
    )

    data class EnrollRequest(
        val host: String,
        val user: String,
        val keyHash: String,
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

    /** The exact bytes to sign for [r]. Throws [InvalidFieldException] first if any field is invalid. */
    fun bytesOf(r: ApproveRequest): ByteArray {
        checkField("host", r.host)
        checkField("user", r.user)
        checkField("service", r.service)
        checkField("tty", r.tty, optional = true)
        checkField("rhost", r.rhost, optional = true)
        checkTime(r.time)
        checkNonce(r.nonce)
        return buildString {
            append(APPROVE_VERSION).append('\n')
            append("host=").append(r.host).append('\n')
            append("user=").append(r.user).append('\n')
            append("service=").append(r.service).append('\n')
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
        if (!KEY_HASH_RE.matches(r.keyHash)) {
            throw InvalidFieldException("key: must be 64 lowercase hex digits")
        }
        checkTime(r.time)
        checkNonce(r.nonce)
        return buildString {
            append(ENROLL_VERSION).append('\n')
            append("host=").append(r.host).append('\n')
            append("user=").append(r.user).append('\n')
            append("key=").append(r.keyHash).append('\n')
            append("time=").append(r.time).append('\n')
            append("nonce=").append(r.nonce).append('\n')
        }.toByteArray(Charsets.UTF_8)
    }
}
