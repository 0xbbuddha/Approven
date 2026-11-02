package com.approven.app.protocol

import java.security.MessageDigest
import java.security.PublicKey

/**
 * The human-readable enrollment code derived from a public key, and the
 * SHA-256 hash it is derived from. Must match the Go side
 * (internal/protocol/crypto.go KeyHash/KeyCode) exactly: both hash the
 * X.509 SubjectPublicKeyInfo DER encoding of the key, which is what
 * [PublicKey.getEncoded] returns for an EC key from the standard
 * provider or from AndroidKeyStore.
 */
object KeyCode {
    /** SHA-256 of [pub]'s encoded form, as 64 lowercase hex digits. */
    fun keyHash(pub: PublicKey): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(pub.encoded)
        return digest.joinToString("") { "%02x".format(it) }
    }

    /** The first 8 bytes of [keyHash], as 16 uppercase hex digits in 4 groups of 4. */
    fun keyCode(pub: PublicKey): String {
        val hash = keyHash(pub)
        val first16 = hash.substring(0, 16).uppercase()
        return first16.chunked(4).joinToString(" ")
    }

    /** Strips spaces and hyphens and uppercases, so a typed code compares regardless of formatting. */
    fun normalize(code: String): String =
        code.filterNot { it == ' ' || it == '-' }.uppercase()
}
