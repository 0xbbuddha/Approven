package com.approven.app.protocol

import java.net.URI
import java.net.URLDecoder

/**
 * What `approve-cli enroll`'s QR code holds (cmd/approve-cli pairingURI):
 * `approven://pair?h=<ip>&p=<port>&fp=<sha256 of the daemon cert>&n=<hostname>`.
 * The fingerprint is the point: the phone pins it before its first
 * connection, so not even that one can be intercepted.
 */
data class PairingUri(val host: String, val port: Int, val fingerprint: String, val name: String) {
    companion object {
        private val FP_RE = Regex("^[0-9a-f]{64}$")
        private val HOST_RE = Regex("^[0-9A-Za-z.:%-]{1,253}$")

        /** Null for anything that is not a well-formed pairing code - a QR code is untrusted input. */
        fun parse(raw: String): PairingUri? {
            val uri = try { URI(raw.trim()) } catch (_: Exception) { return null }
            if (uri.scheme != "approven" || uri.host != "pair") return null
            val q = (uri.rawQuery ?: return null).split('&').mapNotNull {
                val kv = it.split('=', limit = 2)
                if (kv.size != 2) null else kv[0] to URLDecoder.decode(kv[1], "UTF-8")
            }.toMap()
            val host = q["h"]?.takeIf { HOST_RE.matches(it) } ?: return null
            val port = q["p"]?.toIntOrNull()?.takeIf { it in 1..65535 } ?: return null
            val fp = q["fp"]?.takeIf { FP_RE.matches(it) } ?: return null
            val name = q["n"].orEmpty().filter { it.code >= 0x20 && it.code != 0x7f }.take(64).ifEmpty { host }
            return PairingUri(host, port, fp, name)
        }
    }
}
