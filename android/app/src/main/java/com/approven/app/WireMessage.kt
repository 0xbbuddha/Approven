package com.approven.app

import android.util.Base64
import org.json.JSONObject

/**
 * One line of the phone<->daemon wire protocol. Mirrors the Go side's
 * wireMsg (internal/phonetransport/server.go) field for field: the
 * JSON field names must match exactly, and byte fields travel as
 * standard base64 (Go's encoding/json does the same for []byte).
 */
data class WireMessage(
    val type: String,
    val id: String = "",
    val deviceId: String = "",
    val deviceName: String = "",
    val host: String = "",
    val user: String = "",
    val service: String = "",
    val tty: String = "",
    val rhost: String = "",
    val time: Long = 0,
    val nonce: String = "",
    val approved: Boolean = false,
    val signature: ByteArray? = null,
    val publicKeyDer: ByteArray? = null,
) {
    fun toJson(): String {
        val o = JSONObject()
        o.put("type", type)
        if (id.isNotEmpty()) o.put("id", id)
        if (deviceId.isNotEmpty()) o.put("device_id", deviceId)
        if (deviceName.isNotEmpty()) o.put("device_name", deviceName)
        if (host.isNotEmpty()) o.put("host", host)
        if (user.isNotEmpty()) o.put("user", user)
        if (service.isNotEmpty()) o.put("service", service)
        if (tty.isNotEmpty()) o.put("tty", tty)
        if (rhost.isNotEmpty()) o.put("rhost", rhost)
        if (time != 0L) o.put("time", time)
        if (nonce.isNotEmpty()) o.put("nonce", nonce)
        if (approved) o.put("approved", true)
        if (signature != null) o.put("signature", Base64.encodeToString(signature, Base64.NO_WRAP))
        if (publicKeyDer != null) o.put("public_key_der", Base64.encodeToString(publicKeyDer, Base64.NO_WRAP))
        return o.toString()
    }

    companion object {
        fun fromJson(line: String): WireMessage {
            val o = JSONObject(line)
            return WireMessage(
                type = o.optString("type"),
                id = o.optString("id"),
                deviceId = o.optString("device_id"),
                deviceName = o.optString("device_name"),
                host = o.optString("host"),
                user = o.optString("user"),
                service = o.optString("service"),
                tty = o.optString("tty"),
                rhost = o.optString("rhost"),
                time = o.optLong("time"),
                nonce = o.optString("nonce"),
                approved = o.optBoolean("approved"),
                signature = o.optString("signature", "").let { if (it.isEmpty()) null else Base64.decode(it, Base64.NO_WRAP) },
                publicKeyDer = o.optString("public_key_der", "").let { if (it.isEmpty()) null else Base64.decode(it, Base64.NO_WRAP) },
            )
        }
    }
}
