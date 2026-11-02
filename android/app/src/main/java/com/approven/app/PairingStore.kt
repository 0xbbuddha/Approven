package com.approven.app

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.util.UUID

/**
 * The computers this phone knows about. Everything here is non-secret
 * bookkeeping - the actual trust is the Keystore keys plus each
 * computer's pinned certificate fingerprint. All computers share one
 * approval key and one TLS identity: each computer's own trust anchor
 * is what scopes an approval to it.
 */
class PairingStore(context: Context) {
    private val prefs = context.getSharedPreferences("pairing", Context.MODE_PRIVATE)

    /**
     * [pin] is the SHA-256 of the computer's certificate: set by a scanned
     * QR code before the first connection, or at enrollment for an
     * address typed by hand. [user] is set once enrollment succeeds.
     * [paused] keeps a computer the user disconnected from reconnecting.
     */
    data class Computer(
        val id: String,
        val host: String,
        val port: Int,
        val name: String,
        val pin: String? = null,
        val user: String? = null,
        val paused: Boolean = false,
    ) {
        val enrolled get() = pin != null && user != null
    }

    /** This installation's own random ID, stable for its lifetime, sent in every hello. */
    val deviceId: String
        get() = prefs.getString("device_id", null) ?: UUID.randomUUID().toString().also {
            prefs.edit().putString("device_id", it).apply()
        }

    var deviceName: String
        get() = prefs.getString("device_name", android.os.Build.MODEL) ?: "Phone"
        set(value) = prefs.edit().putString("device_name", value).apply()

    val computers: List<Computer>
        get() {
            migrateSingleComputer()
            val arr = try { JSONArray(prefs.getString("computers", "[]")) } catch (_: Exception) { JSONArray() }
            return (0 until arr.length()).map {
                val o = arr.getJSONObject(it)
                Computer(
                    id = o.getString("id"),
                    host = o.getString("host"),
                    port = o.getInt("port"),
                    name = o.optString("name"),
                    pin = o.optString("pin").ifEmpty { null },
                    user = o.optString("user").ifEmpty { null },
                    paused = o.optBoolean("paused"),
                )
            }
        }

    fun computer(id: String) = computers.firstOrNull { it.id == id }

    /** Adds [c], or replaces the computer with the same id. */
    fun save(c: Computer) = write(computers.filter { it.id != c.id } + c)

    fun update(id: String, change: (Computer) -> Computer) {
        computer(id)?.let { save(change(it)) }
    }

    fun remove(id: String) = write(computers.filter { it.id != id })

    private fun write(list: List<Computer>) {
        val arr = JSONArray()
        list.forEach {
            arr.put(
                JSONObject().put("id", it.id).put("host", it.host).put("port", it.port).put("name", it.name)
                    .put("pin", it.pin ?: "").put("user", it.user ?: "").put("paused", it.paused),
            )
        }
        prefs.edit().putString("computers", arr.toString()).apply()
    }

    /** Versions with a single computer kept it in flat keys; carry it over once so an update keeps the pairing. */
    private fun migrateSingleComputer() {
        if (prefs.contains("computers")) return
        val host = prefs.getString("computer_host", null)
        val list = if (host == null) emptyList() else listOf(
            Computer(
                id = UUID.randomUUID().toString(),
                host = host,
                port = prefs.getInt("computer_port", DEFAULT_PORT),
                name = host,
                pin = prefs.getString("pinned_fingerprint", null),
                user = prefs.getString("enrolled_user", null),
            ),
        )
        write(list)
        prefs.edit().remove("computer_host").remove("computer_port").remove("pinned_fingerprint").remove("enrolled_user").apply()
    }

    data class Event(val time: Long, val service: String, val user: String, val host: String, val approved: Boolean)

    /** The last [HISTORY_SIZE] approval decisions, newest first - shown on the home screen. */
    val history: List<Event>
        get() {
            val arr = try { JSONArray(prefs.getString("history", "[]")) } catch (_: Exception) { JSONArray() }
            return (0 until arr.length()).map {
                val o = arr.getJSONObject(it)
                Event(o.getLong("time"), o.optString("service"), o.optString("user"), o.optString("host"), o.getBoolean("approved"))
            }
        }

    fun log(e: Event) {
        val arr = JSONArray()
        (listOf(e) + history).take(HISTORY_SIZE).forEach {
            arr.put(JSONObject().put("time", it.time).put("service", it.service).put("user", it.user).put("host", it.host).put("approved", it.approved))
        }
        prefs.edit().putString("history", arr.toString()).apply()
    }

    companion object {
        const val HISTORY_SIZE = 20
        const val DEFAULT_PORT = 17165
    }
}
