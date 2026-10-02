package com.approven.app

import android.content.Context
import java.util.UUID

/**
 * The one paired computer this app knows about. v1 supports exactly
 * one: enrolling a second computer replaces it. Everything here is
 * non-secret bookkeeping - the actual trust is the Keystore key plus
 * the pinned certificate fingerprint, not this file's existence.
 */
class PairingStore(context: Context) {
    private val prefs = context.getSharedPreferences("pairing", Context.MODE_PRIVATE)

    /** This installation's own random ID, stable for its lifetime, sent in every hello. */
    val deviceId: String
        get() = prefs.getString("device_id", null) ?: UUID.randomUUID().toString().also {
            prefs.edit().putString("device_id", it).apply()
        }

    var deviceName: String
        get() = prefs.getString("device_name", android.os.Build.MODEL) ?: "Phone"
        set(value) = prefs.edit().putString("device_name", value).apply()

    var computerHost: String?
        get() = prefs.getString("computer_host", null)
        set(value) = prefs.edit().putString("computer_host", value).apply()

    var computerPort: Int
        get() = prefs.getInt("computer_port", 17165)
        set(value) = prefs.edit().putInt("computer_port", value).apply()

    /** SHA-256 of the computer's certificate, pinned the moment enrollment succeeds. */
    var pinnedFingerprint: String?
        get() = prefs.getString("pinned_fingerprint", null)
        set(value) = prefs.edit().putString("pinned_fingerprint", value).apply()

    var enrolledUser: String?
        get() = prefs.getString("enrolled_user", null)
        set(value) = prefs.edit().putString("enrolled_user", value).apply()

    val isEnrolled: Boolean
        get() = pinnedFingerprint != null && enrolledUser != null

    fun clear() = prefs.edit().clear().apply()
}
