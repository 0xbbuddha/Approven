package com.approven.app

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.security.MessageDigest
import java.security.Signature
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec

/**
 * The approval signing key in the Android Keystore: EC P-256,
 * sign-only, usable only after a fresh strong-biometric check, in
 * StrongBox when the device has it. Mirrors the properties
 * docs/approve.md requires of the phone side.
 */
object CryptoKeys {
    private const val KEYSTORE = "AndroidKeyStore"
    private const val ALIAS = "approven-key"
    const val TLS_ALIAS = "approven-tls"

    fun hasKey(): Boolean {
        val ks = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        return ks.containsAlias(ALIAS)
    }

    fun publicKey(): PublicKey? {
        val ks = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        return ks.getCertificate(ALIAS)?.publicKey
    }

    /**
     * The existing approval key, when it can still sign - adding a
     * fingerprint permanently invalidates it - or null. Enrolling another
     * computer reuses it, so pairing a second computer does not break the
     * first one.
     */
    fun usableKey(): PublicKey? = try {
        newSignatureForSigning()
        publicKey()
    } catch (_: Exception) {
        null
    }

    fun deleteKey() {
        val ks = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        if (ks.containsAlias(ALIAS)) ks.deleteEntry(ALIAS)
    }

    /** Forgetting the computer also drops the TLS identity it pinned. */
    fun deleteAll() {
        deleteKey()
        val ks = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        if (ks.containsAlias(TLS_ALIAS)) ks.deleteEntry(TLS_ALIAS)
    }

    /**
     * The TLS client identity this phone presents to the computer, made
     * on first use. A separate key from the approval one on purpose: it
     * must sign every handshake in the background, so it cannot require
     * a fingerprint - and so it proves only "this is the enrolled
     * phone's app", never "the human approved". The computer pins its
     * certificate at enrollment so nobody else on the network can take
     * the phone's place. The Keystore self-signs a certificate for it.
     */
    fun tlsIdentity(): Pair<PrivateKey, X509Certificate> {
        val ks = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        if (!ks.containsAlias(TLS_ALIAS)) {
            val spec = KeyGenParameterSpec.Builder(TLS_ALIAS, KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                // NONE: the TLS stack hands the Keystore a precomputed digest.
                .setDigests(KeyProperties.DIGEST_NONE, KeyProperties.DIGEST_SHA256)
                .build()
            KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, KEYSTORE).apply { initialize(spec) }.generateKeyPair()
        }
        return ks.getKey(TLS_ALIAS, null) as PrivateKey to ks.getCertificate(TLS_ALIAS) as X509Certificate
    }

    /** SHA-256 hex of the TLS client certificate - what the computer pins. */
    fun tlsCertHash(): String = sha256Hex(tlsIdentity().second.encoded)

    fun sha256Hex(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

    /**
     * Generates a new key, replacing any existing one under the same
     * alias. Call only right before an enrollment actually sends the
     * new public key: on any failure after this point the caller must
     * delete the key again, so an abandoned enrollment never leaves an
     * orphaned key the user did not mean to keep.
     */
    fun generateKey(): PublicKey {
        try {
            return buildKey(strongBox = true)
        } catch (e: StrongBoxUnavailableException) {
            return buildKey(strongBox = false)
        }
    }

    private fun buildKey(strongBox: Boolean): PublicKey {
        val builder = KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setUserAuthenticationRequired(true)
            .setInvalidatedByBiometricEnrollment(true)
            .setIsStrongBoxBacked(strongBox)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            builder.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
        } else {
            @Suppress("DEPRECATION")
            builder.setUserAuthenticationValidityDurationSeconds(-1)
        }

        val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, KEYSTORE)
        kpg.initialize(builder.build())
        return kpg.generateKeyPair().public
    }

    /**
     * A [Signature] primed to sign with the stored key over
     * SHA256withECDSA, for [androidx.biometric.BiometricPrompt.CryptoObject].
     * Each instance needs its own fresh biometric check - never reuse
     * one across 2 approvals.
     */
    fun newSignatureForSigning(): Signature {
        val ks = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        val key = ks.getKey(ALIAS, null) as PrivateKey
        return Signature.getInstance("SHA256withECDSA").apply { initSign(key) }
    }
}
