package com.approven.app

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
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

    fun hasKey(): Boolean {
        val ks = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        return ks.containsAlias(ALIAS)
    }

    fun publicKey(): PublicKey? {
        val ks = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        return ks.getCertificate(ALIAS)?.publicKey
    }

    fun deleteKey() {
        val ks = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        if (ks.containsAlias(ALIAS)) ks.deleteEntry(ALIAS)
    }

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
