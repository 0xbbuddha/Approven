package com.approven.app.protocol

import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class KeyCodeTest {
    private fun genKeyPair() = KeyPairGenerator.getInstance("EC").apply {
        initialize(ECGenParameterSpec("secp256r1"))
    }.generateKeyPair()

    @Test
    fun keyHashIsStableAndDistinct() {
        val a = genKeyPair()
        val b = genKeyPair()
        assertEquals(KeyCode.keyHash(a.public), KeyCode.keyHash(a.public))
        assertEquals(64, KeyCode.keyHash(a.public).length)
        assertNotEquals(KeyCode.keyHash(a.public), KeyCode.keyHash(b.public))
    }

    @Test
    fun keyCodeFormat() {
        val pair = genKeyPair()
        val code = KeyCode.keyCode(pair.public)
        assertEquals(19, code.length) // XXXX XXXX XXXX XXXX
        for (group in code.split(" ")) assertEquals(4, group.length)
        assertEquals(code.uppercase(), code)
    }

    @Test
    fun normalizeIgnoresFormatting() {
        val pair = genKeyPair()
        val code = KeyCode.keyCode(pair.public)
        val messy = "  " + code.lowercase().replace(" ", "-")
        assertEquals(KeyCode.normalize(code), KeyCode.normalize(messy))
    }

    @Test
    fun keyHashMatchesTheSha256OfTheEncodedKey() {
        // Sanity check that KeyCode hashes getEncoded() (X.509 SPKI DER),
        // the same bytes Go's x509.MarshalPKIXPublicKey produces for an
        // EC key - the actual cross-language contract.
        val pair = genKeyPair()
        val digest = java.security.MessageDigest.getInstance("SHA-256").digest(pair.public.encoded)
        val want = digest.joinToString("") { "%02x".format(it) }
        assertEquals(want, KeyCode.keyHash(pair.public))
        assertTrue(pair.public.format == "X.509")
    }
}
