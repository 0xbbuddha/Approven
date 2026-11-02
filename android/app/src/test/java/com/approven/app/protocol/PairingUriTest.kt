package com.approven.app.protocol

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class PairingUriTest {
    private val fp = "e5".repeat(32)

    @Test
    fun parsesWhatTheGoSideEncodes() {
        // Exactly cmd/approve-cli's pairingURI output (url.Values.Encode: sorted keys, '+' for spaces).
        val got = PairingUri.parse("approven://pair?fp=$fp&h=10.0.0.7&n=my+host&p=17165")
        assertEquals(PairingUri("10.0.0.7", 17165, fp, "my host"), got)
    }

    @Test
    fun rejectsAnythingMalformed() {
        val bad = listOf(
            "https://pair?fp=$fp&h=10.0.0.7&p=17165", // wrong scheme
            "approven://pair?h=10.0.0.7&p=17165", // no fingerprint
            "approven://pair?fp=${"E5".repeat(32)}&h=10.0.0.7&p=17165", // uppercase fingerprint
            "approven://pair?fp=$fp&h=10.0.0.7&p=70000", // port out of range
            "approven://pair?fp=$fp&h=evil%20host&p=17165", // space in host
            "approven://pair?fp=$fp&p=17165", // no host
            "not a uri at all",
        )
        for (raw in bad) assertNull(raw, PairingUri.parse(raw))
    }

    @Test
    fun nameFallsBackToHostAndDropsControlCharacters() {
        assertEquals("10.0.0.7", PairingUri.parse("approven://pair?fp=$fp&h=10.0.0.7&p=1")!!.name)
        assertEquals("eos", PairingUri.parse("approven://pair?fp=$fp&h=10.0.0.7&n=e%0Aos&p=1")!!.name)
    }
}
