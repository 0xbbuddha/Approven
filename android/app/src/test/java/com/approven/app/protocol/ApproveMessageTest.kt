package com.approven.app.protocol

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

/**
 * Same field values as the Go side's internal/protocol/message_test.go,
 * so [TestApproveBytesAreStable] below asserts byte-for-byte the same
 * expected string the Go test does - the actual cross-language contract
 * this whole project depends on.
 */
class ApproveMessageTest {
    private fun validApprove() = ApproveMessage.ApproveRequest(
        host = "eos", user = "bbuddha", service = "sudo",
        command = "sudo pacman -Syu", tty = "pts/2", rhost = "", time = 1700000000L,
        nonce = "a1".repeat(32),
    )

    @Test
    fun approveBytesMatchTheGoSide() {
        val want = "approven-v2\n" +
            "host=eos\n" +
            "user=bbuddha\n" +
            "service=sudo\n" +
            "command=sudo pacman -Syu\n" +
            "tty=pts/2\n" +
            "rhost=\n" +
            "time=1700000000\n" +
            "nonce=${"a1".repeat(32)}\n"
        val got = ApproveMessage.bytesOf(validApprove())
        assertEquals(want, String(got, Charsets.UTF_8))
    }

    @Test
    fun bytesAreStableAcrossCalls() {
        val r = validApprove()
        assertArrayEquals(ApproveMessage.bytesOf(r), ApproveMessage.bytesOf(r))
    }

    @Test
    fun rejectsControlCharacterSmuggling() {
        val r = validApprove().copy(tty = "pts/2\nservice=root-shell")
        assertThrows(ApproveMessage.InvalidFieldException::class.java) {
            ApproveMessage.bytesOf(r)
        }
    }

    @Test
    fun rejectsEmptyRequiredFields() {
        assertThrows(ApproveMessage.InvalidFieldException::class.java) {
            ApproveMessage.bytesOf(validApprove().copy(host = ""))
        }
        assertThrows(ApproveMessage.InvalidFieldException::class.java) {
            ApproveMessage.bytesOf(validApprove().copy(user = ""))
        }
        assertThrows(ApproveMessage.InvalidFieldException::class.java) {
            ApproveMessage.bytesOf(validApprove().copy(service = ""))
        }
    }

    @Test
    fun allowsEmptyOptionalFields() {
        val r = validApprove().copy(tty = "", rhost = "")
        ApproveMessage.bytesOf(r) // must not throw
    }

    @Test
    fun rejectsBadNonces() {
        val bad = listOf(
            "",
            "a".repeat(63),
            "a".repeat(65),
            "A1".repeat(32), // uppercase
            "zz".repeat(32), // not hex
        )
        for (nonce in bad) {
            assertThrows("nonce=$nonce", ApproveMessage.InvalidFieldException::class.java) {
                ApproveMessage.bytesOf(validApprove().copy(nonce = nonce))
            }
        }
    }

    @Test
    fun rejectsOutOfRangeTime() {
        for (t in listOf(0L, -1L, 1L shl 41)) {
            assertThrows("time=$t", ApproveMessage.InvalidFieldException::class.java) {
                ApproveMessage.bytesOf(validApprove().copy(time = t))
            }
        }
    }

    @Test
    fun enrollBytesMatchTheGoSide() {
        val r = ApproveMessage.EnrollRequest(
            host = "eos", user = "bbuddha",
            keyHash = "b2".repeat(32), clientCert = "d4".repeat(32), serverCert = "e5".repeat(32),
            time = 1700000000L, nonce = "c3".repeat(32),
        )
        val want = "approven-enroll-v2\n" +
            "host=eos\n" +
            "user=bbuddha\n" +
            "key=${"b2".repeat(32)}\n" +
            "client=${"d4".repeat(32)}\n" +
            "server=${"e5".repeat(32)}\n" +
            "time=1700000000\n" +
            "nonce=${"c3".repeat(32)}\n"
        assertEquals(want, String(ApproveMessage.bytesOf(r), Charsets.UTF_8))
    }

    @Test
    fun rejectsCommandSmugglingAndBadCertHashes() {
        assertThrows(ApproveMessage.InvalidFieldException::class.java) {
            ApproveMessage.bytesOf(validApprove().copy(command = "true\ntty=pts/9"))
        }
        ApproveMessage.bytesOf(validApprove().copy(command = "")) // optional, must not throw
        val e = ApproveMessage.EnrollRequest(
            host = "eos", user = "bbuddha", keyHash = "b2".repeat(32),
            clientCert = "d4".repeat(32), serverCert = "e5".repeat(32), time = 1L, nonce = "c3".repeat(32),
        )
        for (bad in listOf(e.copy(clientCert = ""), e.copy(serverCert = "E5".repeat(32)))) {
            assertThrows(ApproveMessage.InvalidFieldException::class.java) { ApproveMessage.bytesOf(bad) }
        }
    }

    @Test
    fun checkCodeMatchesTheGoSide() {
        assertEquals("3FA9", ApproveMessage.checkCode("3fa9" + "0".repeat(60)))
    }

    @Test
    fun approveAndEnrollNeverCollide() {
        val a = ApproveMessage.bytesOf(validApprove())
        val e = ApproveMessage.bytesOf(
            ApproveMessage.EnrollRequest(
                host = "eos", user = "bbuddha",
                keyHash = "a1".repeat(32), clientCert = "a1".repeat(32), serverCert = "a1".repeat(32),
                time = 1700000000L, nonce = "a1".repeat(32),
            ),
        )
        assert(!a.contentEquals(e)) { "an approve and an enroll message must never be byte-identical" }
    }
}
