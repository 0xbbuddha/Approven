package protocol

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"strings"
	"testing"
)

func genKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return priv
}

func TestSignVerifyRoundTrip(t *testing.T) {
	priv := genKey(t)
	msg := []byte("some message bytes")
	sig, err := Sign(priv, msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !Verify(&priv.PublicKey, msg, sig) {
		t.Fatalf("Verify: a fresh signature did not verify")
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	priv := genKey(t)
	other := genKey(t)
	msg := []byte("some message bytes")
	sig, _ := Sign(priv, msg)
	if Verify(&other.PublicKey, msg, sig) {
		t.Fatalf("Verify: a signature verified against the wrong key")
	}
}

func TestVerifyRejectsTamperedMessage(t *testing.T) {
	priv := genKey(t)
	msg := []byte("nothing-approve-v1\nhost=eos\n")
	sig, _ := Sign(priv, msg)
	tampered := []byte("nothing-approve-v1\nhost=evil\n")
	if Verify(&priv.PublicKey, tampered, sig) {
		t.Fatalf("Verify: a signature verified a message it was not made for")
	}
}

func TestVerifyRejectsTruncatedSignature(t *testing.T) {
	priv := genKey(t)
	msg := []byte("some message")
	sig, _ := Sign(priv, msg)
	if Verify(&priv.PublicKey, msg, sig[:len(sig)-1]) {
		t.Fatalf("Verify: a truncated signature verified")
	}
}

func TestNewNonceIsHexAndUnique(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		n, err := NewNonce()
		if err != nil {
			t.Fatalf("NewNonce: %v", err)
		}
		if err := validNonce(n); err != nil {
			t.Fatalf("NewNonce produced an invalid nonce %q: %v", n, err)
		}
		if seen[n] {
			t.Fatalf("NewNonce produced a duplicate: %q", n)
		}
		seen[n] = true
	}
}

func TestKeyHashIsStableAndDistinct(t *testing.T) {
	priv := genKey(t)
	h1, err := KeyHash(&priv.PublicKey)
	if err != nil {
		t.Fatalf("KeyHash: %v", err)
	}
	h2, _ := KeyHash(&priv.PublicKey)
	if h1 != h2 {
		t.Fatalf("KeyHash is not stable for the same key")
	}
	if len(h1) != 64 {
		t.Fatalf("KeyHash: want 64 hex chars, got %d", len(h1))
	}
	other := genKey(t)
	h3, _ := KeyHash(&other.PublicKey)
	if h1 == h3 {
		t.Fatalf("KeyHash produced the same hash for two different keys")
	}
}

func TestKeyCodeFormatAndNormalize(t *testing.T) {
	priv := genKey(t)
	code, err := KeyCode(&priv.PublicKey)
	if err != nil {
		t.Fatalf("KeyCode: %v", err)
	}
	// 16 hex digits in 4 groups of 4, separated by 3 spaces: 19 chars.
	if len(code) != 19 {
		t.Fatalf("KeyCode: want 19 chars (XXXX XXXX XXXX XXXX), got %d: %q", len(code), code)
	}
	for _, part := range strings.Split(code, " ") {
		if len(part) != 4 {
			t.Fatalf("KeyCode group %q: want 4 chars", part)
		}
	}
	if code != strings.ToUpper(code) {
		t.Fatalf("KeyCode must be uppercase: %q", code)
	}

	messy := "  " + strings.ToLower(code[:4]) + "-" + code[5:9] + " " + code[10:14] + "-" + code[15:]
	if NormalizeKeyCode(messy) != strings.ReplaceAll(code, " ", "") {
		t.Fatalf("NormalizeKeyCode(%q) = %q, want %q", messy, NormalizeKeyCode(messy), strings.ReplaceAll(code, " ", ""))
	}
}
