package protocol

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
)

// NewNonce returns 32 random bytes, as 64 lowercase hex digits.
func NewNonce() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("nonce: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

// Sign signs msg with priv, which must be on P-256. The result is an
// ASN.1 DER signature over the SHA-256 hash of msg.
func Sign(priv *ecdsa.PrivateKey, msg []byte) ([]byte, error) {
	if priv.Curve != elliptic.P256() {
		return nil, fmt.Errorf("sign: key is not on P-256")
	}
	hash := sha256.Sum256(msg)
	return ecdsa.SignASN1(rand.Reader, priv, hash[:])
}

// Verify reports whether sig is a valid ASN.1 DER signature over the
// SHA-256 hash of msg, made by pub.
func Verify(pub *ecdsa.PublicKey, msg, sig []byte) bool {
	if pub.Curve != elliptic.P256() {
		return false
	}
	hash := sha256.Sum256(msg)
	return ecdsa.VerifyASN1(pub, hash[:], sig)
}

// KeyHash returns the SHA-256 of the DER encoding of pub, as 64 lowercase
// hex digits - what an EnrollRequest.KeyHash must equal, and what the
// enrollment key code is derived from.
func KeyHash(pub *ecdsa.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("key hash: %w", err)
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:]), nil
}

// KeyCode returns the human-readable enrollment code for pub: the first 8
// bytes of its KeyHash, as 16 uppercase hex digits in 4 groups of 4,
// separated by spaces - what the phone shows and the user types back.
func KeyCode(pub *ecdsa.PublicKey) (string, error) {
	h, err := KeyHash(pub)
	if err != nil {
		return "", err
	}
	raw := h[:16] // first 8 bytes, hex-encoded
	upper := make([]byte, 0, 19)
	for i, c := range []byte(raw) {
		if i > 0 && i%4 == 0 {
			upper = append(upper, ' ')
		}
		if c >= 'a' && c <= 'f' {
			c -= 'a' - 'A'
		}
		upper = append(upper, c)
	}
	return string(upper), nil
}

// NormalizeKeyCode strips spaces and hyphens and uppercases, so a typed
// code can be compared regardless of how the user separated the groups.
func NormalizeKeyCode(s string) string {
	out := make([]byte, 0, len(s))
	for _, c := range []byte(s) {
		switch {
		case c == ' ' || c == '-':
			continue
		case c >= 'a' && c <= 'f':
			out = append(out, c-('a'-'A'))
		default:
			out = append(out, c)
		}
	}
	return string(out)
}
