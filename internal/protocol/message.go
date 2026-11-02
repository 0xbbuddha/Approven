// Package protocol builds and validates the exact bytes that a phone signs
// to approve a sudo request, and the bytes it signs to enroll a key. Both
// the desktop helper and the phone app must build byte-identical messages
// from the same fields, or a signature never verifies.
package protocol

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// ApproveVersion and EnrollVersion are the first line of each message.
// They are different strings so a signature for one can never pass as
// the other, and they are specific to this project so a signature made
// for a different approval protocol can never pass as ours.
const (
	ApproveVersion = "approven-v2"
	EnrollVersion  = "approven-enroll-v2"

	// MaxFieldLen is the longest a single field value may be.
	MaxFieldLen = 256

	// NonceHexLen is the length of a nonce once hex-encoded (32 random bytes).
	NonceHexLen = 64
)

// ApproveRequest is the set of fields a sudo (or polkit) approval covers.
type ApproveRequest struct {
	Host    string
	User    string
	Service string
	Command string // what sudo is about to run, so the phone shows it; may be empty
	TTY     string
	RHost   string
	Time    int64
	Nonce   string // 64 lowercase hex digits
}

// EnrollRequest is the set of fields a key-enrollment covers.
type EnrollRequest struct {
	Host    string
	User    string
	KeyHash string // SHA-256 of the DER public key, 64 lowercase hex digits
	// ClientCert and ServerCert are the SHA-256 of the TLS certificates
	// on each end of the connection the enrollment travelled over, as
	// the phone saw them. The computer compares them with its own view:
	// a mismatch means something sat in the middle of that connection.
	ClientCert string
	ServerCert string
	Time       int64
	Nonce      string
}

// field validates a single field value against the shared rules: valid
// UTF-8, no control character (which would let a value smuggle a newline
// and give a message more than one reading), and a length cap.
func field(name, value string) error {
	if value == "" {
		return fmt.Errorf("%s: empty", name)
	}
	if len(value) > MaxFieldLen {
		return fmt.Errorf("%s: longer than %d bytes", name, MaxFieldLen)
	}
	if !utf8.ValidString(value) {
		return fmt.Errorf("%s: not valid UTF-8", name)
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%s: contains a control character", name)
		}
	}
	return nil
}

// optionalField is field, but an empty value is allowed (TTY and RHost
// can genuinely be absent).
func optionalField(name, value string) error {
	if value == "" {
		return nil
	}
	return field(name, value)
}

func validNonce(nonce string) error {
	if len(nonce) != NonceHexLen {
		return fmt.Errorf("nonce: must be %d hex digits", NonceHexLen)
	}
	if _, err := hex.DecodeString(nonce); err != nil {
		return fmt.Errorf("nonce: not hex: %w", err)
	}
	for _, r := range nonce {
		if r >= 'A' && r <= 'F' {
			return fmt.Errorf("nonce: must be lowercase")
		}
	}
	return nil
}

func validHash(name, h string) error {
	if len(h) != 64 {
		return fmt.Errorf("%s: must be 64 hex digits", name)
	}
	if _, err := hex.DecodeString(h); err != nil {
		return fmt.Errorf("%s: not hex: %w", name, err)
	}
	if strings.ToLower(h) != h {
		return fmt.Errorf("%s: must be lowercase", name)
	}
	return nil
}

func validTime(t int64) error {
	if t < 1 || t > (1<<40) {
		return fmt.Errorf("time: out of range")
	}
	return nil
}

// Validate checks every field of r against the shared rules. Build never
// skips this: a message built from an invalid request would be ambiguous
// or would not match what the signer (or verifier) independently builds.
func (r ApproveRequest) Validate() error {
	if err := field("host", r.Host); err != nil {
		return err
	}
	if err := field("user", r.User); err != nil {
		return err
	}
	if err := field("service", r.Service); err != nil {
		return err
	}
	if err := optionalField("command", r.Command); err != nil {
		return err
	}
	if err := optionalField("tty", r.TTY); err != nil {
		return err
	}
	if err := optionalField("rhost", r.RHost); err != nil {
		return err
	}
	if err := validTime(r.Time); err != nil {
		return err
	}
	return validNonce(r.Nonce)
}

func (r EnrollRequest) Validate() error {
	if err := field("host", r.Host); err != nil {
		return err
	}
	if err := field("user", r.User); err != nil {
		return err
	}
	for _, h := range []struct{ name, value string }{
		{"key", r.KeyHash}, {"client", r.ClientCert}, {"server", r.ServerCert},
	} {
		if err := validHash(h.name, h.value); err != nil {
			return err
		}
	}
	if err := validTime(r.Time); err != nil {
		return err
	}
	return validNonce(r.Nonce)
}

// Bytes returns the exact bytes that get signed. 9 lines, each ending in
// exactly one newline, in a fixed order - this shape, not just the field
// values, is part of what the signature covers.
func (r ApproveRequest) Bytes() ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	var b strings.Builder
	b.WriteString(ApproveVersion + "\n")
	b.WriteString("host=" + r.Host + "\n")
	b.WriteString("user=" + r.User + "\n")
	b.WriteString("service=" + r.Service + "\n")
	b.WriteString("command=" + r.Command + "\n")
	b.WriteString("tty=" + r.TTY + "\n")
	b.WriteString("rhost=" + r.RHost + "\n")
	b.WriteString("time=" + strconv.FormatInt(r.Time, 10) + "\n")
	b.WriteString("nonce=" + r.Nonce + "\n")
	return []byte(b.String()), nil
}

func (r EnrollRequest) Bytes() ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	var b strings.Builder
	b.WriteString(EnrollVersion + "\n")
	b.WriteString("host=" + r.Host + "\n")
	b.WriteString("user=" + r.User + "\n")
	b.WriteString("key=" + r.KeyHash + "\n")
	b.WriteString("client=" + r.ClientCert + "\n")
	b.WriteString("server=" + r.ServerCert + "\n")
	b.WriteString("time=" + strconv.FormatInt(r.Time, 10) + "\n")
	b.WriteString("nonce=" + r.Nonce + "\n")
	return []byte(b.String()), nil
}

// CheckCode is the short code both the terminal and the phone show for
// one approval, so the human can tell their own sudo from one started
// at the same moment by something else running as them. The nonce is
// fresh and random per request, so its first 4 hex digits are as good
// as any derived value.
func CheckCode(nonce string) string {
	if len(nonce) < 4 {
		return ""
	}
	return strings.ToUpper(nonce[:4])
}

// Clean makes s safe to print or to store as one field: control
// characters (terminal escapes, newlines) become '?', and the result
// is cut to MaxFieldLen bytes on a rune boundary.
func Clean(s string) string {
	var b strings.Builder
	for _, r := range strings.ToValidUTF8(s, "?") {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			r = '?'
		}
		if b.Len()+utf8.RuneLen(r) > MaxFieldLen {
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}
