package protocol

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func validApprove() ApproveRequest {
	return ApproveRequest{
		Host:    "eos",
		User:    "bbuddha",
		Service: "sudo",
		Command: "sudo pacman -Syu",
		TTY:     "pts/2",
		RHost:   "",
		Time:    1700000000,
		Nonce:   strings.Repeat("a1", 32), // 64 hex chars
	}
}

func TestApproveBytesAreStable(t *testing.T) {
	r := validApprove()
	b1, err := r.Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}
	b2, err := r.Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}
	if string(b1) != string(b2) {
		t.Fatalf("same request produced different bytes")
	}
	want := "approven-v2\n" +
		"host=eos\n" +
		"user=bbuddha\n" +
		"service=sudo\n" +
		"command=sudo pacman -Syu\n" +
		"tty=pts/2\n" +
		"rhost=\n" +
		"time=1700000000\n" +
		"nonce=" + strings.Repeat("a1", 32) + "\n"
	if string(b1) != want {
		t.Fatalf("Bytes mismatch:\ngot:  %q\nwant: %q", b1, want)
	}
}

func TestApproveRejectsControlCharacterSmuggling(t *testing.T) {
	r := validApprove()
	r.TTY = "pts/2\nservice=root-shell"
	if _, err := r.Bytes(); err == nil {
		t.Fatalf("expected an error for a newline inside a field")
	}
}

func TestApproveRejectsEmptyRequiredField(t *testing.T) {
	for _, mutate := range []func(*ApproveRequest){
		func(r *ApproveRequest) { r.Host = "" },
		func(r *ApproveRequest) { r.User = "" },
		func(r *ApproveRequest) { r.Service = "" },
	} {
		r := validApprove()
		mutate(&r)
		if _, err := r.Bytes(); err == nil {
			t.Fatalf("expected an error for an empty required field")
		}
	}
}

func TestApproveAllowsEmptyOptionalFields(t *testing.T) {
	r := validApprove()
	r.TTY = ""
	r.RHost = ""
	if _, err := r.Bytes(); err != nil {
		t.Fatalf("tty and rhost must be allowed empty: %v", err)
	}
}

func TestApproveRejectsBadNonce(t *testing.T) {
	cases := []string{
		"",
		strings.Repeat("a", 63),  // too short
		strings.Repeat("a", 65),  // too long
		strings.Repeat("A1", 32), // uppercase hex
		strings.Repeat("zz", 32), // not hex
	}
	for _, nonce := range cases {
		r := validApprove()
		r.Nonce = nonce
		if _, err := r.Bytes(); err == nil {
			t.Fatalf("nonce %q: expected an error", nonce)
		}
	}
}

func TestApproveRejectsOutOfRangeTime(t *testing.T) {
	for _, tm := range []int64{0, -1, 1 << 41} {
		r := validApprove()
		r.Time = tm
		if _, err := r.Bytes(); err == nil {
			t.Fatalf("time %d: expected an error", tm)
		}
	}
}

func TestEnrollBytesAreStable(t *testing.T) {
	r := EnrollRequest{
		Host:       "eos",
		User:       "bbuddha",
		KeyHash:    strings.Repeat("b2", 32),
		ClientCert: strings.Repeat("d4", 32),
		ServerCert: strings.Repeat("e5", 32),
		Time:       1700000000,
		Nonce:      strings.Repeat("c3", 32),
	}
	b, err := r.Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}
	want := "approven-enroll-v2\n" +
		"host=eos\n" +
		"user=bbuddha\n" +
		"key=" + strings.Repeat("b2", 32) + "\n" +
		"client=" + strings.Repeat("d4", 32) + "\n" +
		"server=" + strings.Repeat("e5", 32) + "\n" +
		"time=1700000000\n" +
		"nonce=" + strings.Repeat("c3", 32) + "\n"
	if string(b) != want {
		t.Fatalf("Bytes mismatch:\ngot:  %q\nwant: %q", b, want)
	}
}

func TestApproveAndEnrollNeverCollide(t *testing.T) {
	a := validApprove()
	ab, _ := a.Bytes()
	e := EnrollRequest{
		Host: "eos", User: "bbuddha",
		KeyHash:    strings.Repeat("a1", 32), // deliberately reuse the approve nonce value as key hash
		ClientCert: strings.Repeat("a1", 32),
		ServerCert: strings.Repeat("a1", 32),
		Time:       1700000000,
		Nonce:      strings.Repeat("a1", 32),
	}
	eb, _ := e.Bytes()
	if string(ab) == string(eb) {
		t.Fatalf("an approve and an enroll message must never be byte-identical")
	}
	if !strings.HasPrefix(string(ab), ApproveVersion+"\n") {
		t.Fatalf("approve message must start with its version line")
	}
	if !strings.HasPrefix(string(eb), EnrollVersion+"\n") {
		t.Fatalf("enroll message must start with its version line")
	}
}

func TestApproveAllowsEmptyCommandButNotSmuggling(t *testing.T) {
	r := validApprove()
	r.Command = ""
	if _, err := r.Bytes(); err != nil {
		t.Fatalf("command must be allowed empty: %v", err)
	}
	r.Command = "true\ntty=pts/9"
	if _, err := r.Bytes(); err == nil {
		t.Fatalf("expected an error for a newline inside command")
	}
}

func TestEnrollRejectsBadCertHashes(t *testing.T) {
	base := EnrollRequest{
		Host: "eos", User: "bbuddha", KeyHash: strings.Repeat("b2", 32),
		ClientCert: strings.Repeat("d4", 32), ServerCert: strings.Repeat("e5", 32),
		Time: 1700000000, Nonce: strings.Repeat("c3", 32),
	}
	for _, mutate := range []func(*EnrollRequest){
		func(r *EnrollRequest) { r.ClientCert = "" },
		func(r *EnrollRequest) { r.ServerCert = strings.Repeat("E5", 32) },
		func(r *EnrollRequest) { r.ServerCert = strings.Repeat("zz", 32) },
	} {
		r := base
		mutate(&r)
		if _, err := r.Bytes(); err == nil {
			t.Fatalf("expected an error for %+v", r)
		}
	}
}

func TestCheckCode(t *testing.T) {
	if got := CheckCode("3fa9" + strings.Repeat("0", 60)); got != "3FA9" {
		t.Fatalf("CheckCode = %q", got)
	}
}

func TestClean(t *testing.T) {
	cases := map[string]string{
		"Pixel 8":           "Pixel 8",
		"evil\x1b[2J\nname": "evil?[2J?name",
		"bad\xffutf8":       "bad?utf8",
		"\u009b31m":         "?31m", // C1 CSI, also a terminal escape
	}
	for in, want := range cases {
		if got := Clean(in); got != want {
			t.Errorf("Clean(%q) = %q, want %q", in, got, want)
		}
	}
	if got := Clean(strings.Repeat("é", 200)); len(got) > MaxFieldLen || !utf8.ValidString(got) {
		t.Errorf("Clean must cut on a rune boundary within MaxFieldLen, got %d bytes", len(got))
	}
}
