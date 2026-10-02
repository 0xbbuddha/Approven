package protocol

import (
	"strings"
	"testing"
)

func validApprove() ApproveRequest {
	return ApproveRequest{
		Host:    "eos",
		User:    "bbuddha",
		Service: "sudo",
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
	want := "nothing-approve-v1\n" +
		"host=eos\n" +
		"user=bbuddha\n" +
		"service=sudo\n" +
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
		strings.Repeat("a", 63),               // too short
		strings.Repeat("a", 65),               // too long
		strings.Repeat("A1", 32),               // uppercase hex
		strings.Repeat("zz", 32),               // not hex
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
		Host:    "eos",
		User:    "bbuddha",
		KeyHash: strings.Repeat("b2", 32),
		Time:    1700000000,
		Nonce:   strings.Repeat("c3", 32),
	}
	b, err := r.Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}
	want := "nothing-approve-enroll-v1\n" +
		"host=eos\n" +
		"user=bbuddha\n" +
		"key=" + strings.Repeat("b2", 32) + "\n" +
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
		KeyHash: strings.Repeat("a1", 32), // deliberately reuse the approve nonce value as key hash
		Time:    1700000000,
		Nonce:   strings.Repeat("a1", 32),
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
