package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"os"
	"os/user"
	"strconv"
	"strings"
	"testing"

	"approven/internal/daemon"
	"approven/internal/ipc"
	"approven/internal/keyfile"
	"approven/internal/protocol"
)

func TestPromptKeyCodeAcceptsNormalizedMatch(t *testing.T) {
	ok, err := promptKeyCode("AB12 CD34 EF56 0078", strings.NewReader("ab12-cd34-ef56-0078\n"))
	if err != nil {
		t.Fatalf("promptKeyCode: %v", err)
	}
	if !ok {
		t.Fatalf("expected a match for a differently-formatted but equal code")
	}
}

func TestPromptKeyCodeFailsAfterThreeTries(t *testing.T) {
	ok, err := promptKeyCode("AB12 CD34 EF56 0078", strings.NewReader("wrong\nwrong\nwrong\n"))
	if err != nil {
		t.Fatalf("promptKeyCode: %v", err)
	}
	if ok {
		t.Fatalf("expected no match after 3 wrong tries")
	}
}

// enrollTransport simulates the phone's side of an enrollment: it makes
// its own key, signs the exact EnrollRequest bytes the CLI will also
// build, and returns the public key DER plus that signature - or,
// for the tamper test, a signature over different bytes.
type enrollTransport struct {
	priv     *ecdsa.PrivateKey
	tamper   bool
	deviceID string
	name     string
}

func (e *enrollTransport) Connected() bool   { return true }
func (e *enrollTransport) PhoneName() string { return e.name }

func (e *enrollTransport) SendApprove(ctx context.Context, req daemon.ApproveFields) ([]byte, error) {
	return nil, nil
}

func (e *enrollTransport) SendEnroll(ctx context.Context, req daemon.EnrollFields) (daemon.EnrollResult, error) {
	der, err := x509.MarshalPKIXPublicKey(&e.priv.PublicKey)
	if err != nil {
		return daemon.EnrollResult{}, err
	}
	keyHash, err := protocol.KeyHash(&e.priv.PublicKey)
	if err != nil {
		return daemon.EnrollResult{}, err
	}
	er := protocol.EnrollRequest{Host: req.Host, User: req.User, KeyHash: keyHash, Time: req.Time, Nonce: req.Nonce}
	msg, err := er.Bytes()
	if err != nil {
		return daemon.EnrollResult{}, err
	}
	if e.tamper {
		msg = append(msg, 'x')
	}
	sig, err := protocol.Sign(e.priv, msg)
	if err != nil {
		return daemon.EnrollResult{}, err
	}
	return daemon.EnrollResult{PublicKeyDER: der, DeviceID: e.deviceID, DeviceName: e.name, Signature: sig}, nil
}

func startCLIDaemon(t *testing.T, uid int, tr daemon.Transport) {
	t.Helper()
	l, err := ipc.Listen(uid)
	if err != nil {
		t.Fatalf("ipc.Listen: %v", err)
	}
	t.Cleanup(func() { l.Close() })
	d := daemon.New(uid, tr, t.Logf)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go d.Serve(ctx, l)
}

func withStdin(t *testing.T, content string) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	old := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = old })
	go func() {
		w.WriteString(content)
		w.Close()
	}()
}

func TestRunEnrollWritesKeyOnValidSignature(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: enroll writes the trust-anchor file and checks os.Geteuid()")
	}
	me, err := user.Current()
	if err != nil {
		t.Fatalf("user.Current: %v", err)
	}
	realUser := os.Getenv("SUDO_USER")
	if realUser == "" {
		t.Skip("run this via sudo so SUDO_USER names a non-root account to enroll")
	}
	t.Cleanup(func() { _ = keyfile.Remove(realUser) })

	u, err := user.Lookup(realUser)
	if err != nil {
		t.Fatalf("user.Lookup(%s): %v", realUser, err)
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		t.Fatalf("Atoi: %v", err)
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tr := &enrollTransport{priv: priv, deviceID: "dev1", name: "Test Phone"}
	startCLIDaemon(t, uid, tr)

	// Compute the real code the "phone" will have signed for, so the
	// piped stdin answers with the actually-correct code rather than a
	// value this test merely asserts was shown - exercising the same
	// path a real user typing the real screen would.
	code, err := protocol.KeyCode(&priv.PublicKey)
	if err != nil {
		t.Fatalf("KeyCode: %v", err)
	}
	withStdin(t, code+"\n")

	if err := runEnroll(); err != nil {
		t.Fatalf("runEnroll: %v", err)
	}

	got, err := keyfile.Load(realUser)
	if err != nil {
		t.Fatalf("keyfile.Load after enroll: %v", err)
	}
	if got.X.Cmp(priv.PublicKey.X) != 0 {
		t.Fatalf("enrolled key does not match the phone's key")
	}
	_ = me
}

func TestRunEnrollRejectsTamperedSignature(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	realUser := os.Getenv("SUDO_USER")
	if realUser == "" {
		t.Skip("run this via sudo so SUDO_USER names a non-root account to enroll")
	}
	t.Cleanup(func() { _ = keyfile.Remove(realUser) })

	u, err := user.Lookup(realUser)
	if err != nil {
		t.Fatalf("user.Lookup(%s): %v", realUser, err)
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		t.Fatalf("Atoi: %v", err)
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tr := &enrollTransport{priv: priv, tamper: true, deviceID: "dev1", name: "Test Phone"}
	startCLIDaemon(t, uid, tr)

	code, _ := protocol.KeyCode(&priv.PublicKey)
	withStdin(t, code+"\n")

	if err := runEnroll(); err == nil {
		t.Fatalf("runEnroll: expected an error for a tampered enrollment signature")
	}
	if _, err := keyfile.Load(realUser); err == nil {
		t.Fatalf("a key file was written despite a tampered signature")
	}
}
