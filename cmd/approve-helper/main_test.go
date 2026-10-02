package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"os"
	"os/user"
	"testing"

	"nothing-approve/internal/daemon"
	"nothing-approve/internal/ipc"
	"nothing-approve/internal/keyfile"
	"nothing-approve/internal/protocol"
)

// signingTransport is a daemon.Transport that signs whatever ApproveFields
// it is asked to forward with a fixed private key, or returns a
// deliberately wrong signature - so the test can drive both the
// success path and the "daemon forwarded garbage" path through the
// same real daemon and the same real ipc wire format the helper uses.
type signingTransport struct {
	priv       *ecdsa.PrivateKey
	wrongSig   bool
	gotRequest daemon.ApproveFields
}

func (s *signingTransport) Connected() bool   { return true }
func (s *signingTransport) PhoneName() string { return "Test Phone" }

func (s *signingTransport) SendApprove(ctx context.Context, req daemon.ApproveFields) ([]byte, error) {
	s.gotRequest = req
	ar := protocol.ApproveRequest{
		Host: req.Host, User: req.User, Service: req.Service,
		TTY: req.TTY, RHost: req.RHost, Time: req.Time, Nonce: req.Nonce,
	}
	msg, err := ar.Bytes()
	if err != nil {
		return nil, err
	}
	if s.wrongSig {
		// A signature that is well-formed but made over a different
		// message - exactly what a compromised daemon trying to splice
		// in its own request would produce.
		msg = append(msg, 'x')
	}
	return protocol.Sign(s.priv, msg)
}

func (s *signingTransport) SendEnroll(ctx context.Context, req daemon.EnrollFields) (daemon.EnrollResult, error) {
	return daemon.EnrollResult{}, nil
}

func startDaemonFor(t *testing.T, uid int, tr daemon.Transport) {
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

func setPAMEnv(t *testing.T, pairs map[string]string) {
	t.Helper()
	for k, v := range pairs {
		old, had := os.LookupEnv(k)
		os.Setenv(k, v)
		t.Cleanup(func() {
			if had {
				os.Setenv(k, old)
			} else {
				os.Unsetenv(k)
			}
		})
	}
}

func TestRunApprovesWithAValidSignature(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: writes the trust-anchor file under /etc/nothing-approve")
	}
	me, err := user.Current()
	if err != nil {
		t.Fatalf("user.Current: %v", err)
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if err := keyfile.Write(me.Username, &priv.PublicKey, "dev1", "Test Phone"); err != nil {
		t.Fatalf("keyfile.Write: %v", err)
	}
	t.Cleanup(func() { _ = keyfile.Remove(me.Username) })

	dir := t.TempDir()
	setPAMEnv(t, map[string]string{
		"PAM_USER": me.Username, "PAM_SERVICE": "sudo", "PAM_TTY": "pts/9",
		"PAM_RHOST": "", "PAM_RUSER": "", "XDG_RUNTIME_DIR": dir,
	})
	startDaemonFor(t, os.Getuid(), &signingTransport{priv: priv})

	if code := run(); code != 0 {
		t.Fatalf("run() = %d, want 0 for a valid signature", code)
	}
}

func TestRunRefusesAWrongSignature(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: writes the trust-anchor file under /etc/nothing-approve")
	}
	me, err := user.Current()
	if err != nil {
		t.Fatalf("user.Current: %v", err)
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if err := keyfile.Write(me.Username, &priv.PublicKey, "dev1", "Test Phone"); err != nil {
		t.Fatalf("keyfile.Write: %v", err)
	}
	t.Cleanup(func() { _ = keyfile.Remove(me.Username) })

	dir := t.TempDir()
	setPAMEnv(t, map[string]string{
		"PAM_USER": me.Username, "PAM_SERVICE": "sudo", "PAM_TTY": "pts/9",
		"PAM_RHOST": "", "PAM_RUSER": "", "XDG_RUNTIME_DIR": dir,
	})
	startDaemonFor(t, os.Getuid(), &signingTransport{priv: priv, wrongSig: true})

	if code := run(); code == 0 {
		t.Fatalf("run() = 0, want non-zero for a signature over a different message")
	}
}

func TestRunRefusesSshd(t *testing.T) {
	setPAMEnv(t, map[string]string{"PAM_USER": "root", "PAM_SERVICE": "sshd"})
	if code := run(); code == 0 {
		t.Fatalf("run() = 0 for sshd, want a refusal")
	}
}

func TestRunRefusesAnotherUser(t *testing.T) {
	setPAMEnv(t, map[string]string{
		"PAM_USER": "alice", "PAM_SERVICE": "sudo", "PAM_RUSER": "mallory",
	})
	if code := run(); code == 0 {
		t.Fatalf("run() = 0 when PAM_RUSER differs from PAM_USER, want a refusal")
	}
}

func TestRunRefusesWithNoKeyFile(t *testing.T) {
	me, err := user.Current()
	if err != nil {
		t.Fatalf("user.Current: %v", err)
	}
	if _, err := keyfile.Load(me.Username); err == nil {
		t.Skipf("a real key is already enrolled for %s on this machine; skipping rather than deleting it", me.Username)
	}
	setPAMEnv(t, map[string]string{
		"PAM_USER": me.Username, "PAM_SERVICE": "sudo",
	})
	if code := run(); code == 0 {
		t.Fatalf("run() = 0 with no enrolled key, want a refusal")
	}
}
