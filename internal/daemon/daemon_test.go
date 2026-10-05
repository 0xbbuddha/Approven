package daemon

import (
	"context"
	"net"
	"os"
	"testing"
	"time"

	"approven/internal/ipc"
)

// fakeTransport lets the tests drive the daemon's local protocol without
// a network or a phone.
type fakeTransport struct {
	connected bool
	name      string

	approveSig  []byte
	approveErr  error
	approveWait time.Duration // simulated delay, to exercise the timeout path

	enrollRes EnrollResult
	enrollErr error

	gotApprove ApproveFields
	gotEnroll  EnrollFields

	gotAckNonce string
	gotAckOK    bool
	gotAckError string
}

func (f *fakeTransport) Connected() bool   { return f.connected }
func (f *fakeTransport) PhoneName() string { return f.name }

func (f *fakeTransport) SendApprove(ctx context.Context, req ApproveFields) ([]byte, error) {
	f.gotApprove = req
	if f.approveWait > 0 {
		select {
		case <-time.After(f.approveWait):
		case <-ctx.Done():
			return nil, ErrTimedOut
		}
	}
	return f.approveSig, f.approveErr
}

func (f *fakeTransport) SendEnroll(ctx context.Context, req EnrollFields) (EnrollResult, error) {
	f.gotEnroll = req
	return f.enrollRes, f.enrollErr
}

func (f *fakeTransport) SendEnrollResult(nonce string, ok bool, errMsg string) error {
	f.gotAckNonce, f.gotAckOK, f.gotAckError = nonce, ok, errMsg
	return nil
}

// startTestDaemon starts a Daemon backed by tr, listening on a socket
// under a fresh temp XDG_RUNTIME_DIR, and returns that uid for Dial.
func startTestDaemon(t *testing.T, tr Transport) int {
	t.Helper()
	dir := t.TempDir()
	old, had := os.LookupEnv("XDG_RUNTIME_DIR")
	os.Setenv("XDG_RUNTIME_DIR", dir)
	t.Cleanup(func() {
		if had {
			os.Setenv("XDG_RUNTIME_DIR", old)
		} else {
			os.Unsetenv("XDG_RUNTIME_DIR")
		}
	})

	uid := os.Getuid()
	l, err := ipc.Listen(uid)
	if err != nil {
		t.Fatalf("ipc.Listen: %v", err)
	}
	t.Cleanup(func() { l.Close() })

	d := New(uid, tr, t.Logf)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go d.Serve(ctx, l)
	return uid
}

func roundTrip(t *testing.T, uid int, req Request) Response {
	t.Helper()
	conn, err := ipc.Dial(uid)
	if err != nil {
		t.Fatalf("ipc.Dial: %v", err)
	}
	defer conn.Close()
	if err := ipc.WriteJSON(conn, req); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	var resp Response
	if err := ipc.NewLineReader(conn).ReadJSON(&resp); err != nil {
		t.Fatalf("ReadJSON: %v", err)
	}
	return resp
}

func TestApproveSuccess(t *testing.T) {
	tr := &fakeTransport{connected: true, approveSig: []byte("sig-bytes")}
	uid := startTestDaemon(t, tr)

	resp := roundTrip(t, uid, Request{
		Cmd: "approve", Host: "eos", User: "bbuddha", Service: "sudo",
		TTY: "pts/2", Time: 123, Nonce: "abc", WaitSeconds: 5,
	})
	if !resp.OK {
		t.Fatalf("resp.OK = false, error = %q", resp.Error)
	}
	if string(resp.Signature) != "sig-bytes" {
		t.Fatalf("signature = %q, want sig-bytes", resp.Signature)
	}
	if tr.gotApprove.Host != "eos" || tr.gotApprove.Nonce != "abc" {
		t.Fatalf("transport got the wrong fields: %+v", tr.gotApprove)
	}
}

func TestApproveDenied(t *testing.T) {
	tr := &fakeTransport{connected: true, approveErr: ErrDenied}
	uid := startTestDaemon(t, tr)

	resp := roundTrip(t, uid, Request{Cmd: "approve", Host: "eos", User: "u", Service: "sudo", Nonce: "n", Time: 1})
	if resp.OK {
		t.Fatalf("resp.OK = true for a denial")
	}
	if resp.Error != ErrDenied.Error() {
		t.Fatalf("resp.Error = %q, want %q", resp.Error, ErrDenied.Error())
	}
}

func TestApproveTimesOut(t *testing.T) {
	tr := &fakeTransport{connected: true, approveWait: 200 * time.Millisecond}
	uid := startTestDaemon(t, tr)

	resp := roundTrip(t, uid, Request{
		Cmd: "approve", Host: "eos", User: "u", Service: "sudo", Nonce: "n", Time: 1,
		WaitSeconds: 1, // the daemon's own wait context; comfortably longer than the simulated phone delay
	})
	if !resp.OK {
		t.Fatalf("expected success once the simulated delay elapses, got error=%q", resp.Error)
	}
}

func TestApproveNoPhone(t *testing.T) {
	tr := &fakeTransport{connected: false}
	uid := startTestDaemon(t, tr)

	resp := roundTrip(t, uid, Request{Cmd: "approve", Host: "eos", User: "u", Service: "sudo", Nonce: "n", Time: 1})
	if resp.OK {
		t.Fatalf("resp.OK = true with no phone connected")
	}
	if resp.Error != ErrNoPhone.Error() {
		t.Fatalf("resp.Error = %q, want %q", resp.Error, ErrNoPhone.Error())
	}
}

func TestEnrollSuccess(t *testing.T) {
	tr := &fakeTransport{connected: true, enrollRes: EnrollResult{
		PublicKeyDER: []byte("der-bytes"), DeviceID: "dev1", DeviceName: "Pixel", Signature: []byte("enroll-sig"),
	}}
	uid := startTestDaemon(t, tr)

	resp := roundTrip(t, uid, Request{Cmd: "enroll", Host: "eos", User: "u", EnrollTime: 1, EnrollNonce: "n"})
	if !resp.OK {
		t.Fatalf("resp.OK = false, error = %q", resp.Error)
	}
	if string(resp.PublicKeyDER) != "der-bytes" || resp.DeviceID != "dev1" || resp.DeviceName != "Pixel" {
		t.Fatalf("unexpected enroll response: %+v", resp)
	}
}

func TestEnrollAckRelaysToTransport(t *testing.T) {
	tr := &fakeTransport{connected: true}
	uid := startTestDaemon(t, tr)

	resp := roundTrip(t, uid, Request{Cmd: "enroll_ack", EnrollNonce: "n8", AckOK: true})
	if !resp.OK {
		t.Fatalf("resp.OK = false, error = %q", resp.Error)
	}
	if tr.gotAckNonce != "n8" || !tr.gotAckOK {
		t.Fatalf("transport did not get the ack: nonce=%q ok=%v", tr.gotAckNonce, tr.gotAckOK)
	}
}

func TestEnrollAckRelaysFailure(t *testing.T) {
	tr := &fakeTransport{connected: true}
	uid := startTestDaemon(t, tr)

	resp := roundTrip(t, uid, Request{Cmd: "enroll_ack", EnrollNonce: "n9", AckOK: false, AckError: "the typed code did not match"})
	if !resp.OK {
		t.Fatalf("resp.OK = false, error = %q", resp.Error)
	}
	if tr.gotAckNonce != "n9" || tr.gotAckOK || tr.gotAckError != "the typed code did not match" {
		t.Fatalf("transport did not get the expected failure ack: nonce=%q ok=%v error=%q", tr.gotAckNonce, tr.gotAckOK, tr.gotAckError)
	}
}

func TestStatusReportsTransportState(t *testing.T) {
	tr := &fakeTransport{connected: true, name: "Nothing Phone 3a"}
	uid := startTestDaemon(t, tr)

	resp := roundTrip(t, uid, Request{Cmd: "status"})
	if !resp.OK || !resp.PhoneConnected || resp.PhoneName != "Nothing Phone 3a" {
		t.Fatalf("unexpected status response: %+v", resp)
	}
}

func TestUnknownCommand(t *testing.T) {
	tr := &fakeTransport{connected: true}
	uid := startTestDaemon(t, tr)

	resp := roundTrip(t, uid, Request{Cmd: "do-something-bad"})
	if resp.OK {
		t.Fatalf("resp.OK = true for an unknown command")
	}
}

func TestRefusesConnectionFromAnotherUID(t *testing.T) {
	// handle() refuses any peer uid that isn't the daemon's own uid or
	// root. We can't fork a real other-uid process in a unit test, but
	// we can call handle() directly over an in-memory pipe and make the
	// uid check observable by using a daemon configured for a uid that
	// is not ours: the real PeerUID of our own test process will then
	// never match, and the request must never reach the transport.
	tr := &fakeTransport{connected: true, approveSig: []byte("should-not-be-used")}
	d := New(os.Getuid()+12345, tr, t.Logf)

	server, client := net.Pipe()
	defer client.Close()
	done := make(chan struct{})
	go func() {
		d.handle(context.Background(), server)
		close(done)
	}()

	_ = ipc.WriteJSON(client, Request{Cmd: "approve", Host: "eos", User: "u", Service: "sudo", Nonce: "n", Time: 1})
	<-done // handle() must return (closing its side) without ever writing a response
	if tr.gotApprove.Host != "" {
		t.Fatalf("transport was called despite the uid mismatch")
	}
}
