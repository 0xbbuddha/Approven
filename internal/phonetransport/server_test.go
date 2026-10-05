package phonetransport

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"testing"
	"time"

	"approven/internal/daemon"
)

// fakePhone is a minimal TLS client standing in for the Android (or
// iOS/Mac) app: it says hello, then answers whatever requests the test
// tells it to.
type fakePhone struct {
	conn net.Conn
	r    *bufio.Reader
}

func dialFakePhone(t *testing.T, addr, deviceID, deviceName string) *fakePhone {
	t.Helper()
	conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // test-only TOFU client
	if err != nil {
		t.Fatalf("tls.Dial: %v", err)
	}
	fp := &fakePhone{conn: conn, r: bufio.NewReader(conn)}
	fp.send(t, wireMsg{Type: "hello", DeviceID: deviceID, DeviceName: deviceName})
	return fp
}

func (fp *fakePhone) send(t *testing.T, msg wireMsg) {
	t.Helper()
	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	data = append(data, '\n')
	if _, err := fp.conn.Write(data); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func (fp *fakePhone) recv(t *testing.T) wireMsg {
	t.Helper()
	line, err := fp.r.ReadBytes('\n')
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var msg wireMsg
	if err := json.Unmarshal(line, &msg); err != nil {
		t.Fatalf("unmarshal %q: %v", line, err)
	}
	return msg
}

func startTestServer(t *testing.T) (*Server, string) {
	t.Helper()
	cert, err := LoadOrCreateCert(t.TempDir())
	if err != nil {
		t.Fatalf("LoadOrCreateCert: %v", err)
	}
	s := NewServer(cert, t.Logf)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go s.Serve(ctx, l)
	t.Cleanup(func() { l.Close() })
	return s, l.Addr().String()
}

func waitUntilConnected(t *testing.T, s *Server) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if s.Connected() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("server never saw the phone connect")
}

func TestHelloMarksConnected(t *testing.T) {
	s, addr := startTestServer(t)
	if s.Connected() {
		t.Fatalf("Connected() = true before any phone dialed in")
	}
	fp := dialFakePhone(t, addr, "dev1", "Test Phone")
	defer fp.conn.Close()
	waitUntilConnected(t, s)
	if s.PhoneName() != "Test Phone" {
		t.Fatalf("PhoneName() = %q, want Test Phone", s.PhoneName())
	}
}

func TestDisconnectClearsConnected(t *testing.T) {
	s, addr := startTestServer(t)
	fp := dialFakePhone(t, addr, "dev1", "Test Phone")
	waitUntilConnected(t, s)
	fp.conn.Close()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && s.Connected() {
		time.Sleep(5 * time.Millisecond)
	}
	if s.Connected() {
		t.Fatalf("Connected() stayed true after the phone disconnected")
	}
}

func TestSendApproveRoundTripApproved(t *testing.T) {
	s, addr := startTestServer(t)
	fp := dialFakePhone(t, addr, "dev1", "Test Phone")
	defer fp.conn.Close()
	waitUntilConnected(t, s)

	go func() {
		req := fp.recv(t)
		if req.Type != "approve_request" || req.Host != "eos" {
			t.Errorf("unexpected request: %+v", req)
		}
		fp.send(t, wireMsg{Type: "approve_response", ID: req.ID, Approved: true, Signature: []byte("sig")})
	}()

	sig, err := s.SendApprove(context.Background(), daemon.ApproveFields{
		Host: "eos", User: "u", Service: "sudo", Nonce: "n1", Time: 1,
	})
	if err != nil {
		t.Fatalf("SendApprove: %v", err)
	}
	if string(sig) != "sig" {
		t.Fatalf("signature = %q, want sig", sig)
	}
}

func TestSendApproveRoundTripDenied(t *testing.T) {
	s, addr := startTestServer(t)
	fp := dialFakePhone(t, addr, "dev1", "Test Phone")
	defer fp.conn.Close()
	waitUntilConnected(t, s)

	go func() {
		req := fp.recv(t)
		fp.send(t, wireMsg{Type: "approve_response", ID: req.ID, Approved: false})
	}()

	_, err := s.SendApprove(context.Background(), daemon.ApproveFields{Host: "eos", User: "u", Service: "sudo", Nonce: "n2", Time: 1})
	if err != daemon.ErrDenied {
		t.Fatalf("err = %v, want ErrDenied", err)
	}
}

func TestSendApproveTimesOut(t *testing.T) {
	s, addr := startTestServer(t)
	fp := dialFakePhone(t, addr, "dev1", "Test Phone")
	defer fp.conn.Close()
	waitUntilConnected(t, s)

	// The fake phone receives the request but never answers.
	go func() { fp.recv(t) }()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err := s.SendApprove(ctx, daemon.ApproveFields{Host: "eos", User: "u", Service: "sudo", Nonce: "n3", Time: 1})
	if err != daemon.ErrTimedOut {
		t.Fatalf("err = %v, want ErrTimedOut", err)
	}
}

func TestSendApproveNoPhoneConnected(t *testing.T) {
	s, _ := startTestServer(t)
	_, err := s.SendApprove(context.Background(), daemon.ApproveFields{Host: "eos", User: "u", Service: "sudo", Nonce: "n4", Time: 1})
	if err != daemon.ErrNoPhone {
		t.Fatalf("err = %v, want ErrNoPhone", err)
	}
}

func TestSendApproveRejectsConcurrentRequests(t *testing.T) {
	s, addr := startTestServer(t)
	fp := dialFakePhone(t, addr, "dev1", "Test Phone")
	defer fp.conn.Close()
	waitUntilConnected(t, s)

	started := make(chan struct{})
	release := make(chan struct{})
	go func() {
		req := fp.recv(t)
		close(started)
		<-release
		fp.send(t, wireMsg{Type: "approve_response", ID: req.ID, Approved: true, Signature: []byte("sig")})
	}()

	firstDone := make(chan error, 1)
	go func() {
		_, err := s.SendApprove(context.Background(), daemon.ApproveFields{Host: "eos", User: "u", Service: "sudo", Nonce: "n5", Time: 1})
		firstDone <- err
	}()
	<-started

	_, err := s.SendApprove(context.Background(), daemon.ApproveFields{Host: "eos", User: "u", Service: "sudo", Nonce: "n6", Time: 1})
	if err == nil {
		t.Fatalf("expected the second concurrent SendApprove to be rejected")
	}
	close(release)
	if err := <-firstDone; err != nil {
		t.Fatalf("first SendApprove: %v", err)
	}
}

func TestSendEnrollRoundTrip(t *testing.T) {
	s, addr := startTestServer(t)
	fp := dialFakePhone(t, addr, "dev1", "Test Phone")
	defer fp.conn.Close()
	waitUntilConnected(t, s)

	go func() {
		req := fp.recv(t)
		if req.Type != "enroll_request" {
			t.Errorf("unexpected request type: %q", req.Type)
		}
		fp.send(t, wireMsg{Type: "enroll_response", ID: req.ID, PublicKeyDER: []byte("der"), Signature: []byte("enroll-sig")})
	}()

	res, err := s.SendEnroll(context.Background(), daemon.EnrollFields{Host: "eos", User: "u", Nonce: "n7", Time: 1})
	if err != nil {
		t.Fatalf("SendEnroll: %v", err)
	}
	if string(res.PublicKeyDER) != "der" || string(res.Signature) != "enroll-sig" {
		t.Fatalf("unexpected result: %+v", res)
	}
	if res.DeviceID != "dev1" || res.DeviceName != "Test Phone" {
		t.Fatalf("device info not carried from hello: %+v", res)
	}
}

func TestSendEnrollResultReachesThePhone(t *testing.T) {
	s, addr := startTestServer(t)
	fp := dialFakePhone(t, addr, "dev1", "Test Phone")
	defer fp.conn.Close()
	waitUntilConnected(t, s)

	if err := s.SendEnrollResult("n8", true, ""); err != nil {
		t.Fatalf("SendEnrollResult: %v", err)
	}
	msg := fp.recv(t)
	if msg.Type != "enroll_result" || msg.ID != "n8" || !msg.Approved || msg.Error != "" {
		t.Fatalf("unexpected message: %+v", msg)
	}
}

func TestSendEnrollResultCarriesFailure(t *testing.T) {
	s, addr := startTestServer(t)
	fp := dialFakePhone(t, addr, "dev1", "Test Phone")
	defer fp.conn.Close()
	waitUntilConnected(t, s)

	if err := s.SendEnrollResult("n9", false, "the typed code did not match"); err != nil {
		t.Fatalf("SendEnrollResult: %v", err)
	}
	msg := fp.recv(t)
	if msg.Type != "enroll_result" || msg.ID != "n9" || msg.Approved || msg.Error != "the typed code did not match" {
		t.Fatalf("unexpected message: %+v", msg)
	}
}
