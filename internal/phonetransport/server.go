// Package phonetransport is the real daemon.Transport: a TLS server the
// phone dials into, long-lived so an approval can reach it at any time.
// It implements internal/daemon.Transport and carries exactly the
// fields a request needs to rebuild the signed message - nothing it
// relays is trusted by itself, the same rule the local IPC layer
// follows.
package phonetransport

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"approven/internal/daemon"
)

// wireMsg is the shape every line on the wire takes, in both
// directions. Only the fields relevant to Type are set.
type wireMsg struct {
	Type string `json:"type"`
	ID   string `json:"id,omitempty"`

	// hello (phone -> daemon, once, right after the TLS handshake)
	DeviceID   string `json:"device_id,omitempty"`
	DeviceName string `json:"device_name,omitempty"`

	// approve_request (daemon -> phone) / enroll_request (daemon -> phone)
	Host    string `json:"host,omitempty"`
	User    string `json:"user,omitempty"`
	Service string `json:"service,omitempty"`
	Command string `json:"command,omitempty"`
	TTY     string `json:"tty,omitempty"`
	RHost   string `json:"rhost,omitempty"`
	Time    int64  `json:"time,omitempty"`
	Nonce   string `json:"nonce,omitempty"`

	// approve_response (phone -> daemon)
	Approved  bool   `json:"approved,omitempty"`
	Signature []byte `json:"signature,omitempty"`

	// enroll_response (phone -> daemon)
	PublicKeyDER []byte `json:"public_key_der,omitempty"`

	// enroll_result (daemon -> phone): Approved doubles as "succeeded".
	Error string `json:"error,omitempty"`
}

// DefaultPort is the TCP port the daemon listens on for phones, and the
// one the enrollment QR code tells the phone to dial.
const DefaultPort = 17165

// maxLine caps one wire message; the biggest legitimate one (an
// enroll_response with a DER key and a signature) is well under 2 KiB.
const maxLine = 64 * 1024

// helloTimeout bounds the TLS handshake plus the hello line, so a peer
// that connects and then says nothing cannot hold a goroutine forever.
var helloTimeout = 10 * time.Second

// Server is a daemon.Transport backed by a TLS listener. The zero value
// is not usable; construct with NewServer.
//
// Every phone must present a TLS client certificate. pin returns the
// SHA-256 of the one certificate enrollment recorded (from the
// root-owned key file), or "" when nothing is enrolled. A connection
// presenting that certificate is "paired": only it ever receives a
// sudo request, and an unpaired connection can never push it out of
// the slot. An unpaired connection is still accepted when no paired
// one is around, because that is exactly how a new phone enrolls - the
// enrollment itself then proves which certificate is the real one.
type Server struct {
	cert       tls.Certificate
	serverCert string
	pin        func() string
	logf       func(string, ...any)

	// OnTest runs a test sudo when the paired phone asks for one (its
	// "test" button); nil disables the feature. The command is fixed by
	// whoever sets this - the phone can only ask, never choose what.
	OnTest  func() error
	testing atomic.Bool

	mu         sync.Mutex
	conn       net.Conn
	clientCert string
	writeMu    sync.Mutex
	deviceName string
	deviceID   string
	pendingID  string
	pendingCh  chan wireMsg
}

// NewServer returns a Server that presents cert to connecting phones
// and trusts the client certificate pin returns.
func NewServer(cert tls.Certificate, pin func() string, logf func(string, ...any)) *Server {
	fp, _ := Fingerprint(cert)
	return &Server{cert: cert, serverCert: fp, pin: pin, logf: logf}
}

// Serve accepts phone connections on l until ctx is done or l closes.
// l should already be a plain TCP listener; Serve wraps it in TLS
// itself so callers never construct a tls.Config of their own.
func (s *Server) Serve(ctx context.Context, l net.Listener) error {
	tl := tls.NewListener(l, &tls.Config{
		Certificates: []tls.Certificate{s.cert},
		MinVersion:   tls.VersionTLS13,
		// Self-signed on the phone, so there is no chain to verify:
		// the certificate's hash against the pin is the whole check.
		ClientAuth: tls.RequireAnyClientCert,
	})
	go func() {
		<-ctx.Done()
		tl.Close()
	}()
	for {
		conn, err := tl.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go s.handleConn(conn)
	}
}

func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()
	r := bufio.NewReaderSize(conn, maxLine)

	_ = conn.SetDeadline(time.Now().Add(helloTimeout))
	var hello wireMsg
	if err := readLine(r, &hello); err != nil || hello.Type != "hello" {
		s.logf("phonetransport: rejected a connection with no hello: %v", err)
		return
	}
	_ = conn.SetDeadline(time.Time{})

	clientCert := peerCertHash(conn)
	if clientCert == "" {
		return // RequireAnyClientCert makes this unreachable; never trust its absence
	}
	paired := s.isPinned(clientCert)

	s.mu.Lock()
	if s.conn != nil && s.isPinned(s.clientCert) && !paired {
		s.mu.Unlock()
		s.logf("phonetransport: refused an unpaired phone while the paired one is connected")
		return
	}
	if s.conn != nil {
		s.conn.Close() // one active phone connection at a time
	}
	s.conn = conn
	s.clientCert = clientCert
	s.deviceID = hello.DeviceID
	s.deviceName = hello.DeviceName
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		if s.conn == conn {
			s.conn = nil
			s.clientCert = ""
			s.deviceID = ""
			s.deviceName = ""
		}
		s.mu.Unlock()
	}()

	for {
		var msg wireMsg
		if err := readLine(r, &msg); err != nil {
			return
		}
		if msg.Type == "test_sudo" {
			s.startTest(conn, s.isPinned(clientCert))
			continue
		}
		s.mu.Lock()
		if msg.ID != "" && msg.ID == s.pendingID && s.pendingCh != nil {
			ch := s.pendingCh
			s.pendingID = ""
			s.pendingCh = nil
			s.mu.Unlock()
			ch <- msg
			continue
		}
		s.mu.Unlock()
	}
}

// isPinned reports whether a client certificate is the enrolled one.
// It asks pin() every time rather than once per connection: a phone
// that just enrolled over this very connection is the pinned one from
// then on, without having to reconnect first.
func (s *Server) isPinned(clientCert string) bool {
	pin := s.pin()
	return pin != "" && clientCert == pin
}

// startTest runs OnTest in the background and reports its outcome as a
// test_result. Only the paired phone may ask, one test at a time - so
// a stranger on the network cannot make this computer pop sudo prompts.
func (s *Server) startTest(conn net.Conn, paired bool) {
	if !paired || s.OnTest == nil || !s.testing.CompareAndSwap(false, true) {
		_ = s.writeTo(conn, wireMsg{Type: "test_result", Error: "test not available right now"})
		return
	}
	go func() {
		defer s.testing.Store(false)
		res := wireMsg{Type: "test_result", Approved: true}
		if err := s.OnTest(); err != nil {
			res = wireMsg{Type: "test_result", Error: err.Error()}
		}
		_ = s.writeTo(conn, res)
	}()
}

// readLine reads one message of at most maxLine bytes: a longer one
// fails with bufio.ErrBufferFull instead of growing memory without end.
func readLine(r *bufio.Reader, v *wireMsg) error {
	line, err := r.ReadSlice('\n')
	if err != nil {
		return err
	}
	return json.Unmarshal(line, v)
}

// peerCertHash is the SHA-256 hex of the client's leaf certificate, or
// "" when there is none. Reading it completes the handshake if the
// first read has not already.
func peerCertHash(conn net.Conn) string {
	tc, ok := conn.(*tls.Conn)
	if !ok || tc.Handshake() != nil {
		return ""
	}
	certs := tc.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return ""
	}
	sum := sha256.Sum256(certs[0].Raw)
	return hex.EncodeToString(sum[:])
}

func (s *Server) writeMsg(msg wireMsg) error {
	s.mu.Lock()
	conn := s.conn
	s.mu.Unlock()
	if conn == nil {
		return daemon.ErrNoPhone
	}
	return s.writeTo(conn, msg)
}

func (s *Server) writeTo(conn net.Conn, msg wireMsg) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	_, err = conn.Write(data)
	return err
}

// Connected reports whether a phone is currently connected.
func (s *Server) Connected() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conn != nil
}

// ServerCert implements daemon.Transport.
func (s *Server) ServerCert() string { return s.serverCert }

// PhoneName is the name of the connected phone, from its hello, or ""
// when none is connected.
func (s *Server) PhoneName() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.deviceName
}

// beginPending registers id as the one in-flight request and returns
// the channel its response will arrive on, or an error when a request
// is already in flight, so a slow phone never lets 2 answers cross.
// needPaired refuses a connection whose certificate is not the pinned
// one: approvals only ever go to the enrolled phone.
func (s *Server) beginPending(id string, needPaired bool) (chan wireMsg, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn == nil {
		return nil, daemon.ErrNoPhone
	}
	if needPaired && !s.isPinned(s.clientCert) {
		return nil, daemon.ErrNotPaired
	}
	if s.pendingID != "" {
		return nil, fmt.Errorf("phonetransport: another request is already waiting for the phone")
	}
	ch := make(chan wireMsg, 1)
	s.pendingID = id
	s.pendingCh = ch
	return ch, nil
}

func (s *Server) endPending(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pendingID == id {
		s.pendingID = ""
		s.pendingCh = nil
	}
}

// SendApprove implements daemon.Transport.
func (s *Server) SendApprove(ctx context.Context, req daemon.ApproveFields) ([]byte, error) {
	ch, err := s.beginPending(req.Nonce, true)
	if err != nil {
		return nil, err
	}
	defer s.endPending(req.Nonce)

	if err := s.writeMsg(wireMsg{
		Type: "approve_request", ID: req.Nonce,
		Host: req.Host, User: req.User, Service: req.Service, Command: req.Command,
		TTY: req.TTY, RHost: req.RHost, Time: req.Time, Nonce: req.Nonce,
	}); err != nil {
		return nil, err
	}

	select {
	case msg := <-ch:
		if !msg.Approved {
			return nil, daemon.ErrDenied
		}
		return msg.Signature, nil
	case <-ctx.Done():
		_ = s.writeMsg(wireMsg{Type: "cancel", ID: req.Nonce})
		return nil, daemon.ErrTimedOut
	}
}

// SendEnroll implements daemon.Transport.
func (s *Server) SendEnroll(ctx context.Context, req daemon.EnrollFields) (daemon.EnrollResult, error) {
	ch, err := s.beginPending(req.Nonce, false)
	if err != nil {
		return daemon.EnrollResult{}, err
	}
	defer s.endPending(req.Nonce)

	if err := s.writeMsg(wireMsg{
		Type: "enroll_request", ID: req.Nonce,
		Host: req.Host, User: req.User, Time: req.Time, Nonce: req.Nonce,
	}); err != nil {
		return daemon.EnrollResult{}, err
	}

	select {
	case msg := <-ch:
		s.mu.Lock()
		devID, devName, clientCert := s.deviceID, s.deviceName, s.clientCert
		s.mu.Unlock()
		return daemon.EnrollResult{
			PublicKeyDER: msg.PublicKeyDER,
			DeviceID:     devID,
			DeviceName:   devName,
			Signature:    msg.Signature,
			ClientCert:   clientCert,
			ServerCert:   s.serverCert,
		}, nil
	case <-ctx.Done():
		_ = s.writeMsg(wireMsg{Type: "cancel", ID: req.Nonce})
		return daemon.EnrollResult{}, daemon.ErrTimedOut
	}
}

// SendEnrollResult implements daemon.Transport. It is fire-and-forget:
// the phone has nothing to answer, and a connection that happens to be
// gone by the time this is called just means the phone will never
// learn the outcome, the same as if it had closed the app right after
// sending enroll_response.
func (s *Server) SendEnrollResult(nonce string, ok bool, errMsg string) error {
	return s.writeMsg(wireMsg{Type: "enroll_result", ID: nonce, Approved: ok, Error: errMsg})
}
