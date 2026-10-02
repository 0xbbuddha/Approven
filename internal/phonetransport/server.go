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
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"sync"

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
	TTY     string `json:"tty,omitempty"`
	RHost   string `json:"rhost,omitempty"`
	Time    int64  `json:"time,omitempty"`
	Nonce   string `json:"nonce,omitempty"`

	// approve_response (phone -> daemon)
	Approved  bool   `json:"approved,omitempty"`
	Signature []byte `json:"signature,omitempty"`

	// enroll_response (phone -> daemon)
	PublicKeyDER []byte `json:"public_key_der,omitempty"`
}

// Server is a daemon.Transport backed by a TLS listener. The zero value
// is not usable; construct with NewServer.
type Server struct {
	cert tls.Certificate
	logf func(string, ...any)

	mu         sync.Mutex
	conn       net.Conn
	writeMu    sync.Mutex
	deviceName string
	deviceID   string
	pendingID  string
	pendingCh  chan wireMsg
}

// NewServer returns a Server that presents cert to connecting phones.
func NewServer(cert tls.Certificate, logf func(string, ...any)) *Server {
	return &Server{cert: cert, logf: logf}
}

// Serve accepts phone connections on l until ctx is done or l closes.
// l should already be a plain TCP listener; Serve wraps it in TLS
// itself so callers never construct a tls.Config of their own.
func (s *Server) Serve(ctx context.Context, l net.Listener) error {
	tl := tls.NewListener(l, &tls.Config{
		Certificates: []tls.Certificate{s.cert},
		MinVersion:   tls.VersionTLS13,
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
	r := bufio.NewReader(conn)

	var hello wireMsg
	if err := readLine(r, &hello); err != nil || hello.Type != "hello" {
		s.logf("phonetransport: rejected a connection with no hello: %v", err)
		return
	}

	s.mu.Lock()
	if s.conn != nil {
		s.conn.Close() // one active phone connection at a time
	}
	s.conn = conn
	s.deviceID = hello.DeviceID
	s.deviceName = hello.DeviceName
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		if s.conn == conn {
			s.conn = nil
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

func readLine(r *bufio.Reader, v *wireMsg) error {
	line, err := r.ReadBytes('\n')
	if err != nil {
		return err
	}
	return json.Unmarshal(line, v)
}

func (s *Server) writeMsg(msg wireMsg) error {
	s.mu.Lock()
	conn := s.conn
	s.mu.Unlock()
	if conn == nil {
		return daemon.ErrNoPhone
	}
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
func (s *Server) beginPending(id string) (chan wireMsg, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn == nil {
		return nil, daemon.ErrNoPhone
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
	ch, err := s.beginPending(req.Nonce)
	if err != nil {
		return nil, err
	}
	defer s.endPending(req.Nonce)

	if err := s.writeMsg(wireMsg{
		Type: "approve_request", ID: req.Nonce,
		Host: req.Host, User: req.User, Service: req.Service,
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
	ch, err := s.beginPending(req.Nonce)
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
		devID, devName := s.deviceID, s.deviceName
		s.mu.Unlock()
		return daemon.EnrollResult{
			PublicKeyDER: msg.PublicKeyDER,
			DeviceID:     devID,
			DeviceName:   devName,
			Signature:    msg.Signature,
		}, nil
	case <-ctx.Done():
		_ = s.writeMsg(wireMsg{Type: "cancel", ID: req.Nonce})
		return daemon.EnrollResult{}, daemon.ErrTimedOut
	}
}
