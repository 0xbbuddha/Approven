// Package daemon implements approved, the user-level process that
// relays approval and enrollment requests between the local helper/CLI
// and the paired phone. It never decides whether a request is approved -
// that decision is a signature the helper or the CLI verifies itself,
// against a key the daemon never holds an opinion on.
package daemon

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"

	"nothing-approve/internal/ipc"
)

// Request is one line a local client (the PAM helper or the CLI) sends
// to the daemon.
type Request struct {
	Cmd string `json:"cmd"` // "approve", "enroll", "status"

	// approve: every field the phone needs to rebuild and show the exact
	// message it will sign. The daemon fills none of these in and
	// changes none of them - they come from the caller, who already
	// knows it will verify the response against the same values.
	Host        string `json:"host,omitempty"`
	User        string `json:"user,omitempty"`
	Service     string `json:"service,omitempty"`
	TTY         string `json:"tty,omitempty"`
	RHost       string `json:"rhost,omitempty"`
	Time        int64  `json:"time,omitempty"`
	Nonce       string `json:"nonce,omitempty"`
	WaitSeconds int    `json:"wait_seconds,omitempty"`

	// enroll: same idea, for the enrollment message.
	EnrollTime  int64  `json:"enroll_time,omitempty"`
	EnrollNonce string `json:"enroll_nonce,omitempty"`
}

// Response is one line the daemon sends back.
type Response struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`

	// approve
	Signature []byte `json:"signature,omitempty"`

	// enroll
	PublicKeyDER []byte `json:"public_key_der,omitempty"`
	DeviceID     string `json:"device_id,omitempty"`
	DeviceName   string `json:"device_name,omitempty"`
	EnrollSig    []byte `json:"enroll_signature,omitempty"`

	// status
	PhoneConnected bool   `json:"phone_connected,omitempty"`
	PhoneName      string `json:"phone_name,omitempty"`
}

// ApproveFields is what the daemon forwards to the phone for one
// approval - the same shape as the approve fields of Request, kept as
// its own type so Transport does not depend on the wire Request shape.
type ApproveFields struct {
	Host, User, Service, TTY, RHost, Nonce string
	Time                                   int64
}

// EnrollFields is the enrollment counterpart.
type EnrollFields struct {
	Host, User, Nonce string
	Time              int64
}

// EnrollResult is what a successful enrollment round trip with the phone
// produces: the new public key and the phone's signature over the
// EnrollRequest that EnrollFields describes, plus the signature's own
// nonce/time are NOT re-sent - the caller already has them, exactly
// like ApproveFields above.
type EnrollResult struct {
	PublicKeyDER []byte
	DeviceID     string
	DeviceName   string
	Signature    []byte
}

// Transport is how the daemon reaches a paired phone. A real
// implementation holds the TLS connection; tests use a fake one so the
// local protocol and the verification logic in the helper and the CLI
// can be exercised without a network or hardware.
type Transport interface {
	// Connected reports whether a phone is currently reachable.
	Connected() bool
	// PhoneName is the name of the connected phone, or "" when none is.
	PhoneName() string
	// SendApprove forwards req to the phone and blocks for its answer,
	// a denial, ctx's deadline, or a disconnect - whichever comes
	// first. A denial and a timeout are both reported as errApprove*
	// sentinel errors so the daemon can tell them apart in its own log,
	// without the local client having to parse an error string.
	SendApprove(ctx context.Context, req ApproveFields) (signature []byte, err error)
	// SendEnroll forwards req to the phone and blocks for the new
	// public key and its signature, or an error.
	SendEnroll(ctx context.Context, req EnrollFields) (EnrollResult, error)
}

var (
	// ErrDenied is returned by a Transport when the phone's user tapped Deny.
	ErrDenied = fmt.Errorf("denied on the phone")
	// ErrNoPhone is returned when no phone is connected.
	ErrNoPhone = fmt.Errorf("no phone connected")
	// ErrTimedOut is returned when the phone did not answer in time.
	ErrTimedOut = fmt.Errorf("timed out waiting for the phone")
)

// Daemon serves local clients over a Listener and relays their requests
// through a Transport.
type Daemon struct {
	Transport Transport
	// UID is the user this daemon serves. A connection from any other
	// uid but root is refused outright: the socket already lives under
	// /run/user/<uid> at mode 0700, so this is defense in depth, not
	// the only thing standing between another user and this socket.
	UID  int
	Logf func(format string, args ...any)
}

// New returns a Daemon running as uid. logf defaults to log.Printf when nil.
func New(uid int, t Transport, logf func(string, ...any)) *Daemon {
	if logf == nil {
		logf = log.Printf
	}
	return &Daemon{Transport: t, UID: uid, Logf: logf}
}

// Serve accepts connections from l until it is closed or ctx is done.
func (d *Daemon) Serve(ctx context.Context, l net.Listener) error {
	go func() {
		<-ctx.Done()
		l.Close()
	}()
	for {
		conn, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go d.handle(ctx, conn)
	}
}

func (d *Daemon) handle(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	peerUID, err := ipc.PeerUID(conn)
	if err != nil {
		d.Logf("approved: could not read the peer of a connection: %v", err)
		return
	}
	if peerUID != d.UID && peerUID != 0 {
		d.Logf("approved: refused a connection from uid %d", peerUID)
		return
	}

	var req Request
	if err := ipc.NewLineReader(conn).ReadJSON(&req); err != nil {
		d.Logf("approved: bad request: %v", err)
		return
	}

	switch req.Cmd {
	case "approve":
		d.handleApprove(ctx, conn, req)
	case "enroll":
		d.handleEnroll(ctx, conn, req)
	case "status":
		d.handleStatus(conn)
	default:
		_ = ipc.WriteJSON(conn, Response{OK: false, Error: "unknown command"})
	}
}

func (d *Daemon) handleApprove(ctx context.Context, conn net.Conn, req Request) {
	if !d.Transport.Connected() {
		_ = ipc.WriteJSON(conn, Response{OK: false, Error: ErrNoPhone.Error()})
		return
	}
	wait := time.Duration(req.WaitSeconds) * time.Second
	if wait <= 0 {
		wait = 20 * time.Second
	}
	cctx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()

	sig, err := d.Transport.SendApprove(cctx, ApproveFields{
		Host: req.Host, User: req.User, Service: req.Service,
		TTY: req.TTY, RHost: req.RHost, Time: req.Time, Nonce: req.Nonce,
	})
	if err != nil {
		d.Logf("approved: approve for %s@%s: %v", req.User, req.Host, err)
		_ = ipc.WriteJSON(conn, Response{OK: false, Error: err.Error()})
		return
	}
	_ = ipc.WriteJSON(conn, Response{OK: true, Signature: sig})
}

func (d *Daemon) handleEnroll(ctx context.Context, conn net.Conn, req Request) {
	if !d.Transport.Connected() {
		_ = ipc.WriteJSON(conn, Response{OK: false, Error: ErrNoPhone.Error()})
		return
	}
	cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	res, err := d.Transport.SendEnroll(cctx, EnrollFields{
		Host: req.Host, User: req.User, Time: req.EnrollTime, Nonce: req.EnrollNonce,
	})
	if err != nil {
		d.Logf("approved: enroll for %s@%s: %v", req.User, req.Host, err)
		_ = ipc.WriteJSON(conn, Response{OK: false, Error: err.Error()})
		return
	}
	_ = ipc.WriteJSON(conn, Response{
		OK: true, PublicKeyDER: res.PublicKeyDER,
		DeviceID: res.DeviceID, DeviceName: res.DeviceName,
		EnrollSig: res.Signature,
	})
}

func (d *Daemon) handleStatus(conn net.Conn) {
	_ = ipc.WriteJSON(conn, Response{
		OK: true, PhoneConnected: d.Transport.Connected(), PhoneName: d.Transport.PhoneName(),
	})
}
