// Package ipc is the local Unix-socket transport between the daemon
// (approved, runs as the user) and its two local callers: the PAM helper
// (runs as root, for approvals) and the CLI (runs as root for enroll,
// as the user for status). It never touches the network - the phone is
// reached only through the daemon.
package ipc

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"
)

// RuntimeDir returns the directory that holds the socket for uid, under
// XDG_RUNTIME_DIR when the caller is that uid, or the standard
// /run/user/<uid> otherwise - a root caller (the helper, the enroll
// command) has no XDG_RUNTIME_DIR of its own for the user's session.
func RuntimeDir(uid int) string {
	if uid == os.Getuid() {
		if d := os.Getenv("XDG_RUNTIME_DIR"); d != "" {
			return filepath.Join(d, "approven")
		}
	}
	return filepath.Join("/run/user", fmt.Sprint(uid), "approven")
}

// SocketPath returns the socket path for uid.
func SocketPath(uid int) string {
	return filepath.Join(RuntimeDir(uid), "approved.sock")
}

// Listen creates the runtime directory (0700, owned by the current
// user) and listens on its socket. The daemon runs this as the user it
// serves, so the directory and the socket are naturally owned by that
// user - a client checks this on connect, not the other way around.
func Listen(uid int) (net.Listener, error) {
	dir := RuntimeDir(uid)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("ipc: mkdir %s: %w", dir, err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, fmt.Errorf("ipc: chmod %s: %w", dir, err)
	}
	path := SocketPath(uid)
	_ = os.Remove(path) // a stale socket from a crashed daemon
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("ipc: listen %s: %w", path, err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		l.Close()
		return nil, fmt.Errorf("ipc: chmod %s: %w", path, err)
	}
	return l, nil
}

// Dial connects to the daemon socket of uid and verifies, with
// SO_PEERCRED, that the process on the other end actually runs as uid -
// not just that the path once belonged to it. wantUID is usually uid
// itself; the helper and the enroll command, which run as root, dial
// the target user's socket and still expect the daemon to be that
// user, never root.
func Dial(uid int) (net.Conn, error) {
	dir := RuntimeDir(uid)
	if info, err := os.Lstat(dir); err != nil {
		return nil, fmt.Errorf("ipc: stat %s: %w", dir, err)
	} else if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("ipc: %s is a symlink", dir)
	} else if sys, ok := info.Sys().(*syscall.Stat_t); !ok || int(sys.Uid) != uid {
		return nil, fmt.Errorf("ipc: %s is not owned by uid %d", dir, uid)
	}

	path := SocketPath(uid)
	conn, err := net.Dial("unix", path)
	if err != nil {
		return nil, fmt.Errorf("ipc: dial %s: %w", path, err)
	}
	peerUID, err := peerUID(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if peerUID != uid {
		conn.Close()
		return nil, fmt.Errorf("ipc: daemon at %s runs as uid %d, not %d", path, peerUID, uid)
	}
	return conn, nil
}

// PeerUID is AcceptAndVerify's counterpart for the daemon side: the uid
// of whatever process is on the other end of conn, from SO_PEERCRED.
func PeerUID(conn net.Conn) (int, error) { return peerUID(conn) }

func peerUID(conn net.Conn) (int, error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, fmt.Errorf("ipc: not a unix socket connection")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, fmt.Errorf("ipc: SyscallConn: %w", err)
	}
	var cred *syscall.Ucred
	var credErr error
	err = raw.Control(func(fd uintptr) {
		cred, credErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	})
	if err != nil {
		return 0, fmt.Errorf("ipc: Control: %w", err)
	}
	if credErr != nil {
		return 0, fmt.Errorf("ipc: SO_PEERCRED: %w", credErr)
	}
	return int(cred.Uid), nil
}

// MaxMessage is the largest single JSON line this transport accepts in
// either direction - generous for the small, fixed-shape messages this
// protocol actually sends, small enough that neither side ever buffers
// an unbounded line from the other.
const MaxMessage = 64 * 1024

// WriteJSON writes v as one JSON line.
func WriteJSON(conn net.Conn, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("ipc: marshal: %w", err)
	}
	if len(data) > MaxMessage {
		return fmt.Errorf("ipc: message too large")
	}
	data = append(data, '\n')
	_, err = conn.Write(data)
	return err
}

// LineReader wraps conn to read bounded JSON lines from it with
// ReadJSON. Each side keeps one for the lifetime of the connection,
// since bufio.Reader may buffer past a single message.
type LineReader struct{ r *bufio.Reader }

// NewLineReader wraps conn for ReadJSON.
func NewLineReader(conn net.Conn) *LineReader {
	return &LineReader{r: bufio.NewReaderSize(conn, MaxMessage)}
}

// ReadJSON reads one newline-terminated JSON line and decodes it into v.
// A line longer than MaxMessage is an error, not a silent truncation.
func (lr *LineReader) ReadJSON(v any) error {
	line, err := lr.r.ReadString('\n')
	if err != nil {
		return err
	}
	if len(line) > MaxMessage {
		return fmt.Errorf("ipc: message too large")
	}
	return json.Unmarshal([]byte(line), v)
}
