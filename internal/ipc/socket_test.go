package ipc

import (
	"os"
	"testing"
)

// withRuntimeDir points XDG_RUNTIME_DIR at a fresh temp dir for the
// duration of the test, so Listen/Dial do not touch the real
// /run/user/<uid> of whatever machine runs the test.
func withRuntimeDir(t *testing.T) {
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
}

func TestListenDialAndPeerCred(t *testing.T) {
	withRuntimeDir(t)
	uid := os.Getuid()

	l, err := Listen(uid)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer l.Close()

	srvConnCh := make(chan error, 1)
	go func() {
		conn, err := l.Accept()
		if err != nil {
			srvConnCh <- err
			return
		}
		defer conn.Close()
		peer, err := PeerUID(conn)
		if err != nil {
			srvConnCh <- err
			return
		}
		if peer != uid {
			srvConnCh <- errNotMatching(peer, uid)
			return
		}
		srvConnCh <- nil
	}()

	conn, err := Dial(uid)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	if err := <-srvConnCh; err != nil {
		t.Fatalf("server side: %v", err)
	}
}

func errNotMatching(got, want int) error {
	return &mismatchError{got, want}
}

type mismatchError struct{ got, want int }

func (e *mismatchError) Error() string {
	return "peer uid mismatch"
}

func TestDialFailsWithoutDaemon(t *testing.T) {
	withRuntimeDir(t)
	if _, err := Dial(os.Getuid()); err == nil {
		t.Fatalf("expected an error dialing with no daemon listening")
	}
}

func TestWriteReadJSONRoundTrip(t *testing.T) {
	withRuntimeDir(t)
	uid := os.Getuid()
	l, err := Listen(uid)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer l.Close()

	type msg struct {
		Cmd   string `json:"cmd"`
		Value int    `json:"value"`
	}

	done := make(chan error, 1)
	go func() {
		conn, err := l.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		var got msg
		if err := NewLineReader(conn).ReadJSON(&got); err != nil {
			done <- err
			return
		}
		if got.Cmd != "approve" || got.Value != 42 {
			done <- &mismatchError{}
			return
		}
		done <- WriteJSON(conn, msg{Cmd: "ok", Value: 43})
	}()

	conn, err := Dial(uid)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	if err := WriteJSON(conn, msg{Cmd: "approve", Value: 42}); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	var reply msg
	if err := NewLineReader(conn).ReadJSON(&reply); err != nil {
		t.Fatalf("ReadJSON: %v", err)
	}
	if reply.Cmd != "ok" || reply.Value != 43 {
		t.Fatalf("reply = %+v, want {ok 43}", reply)
	}
	if err := <-done; err != nil {
		t.Fatalf("server side: %v", err)
	}
}
