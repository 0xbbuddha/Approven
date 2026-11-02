// Command approved is the user-level daemon: it relays approval and
// enrollment requests between the local Unix socket (approve-helper,
// approve-cli) and the paired phone. It holds no opinion on whether a
// request should succeed - it only carries bytes and lets the caller
// verify the phone's signature itself.
package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"syscall"

	"approven/internal/daemon"
	"approven/internal/ipc"
	"approven/internal/keyfile"
	"approven/internal/phonetransport"
)

// DefaultPort is the TCP port the daemon listens on for phones. Not yet
// configurable - the first thing to add when that turns out to matter.
const DefaultPort = 17165

func main() {
	uid := os.Getuid()
	if uid == 0 {
		log.Fatal("approved: refuses to run as root; it should run as the user it serves, under a systemd --user service")
	}

	dataDir, err := dataDir()
	if err != nil {
		log.Fatalf("approved: %v", err)
	}
	cert, err := phonetransport.LoadOrCreateCert(dataDir)
	if err != nil {
		log.Fatalf("approved: %v", err)
	}
	if fp, err := phonetransport.Fingerprint(cert); err == nil {
		log.Printf("approved: certificate fingerprint %s", fp)
	}

	tcpAddr := fmt.Sprintf(":%d", DefaultPort)
	tl, err := net.Listen("tcp", tcpAddr)
	if err != nil {
		log.Fatalf("approved: listen %s: %v", tcpAddr, err)
	}
	defer tl.Close()

	l, err := ipc.Listen(uid)
	if err != nil {
		log.Fatalf("approved: %v", err)
	}
	defer l.Close()

	u, err := user.LookupId(fmt.Sprint(uid))
	if err != nil {
		log.Fatalf("approved: %v", err)
	}
	// Re-read on every connection, so a fresh enrollment (or a remove)
	// takes effect without restarting the daemon.
	pin := func() string {
		info, err := keyfile.ReadDeviceInfo(u.Username)
		if err != nil {
			return ""
		}
		return info.ClientCert
	}
	transport := phonetransport.NewServer(cert, pin, log.Printf)
	transport.OnTest = runTestSudo
	d := daemon.New(uid, transport, log.Printf)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		if err := transport.Serve(ctx, tl); err != nil {
			log.Printf("approved: phone listener: %v", err)
		}
	}()

	log.Printf("approved: phones connect on port %d, local clients on %s", DefaultPort, ipc.SocketPath(uid))
	if err := d.Serve(ctx, l); err != nil {
		log.Fatalf("approved: %v", err)
	}
}

// runTestSudo is the phone's "test" button: a real `sudo true`, with
// cached credentials ignored (-k) so it really goes through the phone.
// It runs through systemd-run because this daemon's own unit sets
// NoNewPrivileges, under which a setuid sudo refuses to start. stdin is
// empty: should the phone deny, the password fallback fails at once
// instead of waiting on a prompt nobody can see.
func runTestSudo() error {
	notify("Test sudo from your phone", "Approve it on the phone…")
	cmd := exec.Command("systemd-run", "--user", "--wait", "--quiet", "--collect",
		"-p", "StandardInput=null", "--", "sudo", "-k", "-S", "true")
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Printf("approved: test sudo: %v: %s", err, out)
		notify("Test sudo failed", "sudo true was not approved.")
		return fmt.Errorf("sudo true failed")
	}
	notify("Test sudo worked ✓", "sudo true was approved from your phone.")
	return nil
}

// notify shows a desktop notification, best-effort: the test runs with
// no terminal, so this is the only sign of it on the computer. The
// synchronous hint makes the result replace the "approve it" bubble on
// daemons that support it (dunst, swaync); the rest just show both.
func notify(title, body string) {
	_ = exec.Command("notify-send", "-a", "approven", "-i", "security-high",
		"-h", "string:x-canonical-private-synchronous:approven-test", title, body).Run()
}

// dataDir returns where the daemon keeps its own certificate.
// $STATE_DIRECTORY is what systemd sets when the unit uses
// StateDirectory=approven (dist/approved.service does): systemd
// creates that exact directory, writable, before the service's mount
// namespace is even set up, which a hand-rolled ReadWritePaths under
// ProtectHome cannot do for a path that does not exist yet. Outside
// systemd - running approved by hand, as the smoke tests in this repo
// do - XDG_DATA_HOME is the right fallback.
func dataDir() (string, error) {
	if sd := os.Getenv("STATE_DIRECTORY"); sd != "" {
		return sd, nil
	}
	base := os.Getenv("XDG_DATA_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		base = filepath.Join(home, ".local", "share")
	}
	return filepath.Join(base, "approven"), nil
}
