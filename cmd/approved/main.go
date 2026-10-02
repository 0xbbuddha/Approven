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
	"os/signal"
	"path/filepath"
	"syscall"

	"approven/internal/daemon"
	"approven/internal/ipc"
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

	transport := phonetransport.NewServer(cert, log.Printf)
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
