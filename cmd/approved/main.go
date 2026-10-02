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

	"nothing-approve/internal/daemon"
	"nothing-approve/internal/ipc"
	"nothing-approve/internal/phonetransport"
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

// dataDir returns where the daemon keeps its own certificate: under
// XDG_DATA_HOME, like any other per-user application state.
func dataDir() (string, error) {
	base := os.Getenv("XDG_DATA_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		base = filepath.Join(home, ".local", "share")
	}
	return filepath.Join(base, "nothing-approve"), nil
}
