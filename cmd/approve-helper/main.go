// Command approve-helper is invoked by PAM (pam_exec, as root) to approve
// a sudo request against a phone's fingerprint. It prints nothing and
// exits non-zero at the first sign of trouble, so PAM falls through to
// the password prompt - this program's job is to say yes, never to say
// why not.
//
// Security-critical invariant: this program trusts nothing that comes
// back over the wire except the raw signature bytes. Every field of the
// message it verifies (host, user, service, tty, rhost, time, nonce)
// comes from its own PAM environment and its own freshly-generated
// values - never from the daemon's response, even though the daemon
// echoes nothing back today. If that ever changes, it must stay this
// way: a changed daemon must not be able to make this program verify a
// different message than the one it asked the phone to sign.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"os/user"
	"strconv"
	"syscall"
	"time"

	"nothing-approve/internal/daemon"
	"nothing-approve/internal/ipc"
	"nothing-approve/internal/keyfile"
	"nothing-approve/internal/protocol"
)

// defaultWait is how long the helper waits for the phone when
// approve_timeout is not configured. Matches the reference design's
// own default.
const defaultWait = 20 * time.Second

// refusedServices never reach the phone: ssh already has its own
// second factor story, and approving it over a LAN protocol this
// program does not harden against would widen, not narrow, what a
// network attacker can reach.
var refusedServices = map[string]bool{
	"sshd": true,
}

func main() {
	os.Exit(run())
}

// run returns the process exit code. Every early return is a refusal:
// PAM treats anything but 0 as "ask for the password instead."
func run() int {
	pamUser := os.Getenv("PAM_USER")
	pamService := os.Getenv("PAM_SERVICE")
	pamTTY := os.Getenv("PAM_TTY")
	pamRHost := os.Getenv("PAM_RHOST")
	pamRUser := os.Getenv("PAM_RUSER")

	if refusedServices[pamService] {
		return 1
	}
	if pamUser == "" || pamService == "" {
		return 1
	}
	// Another user acting on this user's behalf, e.g. through the
	// sudoers "targetpw"/"runaspw" option: refuse outright rather than
	// let that user's phone approve a different account.
	if pamRUser != "" && pamRUser != pamUser {
		return 1
	}

	u, err := user.Lookup(pamUser)
	if err != nil {
		return 1
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return 1
	}

	// No key file, or one that fails any of keyfile.Load's checks: stop
	// at once. This also means a sudo for a user who never enrolled a
	// phone never even reaches the daemon.
	pub, err := keyfile.Load(pamUser)
	if err != nil {
		return 1
	}

	host, err := os.Hostname()
	if err != nil {
		return 1
	}
	nonce, err := protocol.NewNonce()
	if err != nil {
		return 1
	}
	reqTime := time.Now().Unix()

	approveReq := protocol.ApproveRequest{
		Host: host, User: pamUser, Service: pamService,
		TTY: pamTTY, RHost: pamRHost, Time: reqTime, Nonce: nonce,
	}
	// Built once, verified against later: this exact value, not
	// whatever the daemon or the phone might claim the request was.
	message, err := approveReq.Bytes()
	if err != nil {
		return 1
	}

	conn, err := ipc.Dial(uid)
	if err != nil {
		return 1
	}
	defer conn.Close()

	wait := defaultWait
	if err := ipc.WriteJSON(conn, daemon.Request{
		Cmd: "approve", Host: host, User: pamUser, Service: pamService,
		TTY: pamTTY, RHost: pamRHost, Time: reqTime, Nonce: nonce,
		WaitSeconds: int(wait.Seconds()),
	}); err != nil {
		return 1
	}

	name := phoneName(pamUser)
	if pamTTY != "" {
		fmt.Printf("Approve on %s for terminal %s, or wait for the password prompt.\n", name, pamTTY)
	} else {
		fmt.Printf("Approve on %s, or wait for the password prompt.\n", name)
	}

	// SIGTERM (the PAM caller stopping, e.g. the user closing the
	// terminal) ends the wait the same way a timeout does: the daemon's
	// response simply never arrives, and the deferred conn.Close above
	// drops the connection so the daemon can cancel it on the phone.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	readDone := make(chan daemon.Response, 1)
	readErr := make(chan error, 1)
	go func() {
		var resp daemon.Response
		if err := ipc.NewLineReader(conn).ReadJSON(&resp); err != nil {
			readErr <- err
			return
		}
		readDone <- resp
	}()

	// A hard ceiling beyond the daemon's own wait, matching the
	// reference design's "the whole helper: 130 seconds at most" - the
	// daemon is trusted to honor WaitSeconds, but this program does not
	// hang forever if it somehow does not.
	hardCeiling := time.NewTimer(wait + 110*time.Second)
	defer hardCeiling.Stop()

	var resp daemon.Response
	select {
	case resp = <-readDone:
	case <-readErr:
		return 1
	case <-ctx.Done():
		return 1
	case <-hardCeiling.C:
		return 1
	}

	if !resp.OK {
		return 1
	}
	// Defense in depth: even though reqTime is this process's own
	// value, confirm the round trip did not take absurdly long before
	// trusting a signature over it.
	if elapsed := time.Now().Unix() - reqTime; elapsed < 0 || elapsed > int64(wait.Seconds())+10 {
		return 1
	}
	if !protocol.Verify(pub, message, resp.Signature) {
		return 1
	}
	return 0
}

func phoneName(pamUser string) string {
	info, err := keyfile.ReadDeviceInfo(pamUser)
	if err != nil || info.DeviceName == "" {
		return "the phone"
	}
	return info.DeviceName
}
