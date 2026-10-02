// Command approve-cli is the user-facing (and, for enroll, root-facing)
// command: pairing a phone and checking status. The actual approval at
// sudo time runs through approve-helper, invoked by PAM - this binary is
// never on that path.
package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"fmt"
	"io"
	"os"
	"os/user"
	"strconv"
	"strings"
	"time"

	"nothing-approve/internal/daemon"
	"nothing-approve/internal/ipc"
	"nothing-approve/internal/keyfile"
	"nothing-approve/internal/protocol"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "enroll":
		err = runEnroll()
	case "status":
		err = runStatus()
	case "remove":
		err = runRemove()
	case "-h", "--help", "help":
		usage()
		return
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "nothing-approve:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `nothing-approve-cli enroll   pair a phone for sudo approval (run with sudo)
nothing-approve-cli status   show whether a phone is connected
nothing-approve-cli remove   remove the enrolled key for your user (run with sudo)`)
}

// targetUser returns the user an enroll/remove acts on: SUDO_USER when
// run through sudo, so `sudo nothing-approve-cli enroll` enrolls the
// person who ran sudo, not root.
func targetUser() (name string, uid int, err error) {
	if su := os.Getenv("SUDO_USER"); su != "" {
		name = su
	} else {
		u, err := user.Current()
		if err != nil {
			return "", 0, err
		}
		name = u.Username
	}
	u, err := user.Lookup(name)
	if err != nil {
		return "", 0, err
	}
	uid, err = strconv.Atoi(u.Uid)
	return name, uid, err
}

func runStatus() error {
	name, uid, err := targetUser()
	if err != nil {
		return err
	}
	conn, err := ipc.Dial(uid)
	if err != nil {
		return fmt.Errorf("nothing-approved is not running for %s: %w", name, err)
	}
	defer conn.Close()
	if err := ipc.WriteJSON(conn, daemon.Request{Cmd: "status"}); err != nil {
		return err
	}
	var resp daemon.Response
	if err := ipc.NewLineReader(conn).ReadJSON(&resp); err != nil {
		return err
	}
	if !resp.OK {
		return fmt.Errorf("%s", resp.Error)
	}
	if resp.PhoneConnected {
		fmt.Printf("Phone connected: %s\n", resp.PhoneName)
	} else {
		fmt.Println("No phone connected.")
	}
	if info, err := keyfile.ReadDeviceInfo(name); err == nil {
		fmt.Printf("Enrolled: %s (%s)\n", info.DeviceName, info.DeviceID)
	} else {
		fmt.Println("No phone enrolled for sudo approval.")
	}
	return nil
}

func runRemove() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("run this with sudo")
	}
	name, _, err := targetUser()
	if err != nil {
		return err
	}
	if err := keyfile.Remove(name); err != nil {
		return err
	}
	fmt.Printf("Removed the enrolled key for %s.\n", name)
	return nil
}

func runEnroll() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("run this with sudo")
	}
	name, uid, err := targetUser()
	if err != nil {
		return err
	}

	conn, err := ipc.Dial(uid)
	if err != nil {
		return fmt.Errorf("nothing-approved is not running for %s: %w", name, err)
	}
	defer conn.Close()

	host, err := os.Hostname()
	if err != nil {
		return err
	}
	nonce, err := protocol.NewNonce()
	if err != nil {
		return err
	}
	reqTime := time.Now().Unix()

	if err := ipc.WriteJSON(conn, daemon.Request{
		Cmd: "enroll", Host: host, User: name, EnrollTime: reqTime, EnrollNonce: nonce,
	}); err != nil {
		return err
	}

	fmt.Printf("Open the app on the phone and select Enroll for %s on %s.\n", name, host)

	var resp daemon.Response
	if err := ipc.NewLineReader(conn).ReadJSON(&resp); err != nil {
		return fmt.Errorf("waiting for the phone: %w", err)
	}
	if !resp.OK {
		return fmt.Errorf("%s", resp.Error)
	}

	ecdsaPub, err := asECDSA(resp.PublicKeyDER)
	if err != nil {
		return fmt.Errorf("the phone sent a key this program could not use: %w", err)
	}

	// Rebuild the enrollment message from fields this process generated
	// itself (host, user, time, nonce) plus the hash of the key the
	// phone just sent - never from any other field the daemon echoed
	// back. Verifying this proves the phone holds the private key for
	// the public key it sent, and that it was willing to sign with it
	// (which, on the phone, only happens after the biometric check).
	keyHash, err := protocol.KeyHash(ecdsaPub)
	if err != nil {
		return err
	}
	enrollReq := protocol.EnrollRequest{Host: host, User: name, KeyHash: keyHash, Time: reqTime, Nonce: nonce}
	message, err := enrollReq.Bytes()
	if err != nil {
		return err
	}
	if !protocol.Verify(ecdsaPub, message, resp.EnrollSig) {
		return fmt.Errorf("the phone's enrollment signature did not verify; nothing was written")
	}

	code, err := protocol.KeyCode(ecdsaPub)
	if err != nil {
		return err
	}
	fmt.Println("Type the code shown on the phone:")
	ok, err := promptKeyCode(code, os.Stdin)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("the typed code did not match after 3 tries; nothing was written")
	}

	if err := keyfile.Write(name, ecdsaPub, resp.DeviceID, resp.DeviceName); err != nil {
		return err
	}
	fmt.Printf("Enrolled %s for sudo approval on %s.\n", resp.DeviceName, host)
	return nil
}

func asECDSA(der []byte) (*ecdsa.PublicKey, error) {
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("the phone's key is not an EC key")
	}
	if ec.Curve != elliptic.P256() {
		return nil, fmt.Errorf("the phone's key is not on curve P-256")
	}
	return ec, nil
}

// promptKeyCode reads from in (os.Stdin in production), not a value
// echoed by this process - the terminal shows no code of its own,
// matching the reference design: a changed daemon that saw this
// terminal's output could not forge the code the phone actually
// displayed.
func promptKeyCode(want string, in io.Reader) (bool, error) {
	normWant := protocol.NormalizeKeyCode(want)
	r := bufio.NewReader(in)
	for try := 1; try <= 3; try++ {
		fmt.Printf("Code (try %d/3): ", try)
		line, err := r.ReadString('\n')
		if err != nil {
			return false, err
		}
		if protocol.NormalizeKeyCode(strings.TrimSpace(line)) == normWant {
			return true, nil
		}
		fmt.Println("That does not match.")
	}
	return false, nil
}
