// Package keyfile validates the trust-anchor file: the enrolled phone's
// public key, read by a helper that runs as root. The checks exist so
// that nothing but `nothing-approve enroll`, also run as root, can ever
// decide which key approves sudo for a user - not a symlink, not a file
// in a directory the user can repoint, not a file of the wrong shape.
package keyfile

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// MaxSize is the largest a key file may be.
const MaxSize = 16 * 1024

// Dir is the directory that holds one trust-anchor file per user.
// Fixed, like the design requires: no flag, no environment variable
// changes it, so a user cannot point the helper at a key under their
// own control.
const Dir = "/etc/nothing-approve"

// Path returns the trust-anchor path for user.
func Path(user string) string {
	return filepath.Join(Dir, user+".pub")
}

// Load reads and validates the trust-anchor file for user, and returns
// the enrolled public key. It fails closed: any violation of the checks
// below is reported as an error, and the caller must treat that exactly
// like "no key enrolled".
func Load(user string) (*ecdsa.PublicKey, error) {
	path := Path(user)

	// O_NOFOLLOW: refuses a symlink at the final path component outright,
	// rather than opening whatever it points to. Every check below reads
	// the opened descriptor, not the path again, so nothing can replace
	// the file between a check and the open.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("keyfile: open: %w", err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("keyfile: stat: %w", err)
	}
	if err := checkFileStat(info); err != nil {
		return nil, err
	}
	if err := checkDirChain(filepath.Dir(path)); err != nil {
		return nil, err
	}

	data, err := io.ReadAll(io.LimitReader(f, MaxSize+1))
	if err != nil {
		return nil, fmt.Errorf("keyfile: read: %w", err)
	}
	if len(data) > MaxSize {
		return nil, fmt.Errorf("keyfile: larger than %d bytes", MaxSize)
	}

	return parsePublicKey(data)
}

func checkFileStat(info os.FileInfo) error {
	if !info.Mode().IsRegular() {
		return fmt.Errorf("keyfile: not a regular file")
	}
	sys, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("keyfile: cannot read file ownership")
	}
	return checkRootOwnedNotGroupOtherWritable(sys.Uid, info.Mode().Perm())
}

// checkRootOwnedNotGroupOtherWritable is the pure rule behind both the
// key file check and the directory chain check: owned by root (uid 0),
// and neither the group nor other write bit set. Kept free of os.Stat
// so it can be tested directly with values a test can set up without
// needing root to actually own a file.
func checkRootOwnedNotGroupOtherWritable(uid uint32, perm os.FileMode) error {
	if uid != 0 {
		return fmt.Errorf("keyfile: not owned by root")
	}
	if perm&0o022 != 0 {
		return fmt.Errorf("keyfile: writable by group or other")
	}
	return nil
}

// checkDirOwnerAndMode is checkRootOwnedNotGroupOtherWritable with one
// relaxation: a sticky directory (like /tmp) may be group/other
// writable, since the sticky bit itself already stops one user from
// renaming or deleting another's entry in it. The owner must still be
// root regardless - the sticky bit never forgives that.
func checkDirOwnerAndMode(uid uint32, perm os.FileMode, sticky bool) error {
	if uid != 0 {
		return fmt.Errorf("not owned by root")
	}
	if perm&0o022 != 0 && !sticky {
		return fmt.Errorf("writable by group or other")
	}
	return nil
}

// checkDirChain walks from dir up to the filesystem root. Every directory
// in the chain must be root-owned and not writable by group or other,
// unless it has the sticky bit and root owns it (as /tmp would, though
// nothing under /etc should ever need that: the sticky-bit exception
// exists so a correctly-configured system directory is never rejected
// over a bit this check does not actually need to be strict about).
func checkDirChain(dir string) error {
	for {
		info, err := os.Lstat(dir)
		if err != nil {
			return fmt.Errorf("keyfile: stat %s: %w", dir, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("keyfile: %s is a symlink", dir)
		}
		sys, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("keyfile: cannot read ownership of %s", dir)
		}
		sticky := info.Mode()&os.ModeSticky != 0
		if err := checkDirOwnerAndMode(sys.Uid, info.Mode().Perm(), sticky); err != nil {
			return fmt.Errorf("keyfile: %s: %w", dir, err)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return nil // reached /
		}
		dir = parent
	}
}

func parsePublicKey(data []byte) (*ecdsa.PublicKey, error) {
	block, rest := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("keyfile: not a PEM file")
	}
	if strings.TrimSpace(string(rest)) != "" {
		return nil, fmt.Errorf("keyfile: trailing data after the PEM block")
	}
	if block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("keyfile: PEM block is %q, want \"PUBLIC KEY\"", block.Type)
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("keyfile: parse: %w", err)
	}
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("keyfile: not an EC key")
	}
	if ecPub.Curve != elliptic.P256() {
		return nil, fmt.Errorf("keyfile: not on curve P-256")
	}
	return ecPub, nil
}

// DeviceInfo holds the PEM headers that name the enrolled phone. They
// are descriptive only: changing them does not change what counts as a
// valid signature, since they never enter the signed message.
type DeviceInfo struct {
	DeviceID   string
	DeviceName string
}

// ReadDeviceInfo reads the PEM headers of the trust-anchor file for
// user, without the strict ownership checks Load applies - it is used
// only to print a friendly name, never to decide whether a signature
// is trusted.
func ReadDeviceInfo(user string) (DeviceInfo, error) {
	data, err := os.ReadFile(Path(user))
	if err != nil {
		return DeviceInfo{}, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return DeviceInfo{}, fmt.Errorf("keyfile: not a PEM file")
	}
	return DeviceInfo{
		DeviceID:   block.Headers["Device-Id"],
		DeviceName: block.Headers["Device-Name"],
	}, nil
}

// Write writes pub as the trust-anchor file for user, with the device
// headers, atomically: a temp file in Dir, synced, then renamed into
// place. The caller must already be root. Write sets the file to the
// permissions Load requires, so a file Write produces always passes
// Load immediately after.
func Write(user string, pub *ecdsa.PublicKey, deviceID, deviceName string) error {
	if err := os.MkdirAll(Dir, 0o755); err != nil {
		return fmt.Errorf("keyfile: mkdir: %w", err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return fmt.Errorf("keyfile: marshal: %w", err)
	}
	block := &pem.Block{
		Type: "PUBLIC KEY",
		Headers: map[string]string{
			"Device-Id":   deviceID,
			"Device-Name": deviceName,
		},
		Bytes: der,
	}
	data := pem.EncodeToMemory(block)

	path := Path(user)
	tmp, err := os.CreateTemp(Dir, ".tmp-"+user+"-*")
	if err != nil {
		return fmt.Errorf("keyfile: create temp: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once the rename below succeeds

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("keyfile: write: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("keyfile: sync: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("keyfile: close: %w", err)
	}
	if err := os.Chmod(tmpName, 0o644); err != nil {
		return fmt.Errorf("keyfile: chmod: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("keyfile: rename: %w", err)
	}
	return nil
}

// Remove deletes the trust-anchor file for user. The caller must
// already be root.
func Remove(user string) error {
	err := os.Remove(Path(user))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}
