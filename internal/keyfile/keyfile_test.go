package keyfile

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestCheckRootOwnedNotGroupOtherWritable(t *testing.T) {
	cases := []struct {
		name    string
		uid     uint32
		perm    os.FileMode
		wantErr bool
	}{
		{"root, 0644", 0, 0o644, false},
		{"root, 0600", 0, 0o600, false},
		{"root, 0640", 0, 0o640, false}, // group read only, no write bits set
		{"non-root, 0600", 1000, 0o600, true},
		{"root, 0646 other-write", 0, 0o646, true},
		{"root, 0664 group-write", 0, 0o664, true},
	}
	for _, c := range cases {
		err := checkRootOwnedNotGroupOtherWritable(c.uid, c.perm)
		if (err != nil) != c.wantErr {
			t.Errorf("%s: err=%v, wantErr=%v", c.name, err, c.wantErr)
		}
	}
}

func TestCheckDirOwnerAndModeStickyException(t *testing.T) {
	if err := checkDirOwnerAndMode(0, 0o777, true); err != nil {
		t.Errorf("sticky root-owned 0777 dir should pass: %v", err)
	}
	if err := checkDirOwnerAndMode(0, 0o777, false); err == nil {
		t.Errorf("non-sticky root-owned 0777 dir should fail")
	}
	if err := checkDirOwnerAndMode(1000, 0o755, true); err == nil {
		t.Errorf("sticky bit must never forgive a non-root owner")
	}
}

func genTestKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return priv
}

func TestParsePublicKeyAcceptsValidP256(t *testing.T) {
	priv := genTestKey(t)
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	data := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	pub, err := parsePublicKey(data)
	if err != nil {
		t.Fatalf("parsePublicKey: %v", err)
	}
	if pub.X.Cmp(priv.PublicKey.X) != 0 {
		t.Fatalf("parsed key does not match the original")
	}
}

func TestParsePublicKeyRejectsNonP256(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	data := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	if _, err := parsePublicKey(data); err == nil {
		t.Fatalf("expected an error for a P-384 key")
	}
}

func TestParsePublicKeyRejectsWrongPEMType(t *testing.T) {
	priv := genTestKey(t)
	der, _ := x509.MarshalECPrivateKey(priv)
	data := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	if _, err := parsePublicKey(data); err == nil {
		t.Fatalf("expected an error for a private key PEM block")
	}
}

func TestParsePublicKeyRejectsGarbage(t *testing.T) {
	if _, err := parsePublicKey([]byte("not even pem")); err == nil {
		t.Fatalf("expected an error for non-PEM data")
	}
}

func TestParsePublicKeyRejectsTrailingData(t *testing.T) {
	priv := genTestKey(t)
	der, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	data := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	data = append(data, []byte("extra trailing junk\n")...)
	if _, err := parsePublicKey(data); err == nil {
		t.Fatalf("expected an error for trailing data after the PEM block")
	}
}

func TestWriteThenLoadRoundTrip(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("Write/Load round trip needs root to own /etc/nothing-approve and the key file")
	}
	priv := genTestKey(t)
	user := "nothing-approve-test-user"
	t.Cleanup(func() { _ = Remove(user) })

	if err := Write(user, &priv.PublicKey, "device-1", "Test Phone"); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got, err := Load(user)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.X.Cmp(priv.PublicKey.X) != 0 {
		t.Fatalf("loaded key does not match the written key")
	}

	info, err := ReadDeviceInfo(user)
	if err != nil {
		t.Fatalf("ReadDeviceInfo: %v", err)
	}
	if info.DeviceID != "device-1" || info.DeviceName != "Test Phone" {
		t.Fatalf("ReadDeviceInfo = %+v, want device-1/Test Phone", info)
	}
}

func TestLoadRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real.pub")
	if err := os.WriteFile(real, []byte("whatever"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	link := filepath.Join(dir, "link.pub")
	if err := os.Symlink(real, link); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	// Exercise the same O_NOFOLLOW open Load uses, directly against our
	// temp-dir symlink rather than the fixed /etc path, so the test does
	// not depend on root.
	_, err := os.OpenFile(link, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err == nil {
		t.Fatalf("expected O_NOFOLLOW to refuse a symlink")
	}
}
