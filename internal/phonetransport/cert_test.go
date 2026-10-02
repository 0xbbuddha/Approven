package phonetransport

import (
	"testing"
)

func TestLoadOrCreateCertPersists(t *testing.T) {
	dir := t.TempDir()
	c1, err := LoadOrCreateCert(dir)
	if err != nil {
		t.Fatalf("LoadOrCreateCert: %v", err)
	}
	c2, err := LoadOrCreateCert(dir)
	if err != nil {
		t.Fatalf("LoadOrCreateCert (second call): %v", err)
	}
	f1, err := Fingerprint(c1)
	if err != nil {
		t.Fatalf("Fingerprint: %v", err)
	}
	f2, err := Fingerprint(c2)
	if err != nil {
		t.Fatalf("Fingerprint: %v", err)
	}
	if f1 != f2 {
		t.Fatalf("a second LoadOrCreateCert in the same dir produced a different certificate: %s vs %s", f1, f2)
	}
}

func TestLoadOrCreateCertDifferentDirsDiffer(t *testing.T) {
	c1, err := LoadOrCreateCert(t.TempDir())
	if err != nil {
		t.Fatalf("LoadOrCreateCert: %v", err)
	}
	c2, err := LoadOrCreateCert(t.TempDir())
	if err != nil {
		t.Fatalf("LoadOrCreateCert: %v", err)
	}
	f1, _ := Fingerprint(c1)
	f2, _ := Fingerprint(c2)
	if f1 == f2 {
		t.Fatalf("2 fresh certificates in different dirs must not collide")
	}
}
