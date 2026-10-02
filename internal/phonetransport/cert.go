package phonetransport

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// certLifetime is long on purpose: this certificate is not refreshed
// automatically yet, and a server cert a pinned phone rejects at
// expiry is a worse failure mode than a long-lived one.
const certLifetime = 10 * 365 * 24 * time.Hour

// LoadOrCreateCert returns the daemon's TLS certificate, generating and
// persisting a new self-signed one at dir/daemon.key and dir/daemon.crt
// if none exists yet. The same certificate must survive daemon
// restarts: a phone pins it at enrollment, and a new certificate on
// every restart would make every approval after that look like a
// network attacker to the phone.
func LoadOrCreateCert(dir string) (tls.Certificate, error) {
	keyPath := filepath.Join(dir, "daemon.key")
	certPath := filepath.Join(dir, "daemon.crt")

	if cert, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil {
		return cert, nil
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return tls.Certificate{}, fmt.Errorf("phonetransport: mkdir: %w", err)
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("phonetransport: generate key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("phonetransport: serial: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "approven"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(certLifetime),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true, // self-signed leaf acting as its own anchor; nothing chains to it
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("phonetransport: create certificate: %w", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("phonetransport: marshal key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	if err := writePrivate(keyPath, keyPEM); err != nil {
		return tls.Certificate{}, err
	}
	if err := writePrivate(certPath, certPEM); err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(certPEM, keyPEM)
}

func writePrivate(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("phonetransport: write %s: %w", path, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("phonetransport: rename %s: %w", path, err)
	}
	return nil
}

// Fingerprint returns the SHA-256 of cert's DER bytes, as 64 lowercase
// hex digits - what a phone pins at enrollment and checks on every
// later connection.
func Fingerprint(cert tls.Certificate) (string, error) {
	if len(cert.Certificate) == 0 {
		return "", fmt.Errorf("phonetransport: certificate has no DER bytes")
	}
	sum := sha256.Sum256(cert.Certificate[0])
	return hex.EncodeToString(sum[:]), nil
}
