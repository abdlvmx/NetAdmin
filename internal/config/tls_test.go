package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func testCertificate(t *testing.T, expired bool) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	end := now.Add(time.Hour)
	if expired {
		end = now.Add(-time.Minute)
	}
	c := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "panel.example.test"}, DNSNames: []string{"panel.example.test"}, NotBefore: now.Add(-time.Hour), NotAfter: end, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, c, c, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key")
	if err = os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: priv}), 0600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

func TestTLSSettingsResolveDataDirectoryAndEnvironment(t *testing.T) {
	dir := t.TempDir()
	c := Config{TLSCertFile: "certs/server.crt", TLSKeyFile: "certs/server.key", PublicURL: "https://panel.example.test:8765/"}
	s, err := c.TLSSettingsAt(dir, false)
	if err != nil || s.CertFile != filepath.Join(dir, "certs/server.crt") || s.PublicURL != "https://panel.example.test:8765" {
		t.Fatalf("settings: %+v %v", s, err)
	}
	t.Setenv("NETADMIN_PUBLIC_URL", "https://override.example.test")
	s, err = c.TLSSettingsAt(dir, true)
	if err != nil || s.PublicURL != "https://override.example.test" {
		t.Fatalf("environment ignored: %+v %v", s, err)
	}
	s, _ = c.TLSSettingsAt(dir, false)
	if s.PublicURL != "https://panel.example.test:8765" {
		t.Fatal("installer inherited shell override")
	}
}

func TestTLSSettingsRejectIncompleteAndInvalidOrigins(t *testing.T) {
	for _, c := range []Config{
		{TLSCertFile: "a"}, {PublicURL: "https://panel.example.test"},
		{TLSCertFile: "a", TLSKeyFile: "b"},
		{TLSCertFile: "a", TLSKeyFile: "b", PublicURL: "http://panel.example.test"},
		{TLSCertFile: "a", TLSKeyFile: "b", PublicURL: "https://user:password@panel.example.test"},
		{TLSCertFile: "a", TLSKeyFile: "b", PublicURL: "https://panel.example.test/path"},
		{TLSCertFile: "a", TLSKeyFile: "b", PublicURL: "https://panel.example.test?x=1"},
		{TLSCertFile: "a", TLSKeyFile: "b", PublicURL: "https://panel.example.test:65536"},
	} {
		if _, err := c.TLSSettingsAt(t.TempDir(), false); err == nil {
			t.Fatalf("invalid config accepted: %+v", c)
		}
	}
}

func TestTLSLoadVerifiesNameDateAndKey(t *testing.T) {
	cert, key := testCertificate(t, false)
	s := TLSSettings{cert, key, "https://panel.example.test:8765"}
	c, err := s.Load()
	if err != nil || c.MinVersion != tls.VersionTLS12 || len(c.Certificates) != 1 {
		t.Fatalf("valid TLS: %v", err)
	}
	s.PublicURL = "https://different.example.test"
	if _, err = s.Load(); err == nil {
		t.Fatal("hostname mismatch accepted")
	}
	s.PublicURL = "https://panel.example.test"
	_, otherKey := testCertificate(t, false)
	s.KeyFile = otherKey
	if _, err = s.Load(); err == nil {
		t.Fatal("wrong private key accepted")
	}
	s.CertFile, s.KeyFile = testCertificate(t, true)
	if _, err = s.Load(); err == nil {
		t.Fatal("expired certificate accepted")
	}
}
