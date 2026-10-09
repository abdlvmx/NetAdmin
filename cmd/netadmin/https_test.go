package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"netadmin/internal/config"
	"netadmin/internal/version"
)

func TestHTTPSHealthPinsConfiguredCertificateAndDialsLocalListener(t *testing.T) {
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-NetAdmin-Version", "test-tls")
		w.Header().Set("X-NetAdmin-PID", "456")
		w.Write([]byte("ok"))
	}))
	defer s.Close()
	der := s.TLS.Certificates[0].Certificate[0]
	leaf, err := x509.ParseCertificate(der)
	if err != nil || len(leaf.DNSNames) == 0 {
		t.Fatalf("test certificate: %v", err)
	}
	certFile := filepath.Join(t.TempDir(), "server.crt")
	if err = os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(s.URL)
	// The public hostname/port need not resolve locally. The check still
	// verifies its certificate name while connecting to the actual listener.
	publicURL := "https://" + leaf.DNSNames[0] + ":443/healthz"
	if err = checkServerHealthTLS(publicURL, "test-tls", 456, certFile, u.Host); err != nil {
		t.Fatalf("local TLS probe: %v", err)
	}
	if err = checkServerHealthTLS("https://wrong.example.invalid/healthz", "test-tls", 456, certFile, u.Host); err == nil {
		t.Fatal("wrong hostname accepted")
	}
	if err = checkServerHealthTLS(s.URL+"/healthz", "test-tls", 456, "", ""); err == nil {
		t.Fatal("untrusted TLS certificate accepted")
	}
	if err = checkServerHealthTLS(publicURL, "test-tls", 999, certFile, u.Host); err == nil {
		t.Fatal("wrong service process accepted")
	}
}

func TestInstalledHTTPSUsesConfigurationWithoutShellOverrides(t *testing.T) {
	dir := t.TempDir()
	cfg := config.Config{ListenAddr: "0.0.0.0:8765", TLSCertFile: "certs/server.crt", TLSKeyFile: "certs/server.key", PublicURL: "https://panel.example.test:8765"}
	b, _ := json.Marshal(cfg)
	if err := os.WriteFile(filepath.Join(dir, "config.json"), b, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NETADMIN_PUBLIC_URL", "https://wrong.example.test")
	got, err := installedServerHealthURL(dir)
	if err != nil || got != cfg.PublicURL+"/healthz" {
		t.Fatalf("health URL: %q %v", got, err)
	}
	_, transport, err := installedServerTransport(dir)
	if err != nil || transport.CertFile != filepath.Join(dir, "certs/server.crt") {
		t.Fatalf("service certificate path: %+v %v", transport, err)
	}
}

func TestServerRejectsCorruptConfigurationWithoutOverwritingOrOpeningDatabase(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("NETADMIN_DATA_DIR", dir)
	b := []byte(`{"tls_cert_file":"server.crt",broken`)
	p := filepath.Join(dir, "config.json")
	if err := os.WriteFile(p, b, 0600); err != nil {
		t.Fatal(err)
	}
	if err := serve(false, nil); err == nil {
		t.Fatal("corrupt config started server")
	}
	got, err := os.ReadFile(p)
	if err != nil || string(got) != string(b) {
		t.Fatal("config changed before rejection")
	}
	if _, err = os.Stat(config.DBPath()); !os.IsNotExist(err) {
		t.Fatalf("database touched before config check: %v", err)
	}
}

func TestNativeHTTPSServerStartsAndServesSecureLogin(t *testing.T) {
	fixture := httptest.NewTLSServer(http.NotFoundHandler())
	pair := fixture.TLS.Certificates[0]
	fixture.Close()
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(pair.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	t.Setenv("NETADMIN_DATA_DIR", dir)
	t.Setenv("NETADMIN_NO_BROWSER", "1")
	for _, name := range []string{"NETADMIN_TLS_CERT", "NETADMIN_TLS_KEY", "NETADMIN_PUBLIC_URL"} {
		t.Setenv(name, "")
	}
	certFile := filepath.Join(dir, "server.crt")
	if err = os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pair.Certificate[0]}), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "server.key"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}), 0600); err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_, port, _ := net.SplitHostPort(addr)
	l.Close()
	t.Setenv("NETADMIN_ADDR", addr)
	publicURL := "https://" + net.JoinHostPort(leaf.DNSNames[0], port)
	cfg := config.Config{AgentToken: "native-tls-test", ListenAddr: addr, TLSCertFile: "server.crt", TLSKeyFile: "server.key", PublicURL: publicURL, BackupIntervalHours: -1}
	if err = config.Save(cfg); err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- serve(false, stop) }()
	defer func() {
		close(stop)
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(4 * time.Second):
			t.Error("HTTPS server failed to stop")
		}
	}()
	// Both editions initialize their databases before listening. Allow the
	// cold SQLite schema setup to finish while other packages run in parallel.
	deadline := time.Now().Add(12 * time.Second)
	for {
		err = checkServerHealthTLS(publicURL+"/healthz", version.Value, os.Getpid(), certFile, addr)
		if err == nil {
			break
		}
		if !time.Now().Before(deadline) {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	dialer := &net.Dialer{Timeout: time.Second}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, addr)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: time.Second}
	resp, err := client.Get(publicURL + "/login")
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("login: HTTP %d", resp.StatusCode)
	}
	found := false
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "csrf" {
			found = true
			if !cookie.Secure {
				t.Fatal("native HTTPS cookie is not Secure")
			}
		}
	}
	if !found {
		t.Fatal("login CSRF cookie missing")
	}
}
