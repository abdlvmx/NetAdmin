package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

func TestServerHealthURLUsesTheServiceListenAddress(t *testing.T) {
	for _, tt := range []struct {
		listen, want string
	}{
		{"", "http://127.0.0.1:8765/healthz"},
		{"0.0.0.0:8765", "http://127.0.0.1:8765/healthz"},
		{":9000", "http://127.0.0.1:9000/healthz"},
		{"[::]:9000", "http://[::1]:9000/healthz"},
		{"127.0.0.1:9001", "http://127.0.0.1:9001/healthz"},
		{"192.168.1.10:9002", "http://192.168.1.10:9002/healthz"},
		{"[fd00::10]:9003", "http://[fd00::10]:9003/healthz"},
		{"localhost:9004", "http://localhost:9004/healthz"},
	} {
		t.Run(tt.listen, func(t *testing.T) {
			got, err := serverHealthURL(tt.listen)
			if err != nil || got != tt.want {
				t.Fatalf("serverHealthURL(%q) = %q, %v; want %q", tt.listen, got, err, tt.want)
			}
		})
	}
}

func TestServerHealthURLRejectsMalformedAddress(t *testing.T) {
	for _, listen := range []string{"not-an-address", "http://127.0.0.1:8765", "127.0.0.1", "[::1]", "127.0.0.1:0", "127.0.0.1:65536", "127.0.0.1:abc"} {
		if got, err := serverHealthURL(listen); err == nil {
			t.Errorf("serverHealthURL(%q) accepted malformed address as %q", listen, got)
		}
	}
}

func TestInstalledServerHealthURLIgnoresInstallerShellOverrides(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("NETADMIN_ADDR", "127.0.0.1:3210")
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{"listen_addr":"192.168.1.10:9002"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := installedServerHealthURL(dir)
	if err != nil || got != "http://192.168.1.10:9002/healthz" {
		t.Fatalf("installed health address = %q, %v; installer shell must not override service config", got, err)
	}
}

func TestInstalledServerHealthURLRejectsCorruptConfiguration(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{"listen_addr":`), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := installedServerHealthURL(dir); err == nil {
		t.Fatalf("corrupt service configuration accepted as %q", got)
	}
}

// Another NetAdmin process answering the same port must not make a failed
// candidate installation look healthy, even when both builds share a version.
func TestCheckServerHealthRequiresReadyBodyVersionAndServiceProcess(t *testing.T) {
	const wantVersion = "1.2.3"
	const wantPID = 456
	for _, tt := range []struct {
		name, version, pid, body string
		status                   int
		wantErr                  bool
	}{
		{"ready", wantVersion, "456", "ok", http.StatusOK, false},
		{"old-process", wantVersion, "123", "ok", http.StatusOK, true},
		{"old-version", "1.2.2", "456", "ok", http.StatusOK, true},
		{"missing-version", "", "456", "ok", http.StatusOK, true},
		{"missing-process", wantVersion, "", "ok", http.StatusOK, true},
		{"invalid-process", wantVersion, "invalid", "ok", http.StatusOK, true},
		{"unready-db", wantVersion, "456", "ok", http.StatusServiceUnavailable, true},
		{"login-page", wantVersion, "456", "<html>login</html>", http.StatusOK, true},
		{"empty-body", wantVersion, "456", "", http.StatusOK, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("X-NetAdmin-Version", tt.version)
				w.Header().Set("X-NetAdmin-PID", tt.pid)
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.body))
			}))
			defer srv.Close()
			err := checkServerHealth(srv.URL+"/healthz", wantVersion, wantPID)
			if (err != nil) != tt.wantErr {
				t.Fatalf("checkServerHealth() = %v, wantErr %t", err, tt.wantErr)
			}
		})
	}
}

func TestCheckServerHealthDoesNotFollowRedirects(t *testing.T) {
	var readyRequests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			http.Redirect(w, r, "/other-instance", http.StatusFound)
			return
		}
		readyRequests.Add(1)
		w.Header().Set("X-NetAdmin-Version", "1.2.3")
		w.Header().Set("X-NetAdmin-PID", "456")
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	if err := checkServerHealth(srv.URL+"/healthz", "1.2.3", 456); err == nil {
		t.Fatal("redirect accepted as candidate readiness")
	}
	if got := readyRequests.Load(); got != 0 {
		t.Fatalf("readiness probe followed redirect %d times", got)
	}
}

func TestCheckServerHealthReportsUnreachableServer(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	u := srv.URL + "/healthz"
	srv.Close()
	if err := checkServerHealth(u, "1.2.3", 456); err == nil {
		t.Fatal("unreachable server accepted as ready")
	}
}
