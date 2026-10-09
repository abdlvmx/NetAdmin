package handlers

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"netadmin/internal/auth"
	"netadmin/internal/config"
	"netadmin/internal/diagnostics"
)

func diagnosticRequest(t *testing.T, a *App, role string, handler http.HandlerFunc) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/diagnostics/archive?path=../../config.json&include=logs", nil)
	if role != "" {
		res, err := a.DB.Exec(`INSERT INTO users(username,password_hash,role,is_active) VALUES (?,'unused',?,1)`, "diagnostic-"+role, role)
		if err != nil {
			t.Fatal(err)
		}
		id, _ := res.LastInsertId()
		token, err := auth.CreateSession(a.DB, id)
		if err != nil {
			t.Fatal(err)
		}
		req.AddCookie(&http.Cookie{Name: "session", Value: token})
	}
	req.Header.Set("Authorization", "Bearer request-secret")
	rec := httptest.NewRecorder()
	handler(rec, req)
	return rec
}

func TestDiagnosticArchiveAdministratorOnly(t *testing.T) {
	for _, role := range []string{"", "viewer", "user", "admin"} {
		t.Run(role, func(t *testing.T) {
			a := newTestApp(t)
			rec := diagnosticRequest(t, a, role, a.DiagnosticsArchive)
			want := http.StatusForbidden
			if role == "admin" {
				want = http.StatusOK
			}
			if rec.Code != want {
				t.Fatalf("got %d, want %d: %s", rec.Code, want, rec.Body.String())
			}
			if rec.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("archive can be cached")
			}
			if role == "admin" && (rec.Header().Get("Content-Type") != "application/zip" || !strings.Contains(rec.Header().Get("Content-Disposition"), "attachment")) {
				t.Fatal("missing download headers")
			}
		})
	}
}

func TestDiagnosticPageAdministratorOnly(t *testing.T) {
	for _, role := range []string{"", "viewer", "user"} {
		a := newTestApp(t)
		if rec := diagnosticRequest(t, a, role, a.DiagnosticsPage); rec.Code != http.StatusForbidden {
			t.Fatalf("%s: %d", role, rec.Code)
		}
	}
}

func TestDiagnosticRoutesAndPageRender(t *testing.T) {
	for _, path := range []string{"/settings/diagnostics", "/api/diagnostics/archive"} {
		for _, role := range []string{"", "viewer", "user", "admin"} {
			t.Run(path+"/"+role, func(t *testing.T) {
				a := newTestApp(t)
				routes := a.Routes()
				rec := diagnosticRequest(t, a, role, func(w http.ResponseWriter, r *http.Request) {
					r.URL.Path = path
					r.RemoteAddr = "127.0.0.1:65432"
					routes.ServeHTTP(w, r)
				})
				want := http.StatusForbidden
				if role == "admin" {
					want = http.StatusOK
				}
				if rec.Code != want {
					t.Fatalf("got %d, want %d: %s", rec.Code, want, rec.Body.String())
				}
				if path == "/settings/diagnostics" && role == "admin" {
					body := rec.Body.String()
					for _, text := range []string{"Следующий шаг:", "Скачать архив диагностики", "База данных отвечает", "Компьютеры ещё не подключены"} {
						if !strings.Contains(body, text) {
							t.Errorf("missing page content: %s", text)
						}
					}
					if strings.Contains(body, "template error") {
						t.Fatal("diagnostics template error")
					}
				}
			})
		}
	}
}

func TestDiagnosticArchiveDoesNotExportInjectedSecrets(t *testing.T) {
	a := newTestApp(t)
	t.Setenv("NETADMIN_ADDR", "127.0.0.1:12345")
	t.Setenv("NETADMIN_ALLOW", "192.168.87.0/24")
	t.Setenv("UNRELATED_DIAGNOSTIC_SECRET", "environment-secret")
	secret := "do-not-export-credential"
	data := []byte(`{"agent_token":"` + secret + `","smtp_pass":"smtp-secret","organization_name":"private-organisation","smtp_user":"private@example.test","listen_addr":"10.76.54.32:8765","allow_subnets":"10.76.54.0/24","backup_interval_hours":24,"backup_keep":7}`)
	if err := os.WriteFile(config.ConfigPath(), data, 0600); err != nil {
		t.Fatal(err)
	}
	_, err := a.DB.Exec(`INSERT INTO devices(hostname,ip_address,agent_token,last_seen) VALUES(?,?,?,datetime('now'))`, "private-device", "192.168.87.44", secret)
	if err != nil {
		t.Fatal(err)
	}
	_, err = a.DB.Exec(`INSERT INTO agent_tasks(device_id,status,result,payload,label,created_at,done_at) VALUES(1,'failed',?,?,?,datetime('now'),datetime('now'))`, "command-output-secret", "command-payload-secret", "private-label")
	if err != nil {
		t.Fatal(err)
	}
	rec := diagnosticRequest(t, a, "admin", a.DiagnosticsArchive)
	if rec.Code != 200 {
		t.Fatalf("%d: %s", rec.Code, rec.Body.String())
	}
	z, err := zip.NewReader(bytes.NewReader(rec.Body.Bytes()), int64(rec.Body.Len()))
	if err != nil {
		t.Fatal(err)
	}
	if len(z.File) != 3 || rec.Body.Len() > diagnostics.MaxArchiveBytes {
		t.Fatal("archive allowlist/limit broken")
	}
	for _, f := range z.File {
		fr, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(fr)
		_ = fr.Close()
		if err != nil {
			t.Fatal(err)
		}
		for _, value := range []string{secret, "smtp-secret", "private-organisation", "private@example.test", "10.76.54.", "192.168.87.", "private-device", "command-output-secret", "command-payload-secret", "private-label", "request-secret", "environment-secret", config.DataDir()} {
			if bytes.Contains(b, []byte(value)) {
				t.Fatalf("%s leaked %q", f.Name, value)
			}
		}
	}
	after, err := os.ReadFile(config.ConfigPath())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, after) {
		t.Fatal("diagnostic read changed configuration")
	}
}

func TestReadDiagnosticConfigMissingMalformedAndBounded(t *testing.T) {
	a := newTestApp(t)
	_ = a
	_ = os.Remove(config.ConfigPath())
	cfg, state := readDiagnosticConfig()
	if state != diagnostics.ConfigMissing || cfg.BackupIntervalHours != 24 {
		t.Fatalf("missing config: %s %+v", state, cfg)
	}
	if _, err := os.Stat(config.ConfigPath()); !os.IsNotExist(err) {
		t.Fatal("reader created configuration")
	}
	for _, data := range []string{"{broken", "null", `{"listen_addr":"x"} {}`, strings.Repeat("x", maxDiagnosticConfigBytes+1)} {
		if err := os.WriteFile(config.ConfigPath(), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		_, state = readDiagnosticConfig()
		if state != diagnostics.ConfigInvalid {
			t.Fatalf("malformed config classified as %s", state)
		}
	}
	if err := os.WriteFile(config.ConfigPath(), []byte(`{"agent_token":"secret","smtp_pass":"secret","backup_interval_hours":0,"backup_keep":7}`), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, state = readDiagnosticConfig()
	if state != diagnostics.ConfigOK || cfg.AgentToken != "" || cfg.SMTPPass != "" || cfg.BackupIntervalHours != 0 {
		t.Fatalf("reader escaped allowlist: %s %+v", state, cfg)
	}
}

func TestConfigurationUsesSharedBoundedFilesystemGate(t *testing.T) {
	a := newTestApp(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	var released sync.Once
	defer released.Do(func() { close(release) })
	done := make(chan error, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	go func() {
		_, err := diagnostics.Filesystem(ctx, func() (int, error) { close(entered); <-release; return 0, nil })
		done <- err
	}()
	<-entered
	if err := <-done; !errors.Is(err, diagnostics.ErrFilesystemTimeout) {
		t.Fatalf("fake filesystem worker: %v", err)
	}
	start := time.Now()
	cfg, state := readDiagnosticConfigContext(context.Background())
	if state != diagnostics.ConfigBusy || cfg.AgentToken != "" || time.Since(start) > time.Second {
		t.Fatalf("config gate: state=%s cfg=%+v elapsed=%v", state, cfg, time.Since(start))
	}
	r := a.diagnosticReport(httptest.NewRequest(http.MethodGet, "/settings/diagnostics", nil))
	if r.Summary.Backup.Known || r.UncheckedCount() < 4 {
		t.Fatalf("blocked files look healthy: %+v", r)
	}
	for _, check := range r.Checks {
		if check.Code == "configuration" && check.Level != "unknown" {
			t.Fatalf("busy config check: %+v", check)
		}
	}
	released.Do(func() { close(release) })
	deadline := time.Now().Add(time.Second)
	for state == diagnostics.ConfigBusy && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
		_, state = readDiagnosticConfigContext(context.Background())
	}
	if state != diagnostics.ConfigMissing {
		t.Fatalf("config reader did not recover: %s", state)
	}
	ctx, cancelled := context.WithCancel(context.Background())
	cancelled()
	_, state = readDiagnosticConfigContext(ctx)
	if state != diagnostics.ConfigTimeout {
		t.Fatalf("cancelled reader: %s", state)
	}
}
