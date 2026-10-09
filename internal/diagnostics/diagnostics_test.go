package diagnostics

import (
	"archive/zip"
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"netadmin/internal/config"
	"netadmin/internal/db"
)

func testInput(t *testing.T) Input {
	t.Helper()
	dir := t.TempDir()
	d, err := db.Open(filepath.Join(dir, "diagnostic.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.InitSchema(d); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return Input{DB: d, Version: "1.2.3", ConfigState: ConfigOK, DataDir: dir, DBPath: filepath.Join(dir, "diagnostic.db"), BackupIntervalHours: 24}
}

func checkLevel(t *testing.T, r Report, code string) string {
	t.Helper()
	for _, c := range r.Checks {
		if c.Code == code {
			return c.Level
		}
	}
	t.Fatalf("missing check %s", code)
	return ""
}

func archiveFiles(t *testing.T, r Report) map[string]string {
	t.Helper()
	b, err := Archive(r)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) > MaxArchiveBytes {
		t.Fatalf("archive too large: %d", len(b))
	}
	z, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatal(err)
	}
	files := make(map[string]string)
	for _, f := range z.File {
		if f.UncompressedSize64 > MaxArchiveBytes {
			t.Fatal("oversized zip entry")
		}
		fr, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(fr)
		_ = fr.Close()
		if err != nil {
			t.Fatal(err)
		}
		files[f.Name] = string(data)
	}
	if len(files) != 3 || files["summary.json"] == "" || files["checks.json"] == "" || files["README.txt"] == "" {
		t.Fatalf("unexpected files: %v", files)
	}
	return files
}

func TestCollectExportsCountsAndNoSensitiveData(t *testing.T) {
	in := testInput(t)
	secret := "never-export-secret-password"
	_, err := in.DB.Exec(`INSERT INTO devices(hostname,ip_address,agent_token,last_seen,status) VALUES
		(?,?,?,datetime('now'),'offline'), (?,?,?,datetime('now','-1 hour'),'online')`, secret, "192.168.47.123", secret, secret, "192.168.47.124", secret+"2")
	if err != nil {
		t.Fatal(err)
	}
	_, err = in.DB.Exec(`INSERT INTO agent_tasks(device_id,kind,payload,label,status,result,created_at,done_at) VALUES
		(1,'command',?,?,'failed',?,datetime('now'),datetime('now')),
		(1,'command',?,?,'failed',?,datetime('now','-2 days'),datetime('now','-2 days')),
		(1,'command',?,?,'pending',?,datetime('now'),NULL)`, secret, secret, secret, secret, secret, secret, secret, secret, secret)
	if err != nil {
		t.Fatal(err)
	}
	in.Listen = config.NetworkSetting{Value: "192.168.47.123:8765", Source: config.SourceConfig}
	in.Allow = config.NetworkSetting{Value: "192.168.47.0/24", Source: config.SourceEnv}
	in.IsService = true
	r := Collect(context.Background(), in)
	if !r.Summary.Agents.Known || r.Summary.Agents.Total != 2 || r.Summary.Agents.Online != 1 {
		t.Fatalf("agents: %+v", r.Summary.Agents)
	}
	if !r.Summary.Tasks.Known || r.Summary.Tasks.FailedLast24Hours != 1 || r.Summary.Tasks.Pending != 1 {
		t.Fatalf("tasks: %+v", r.Summary.Tasks)
	}
	if r.Summary.Mode != "service" || !r.Summary.DatabaseAvailable || checkLevel(t, r, "agents") != "warning" {
		t.Fatalf("report: %+v", r)
	}
	for name, data := range archiveFiles(t, r) {
		for _, private := range []string{secret, "192.168.47.", in.DataDir, "agent_token", "payload", "ip_address"} {
			if strings.Contains(data, private) {
				t.Fatalf("%s contains private value %q", name, private)
			}
		}
	}
}

func TestUnavailableDatabaseDoesNotInventZeroCounts(t *testing.T) {
	in := testInput(t)
	_ = in.DB.Close()
	r := Collect(context.Background(), in)
	if r.Summary.DatabaseAvailable || r.Summary.Agents.Known || r.Summary.Tasks.Known {
		t.Fatalf("unavailable database appears healthy: %+v", r.Summary)
	}
	if checkLevel(t, r, "database") != "error" || checkLevel(t, r, "agents") != "unknown" || checkLevel(t, r, "tasks") != "unknown" {
		t.Fatal("missing unavailable states")
	}
	archiveFiles(t, r)
}

func TestNetworkErrorsAndValuesNeverExported(t *testing.T) {
	in := testInput(t)
	secret := "a-sensitive-value@private-host"
	in.Listen = config.NetworkSetting{Value: secret + ":password", Source: secret}
	in.Allow = config.NetworkSetting{Value: secret, Source: secret}
	in.Version = secret
	r := Collect(context.Background(), in)
	if r.Summary.Network.ListenValid || r.Summary.Network.AllowValid || r.Summary.Version != "unknown" {
		t.Fatalf("invalid input: %+v", r.Summary)
	}
	if checkLevel(t, r, "listen") != "error" || checkLevel(t, r, "access") != "error" {
		t.Fatal("invalid network was not detected")
	}
	for _, data := range archiveFiles(t, r) {
		if strings.Contains(data, secret) {
			t.Fatal("network parse error leaked input")
		}
	}
	in.Allow.Value = "any"
	in.Listen.Value = "127.0.0.1:8765"
	r = Collect(context.Background(), in)
	if checkLevel(t, r, "access") != "warning" || r.Summary.Network.ListenScope != "loopback" {
		t.Fatal("missing access guidance")
	}
	in.Allow.Value = strings.Repeat("x", maxNetworkBytes+1)
	r = Collect(context.Background(), in)
	if r.Summary.Network.AllowValid {
		t.Fatal("oversized rule accepted")
	}
}

func TestBackupReadOnlyFreshnessAndPendingRestore(t *testing.T) {
	in := testInput(t)
	backupDir := filepath.Join(in.DataDir, "backups")
	r := Collect(context.Background(), in)
	if _, err := os.Stat(backupDir); !os.IsNotExist(err) {
		t.Fatal("diagnostics created backup directory")
	}
	if checkLevel(t, r, "backups") != "info" {
		t.Fatal("missing initial copy guidance")
	}
	if err := os.Mkdir(backupDir, 0700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(backupDir, "netadmin-2026-01-01-1200.db")
	if err := os.WriteFile(p, []byte("contents-not-read"), 0600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-72 * time.Hour)
	if err := os.Chtimes(p, old, old); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(in.DBPath+".restore", []byte("secret-backup"), 0600); err != nil {
		t.Fatal(err)
	}
	r = Collect(context.Background(), in)
	if r.Summary.Backup.Count != 1 || !r.Summary.Backup.PendingRestore || checkLevel(t, r, "backups") != "warning" {
		t.Fatalf("backup snapshot: %+v", r.Summary.Backup)
	}
	if checkLevel(t, r, "restore") != "warning" {
		t.Fatal("missing pending restore warning")
	}
	now := time.Now()
	if err := os.Chtimes(p, now, now); err != nil {
		t.Fatal(err)
	}
	r = Collect(context.Background(), in)
	if checkLevel(t, r, "backups") != "ok" {
		t.Fatal("fresh backup not recognised")
	}
	// Empty files and unrelated files must not produce a reassuring count.
	if err := os.WriteFile(filepath.Join(backupDir, "netadmin-2026-01-02-1200.db"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(backupDir, "private-secret.db"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	r = Collect(context.Background(), in)
	if r.Summary.Backup.Count != 1 {
		t.Fatalf("unexpected copies: %d", r.Summary.Backup.Count)
	}
}

func TestBackupListingLimitReturnsUnknown(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"a", "b", "c"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	count, latest, limited, err := scanBackups(dir, 2)
	if err != nil || !limited || count != 0 || !latest.IsZero() {
		t.Fatalf("bounded listing: %d %v %t %v", count, latest, limited, err)
	}
}

func TestArchiveRejectsOversizedDataBeforeCompression(t *testing.T) {
	r := Report{Checks: make([]Check, 33)}
	if _, err := Archive(r); err == nil {
		t.Fatal("too many checks accepted")
	}
	r.Checks = []Check{{Detail: strings.Repeat("x", MaxArchiveBytes+1)}}
	if _, err := Archive(r); err == nil {
		t.Fatal("oversized check accepted")
	}
	r.Checks = nil
	r.Summary.Version = strings.Repeat("x", 65)
	if _, err := Archive(r); err == nil {
		t.Fatal("oversized metadata accepted")
	}
}

func TestCancelledContextAndInvalidConfigRemainUnknown(t *testing.T) {
	in := testInput(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	in.ConfigState = ConfigInvalid
	r := Collect(ctx, in)
	if r.Summary.DatabaseAvailable || r.Summary.Agents.Known || r.Summary.Backup.Known || r.Summary.Network.AllowValid {
		t.Fatalf("invented success: %+v", r.Summary)
	}
	if r.UncheckedCount() < 4 || checkLevel(t, r, "configuration") != "error" {
		t.Fatal("missing unknown checks")
	}
}
