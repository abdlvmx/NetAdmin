package main

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"netadmin/internal/db"
	"netadmin/internal/installtxn"
)

// A new build can change the schema before failing to bind its HTTP port.
// Restoring only the EXE would then leave the old service with migrated data.
func TestServerInstallRollbackRestoresDatabaseBeforeRestartingOldBuild(t *testing.T) {
	dir := t.TempDir()
	dbPath, configPath := filepath.Join(dir, "netadmin.db"), filepath.Join(dir, "config.json")
	original, err := db.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := original.Exec("CREATE TABLE installation_test(value TEXT); INSERT INTO installation_test VALUES('before')"); err != nil {
		original.Close()
		t.Fatal(err)
	}
	if err := original.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte("original config"), 0o600); err != nil {
		t.Fatal(err)
	}
	var candidate *sql.DB
	t.Cleanup(func() {
		if candidate != nil {
			candidate.Close()
		}
	})
	failed, recovered, stops := errors.New("candidate HTTP port unavailable"), false, 0
	files := []installtxn.File{}
	for _, name := range []string{"netadmin.db", "netadmin.db-wal", "netadmin.db-shm", "config.json"} {
		files = append(files, installtxn.File{Path: filepath.Join(dir, name), Snapshot: true})
	}
	err = installtxn.Apply(files, installtxn.Hooks{
		Stop: func() error {
			stops++
			if candidate != nil {
				err := candidate.Close()
				candidate = nil
				return err
			}
			return nil
		},
		Start: func() error {
			var err error
			candidate, err = db.Open(dbPath)
			if err != nil {
				return err
			}
			if _, err := candidate.Exec("ALTER TABLE installation_test ADD COLUMN candidate_column TEXT; UPDATE installation_test SET value='after'"); err != nil {
				return err
			}
			return os.WriteFile(configPath, []byte("candidate config"), 0o600)
		},
		Verify: func() error { return failed },
		Recover: func() error {
			restored, err := db.Open(dbPath)
			if err != nil {
				return err
			}
			defer restored.Close()
			var value string
			if err := restored.QueryRow("SELECT value FROM installation_test").Scan(&value); err != nil {
				return err
			}
			if value != "before" {
				return fmt.Errorf("old service restarted with candidate data: %q", value)
			}
			var candidateColumns int
			if err := restored.QueryRow("SELECT COUNT(*) FROM pragma_table_info('installation_test') WHERE name='candidate_column'").Scan(&candidateColumns); err != nil {
				return err
			}
			if candidateColumns != 0 {
				return errors.New("candidate schema survived rollback")
			}
			config, err := os.ReadFile(configPath)
			if err != nil || string(config) != "original config" {
				return fmt.Errorf("configuration not restored: %q, %v", config, err)
			}
			recovered = true
			return nil
		},
	})
	if !errors.Is(err, failed) || !recovered || stops != 2 {
		t.Fatalf("server rollback = %v, recovered=%t stops=%d", err, recovered, stops)
	}
}
