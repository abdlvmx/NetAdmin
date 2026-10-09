//go:build securityevents

package securityevents

import (
	"context"
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestEventsBackupRoundTripPreservesInvestigationAndDisablesConsent(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)
	p := enabledStorePolicy(t, s, 1, "system")
	if err := s.AcceptBatch(ctx, 1, "personal-token", validStoreBatch(p)); err != nil {
		t.Fatal(err)
	}
	f := allFindings(t, s)[0]
	if err := s.UpdateFinding(ctx, f.ID, f.Revision, "in_progress", 7, "Заметка расследования", "admin"); err != nil {
		t.Fatal(err)
	}
	if err := s.AddException(ctx, Exception{RuleID: "service_installed", Scope: "service", Value: "Allowed", Reason: "Обновление", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "copies")
	copy, err := s.CreateBackup(ctx, dir, 7)
	if err != nil {
		t.Fatal(err)
	}
	path, err := BackupPath(dir, copy.Name)
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	second := validStoreBatch(p)
	second.ID = strings.Repeat("c", 32)
	second.Events[0].RecordID++
	if err = s.AcceptBatch(ctx, 1, "personal-token", second); err != nil {
		t.Fatal(err)
	}
	if err = s.StageRestore(ctx, dir, copy.Name); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(path)
	if sha256.Sum256(before) != sha256.Sum256(after) {
		t.Fatal("selected backup was modified")
	}
	if !PendingRestore(s.path) {
		t.Fatal("restore not staged")
	}
	if tableCount(t, s, "events_records") != 2 {
		t.Fatal("staging changed live database")
	}
	live := s.path
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	saved, err := ApplyRestore(ctx, live)
	if err != nil || saved == "" {
		t.Fatalf("apply: %s %v", saved, err)
	}
	if _, err = os.Stat(saved); err != nil {
		t.Fatal("previous database missing", err)
	}
	if PendingRestore(live) {
		t.Fatal("pending not consumed")
	}
	recovered, err := Open(live)
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close()
	if tableCount(t, recovered, "events_records") != 1 {
		t.Fatal("records not restored")
	}
	details, err := recovered.Finding(ctx, f.ID)
	if err != nil || details.Status != "in_progress" || details.AssigneeID != 7 || len(details.Comments) != 1 || details.Comments[0].Text != "Заметка расследования" || len(details.Evidence) != 1 {
		t.Fatalf("investigation not restored: %+v %v", details, err)
	}
	if tableCount(t, recovered, "events_rule_exceptions") != 1 {
		t.Fatal("exceptions lost")
	}
	rules, err := recovered.Rules(ctx)
	if err != nil || len(rules) != 3 {
		t.Fatal("rules lost", err)
	}
	q, err := recovered.Policy(ctx, 1, "personal-token")
	if err != nil || q.Enabled || q.Generation == p.Generation {
		t.Fatalf("stale consent restored: %+v %v", q, err)
	}
	status, err := recovered.GetStatus(ctx, 1)
	if err != nil || !status.LastReceived.IsZero() || !status.LastContact.IsZero() {
		t.Fatalf("stale health restored: %+v %v", status, err)
	}
	if err = recovered.AcceptBatch(ctx, 1, "personal-token", second); err != ErrDisabled {
		t.Fatalf("old queue accepted after restore: %v", err)
	}
}

func TestEventsBackupRotationCancellationAndUnrelatedFiles(t *testing.T) {
	s := openTestStore(t)
	dir := t.TempDir()
	ctx := context.Background()
	other := filepath.Join(dir, "keep-me.db")
	if err := os.WriteFile(other, []byte("other"), 0600); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		if _, err := s.CreateBackup(ctx, dir, 2); err != nil {
			t.Fatal(err)
		}
	}
	list, err := ListBackups(dir)
	if err != nil || len(list) != 2 {
		t.Fatalf("rotation %+v %v", list, err)
	}
	if _, err = os.Stat(other); err != nil {
		t.Fatal("rotation removed unrelated file")
	}
	if _, err = BackupPath(dir, "../keep-me.db"); err == nil {
		t.Fatal("path traversal accepted")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err = s.CreateBackup(cancelled, dir, 1); err == nil {
		t.Fatal("cancelled snapshot succeeded")
	}
	list, _ = ListBackups(dir)
	if len(list) != 2 {
		t.Fatal("failed snapshot pruned existing backups")
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Fatal("partial snapshot left behind")
		}
	}
}

func TestEventsRestoreRejectsDamageAndPreservesOriginalAndPending(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	dir := t.TempDir()
	copy, err := s.CreateBackup(ctx, dir, 7)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.StageRestore(ctx, dir, copy.Name); err != nil {
		t.Fatal(err)
	}
	path := s.path
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	if err = os.WriteFile(path+".restore", []byte("truncated sqlite"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = ApplyRestore(ctx, path); err == nil {
		t.Fatal("damaged restore applied")
	}
	after, _ := os.ReadFile(path)
	if sha256.Sum256(before) != sha256.Sum256(after) {
		t.Fatal("failed restore changed live database")
	}
	if !PendingRestore(path) {
		t.Fatal("failed restore silently discarded")
	}
	if err = s.CancelRestore(); err != nil || PendingRestore(path) {
		t.Fatal("cancel failed", err)
	}
	if _, err = ApplyRestore(ctx, path); err != nil {
		t.Fatal("restart without restore", err)
	}
}

func TestEventsBackupRejectsForeignFutureAndIncompleteSchema(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	dir := t.TempDir()
	copy, err := s.CreateBackup(ctx, dir, 7)
	if err != nil {
		t.Fatal(err)
	}
	path, err := BackupPath(dir, copy.Name)
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{`PRAGMA application_id=0`, `PRAGMA application_id=1312900438; PRAGMA user_version=99`, `PRAGMA user_version=1; DROP TABLE events_finding_comments`} {
		d, err := openBackup(path, false)
		if err != nil {
			t.Fatal(err)
		}
		_, err = d.Exec(statement)
		d.Close()
		if err != nil {
			t.Fatal(err)
		}
		if err = VerifyBackup(ctx, path); err == nil {
			t.Fatalf("invalid backup accepted: %s", statement)
		}
		if err = s.StageRestore(ctx, dir, copy.Name); err == nil {
			t.Fatal("invalid backup staged")
		}
	}
}

func TestEventsRestorePreservesOldSidecars(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	dir := t.TempDir()
	copy, err := s.CreateBackup(ctx, dir, 7)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.StageRestore(ctx, dir, copy.Name); err != nil {
		t.Fatal(err)
	}
	path := s.path
	s.Close()
	for _, suffix := range []string{"-wal", "-shm"} {
		if err = os.WriteFile(path+suffix, []byte("original"+suffix), 0600); err != nil {
			t.Fatal(err)
		}
	}
	saved, err := ApplyRestore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		data, err := os.ReadFile(saved + suffix)
		if err != nil || string(data) != "original"+suffix {
			t.Fatal("old sidecar not preserved", suffix, err)
		}
		if _, err = os.Stat(path + suffix); !os.IsNotExist(err) {
			t.Fatal("old sidecar remained beside restored database")
		}
	}
}

func TestEventsRestoreRollsBackIfOriginalSidecarCannotBeMoved(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	dir := t.TempDir()
	copy, err := s.CreateBackup(ctx, dir, 7)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.StageRestore(ctx, dir, copy.Name); err != nil {
		t.Fatal(err)
	}
	path := s.path
	s.Close()
	before, _ := os.ReadFile(path)
	if err = os.Mkdir(path+"-wal", 0700); err != nil {
		t.Fatal(err)
	}
	if _, err = ApplyRestore(ctx, path); err == nil {
		t.Fatal("replacement proceeded despite invalid sidecar")
	}
	after, err := os.ReadFile(path)
	if err != nil || sha256.Sum256(before) != sha256.Sum256(after) {
		t.Fatal("original database not rolled back", err)
	}
	if !PendingRestore(path) {
		t.Fatal("pending file lost after failed replacement")
	}
}

func TestEventsOpenRejectsFutureFormatWithoutChangingIt(t *testing.T) {
	s := openTestStore(t)
	path := s.path
	s.Close()
	d, err := openBackup(path, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.Exec(`PRAGMA user_version=99`); err != nil {
		t.Fatal(err)
	}
	d.Close()
	before, _ := os.ReadFile(path)
	if newer, err := Open(path); err == nil {
		newer.Close()
		t.Fatal("future format opened")
	}
	after, _ := os.ReadFile(path)
	if sha256.Sum256(before) != sha256.Sum256(after) {
		t.Fatal("future database modified on rejection")
	}
}
