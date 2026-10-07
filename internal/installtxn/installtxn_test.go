package installtxn

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, path, text string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
}

func contents(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func installedEntries(t *testing.T, dir string) []os.DirEntry {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	filtered := entries[:0]
	for _, e := range entries {
		if e.Name() != ".netadmin-install.lock" {
			filtered = append(filtered, e)
		}
	}
	return filtered
}

func TestStageFailureLeavesRunningInstallationUntouched(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "agent.exe")
	write(t, exe, "old")
	stopped := false
	err := Apply([]File{{Path: exe, Source: filepath.Join(dir, "missing")}}, Hooks{Stop: func() error { stopped = true; return nil }})
	if err == nil || stopped || contents(t, exe) != "old" {
		t.Fatalf("staging failure touched old installation: %v, stopped=%v", err, stopped)
	}
	entries := installedEntries(t, dir)
	if len(entries) != 1 {
		t.Fatalf("staging left temporary files: %v", entries)
	}
}

func TestFailedHealthRestoresBinaryIdentityAndStartupMutations(t *testing.T) {
	dir := t.TempDir()
	exe, state := filepath.Join(dir, "agent.exe"), filepath.Join(dir, "agent_state.json")
	config, newDB := filepath.Join(dir, "config.json"), filepath.Join(dir, "new.db")
	write(t, exe, "old binary")
	write(t, state, "old identity")
	write(t, config, "old config")
	stops, recovered := 0, false
	err := Apply([]File{
		{Path: exe, Data: []byte("candidate")},
		{Path: state, Snapshot: true},
		{Path: config, Data: []byte("new config")},
		{Path: newDB, Snapshot: true},
	}, Hooks{
		Stop: func() error { stops++; return nil },
		Start: func() error {
			write(t, state, "candidate identity")
			write(t, config, "token cleared by candidate")
			write(t, newDB, "created on startup")
			return nil
		},
		Verify: func() error { return errors.New("heartbeat rejected") },
		Recover: func() error {
			recovered = true
			if contents(t, exe) != "old binary" || contents(t, state) != "old identity" || contents(t, config) != "old config" {
				t.Fatal("service recovered before files restored")
			}
			return nil
		},
	})
	if err == nil || !strings.Contains(err.Error(), "heartbeat rejected") || !recovered || stops != 2 {
		t.Fatalf("failed rollback: %v, recovered=%v stops=%d", err, recovered, stops)
	}
	if _, err := os.Stat(newDB); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("candidate-created file survived rollback: %v", err)
	}
	entries := installedEntries(t, dir)
	if len(entries) != 3 {
		t.Fatalf("rollback left temporary files: %v", entries)
	}
}

func TestFailureHalfwayThroughReplacementRestoresAlreadyChangedFiles(t *testing.T) {
	dir := t.TempDir()
	one, two := filepath.Join(dir, "one"), filepath.Join(dir, "two")
	write(t, one, "old")
	if err := os.Mkdir(two, 0o700); err != nil {
		t.Fatal(err)
	}
	recovered := false
	err := Apply([]File{{Path: one, Data: []byte("new")}, {Path: two, Remove: true}}, Hooks{Recover: func() error { recovered = true; return nil }})
	if err == nil || !recovered || contents(t, one) != "old" {
		t.Fatalf("partial replacement did not roll back: %v", err)
	}
}

func TestRollbackNeverOverwritesFilesOfAServiceThatCannotStop(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "agent.exe")
	write(t, exe, "old")
	stops, recovered := 0, false
	err := Apply([]File{{Path: exe, Data: []byte("candidate")}}, Hooks{
		Stop: func() error {
			stops++
			if stops == 2 {
				return errors.New("still running")
			}
			return nil
		},
		Verify:  func() error { return errors.New("no heartbeat") },
		Recover: func() error { recovered = true; return nil },
	})
	if err == nil || !strings.Contains(err.Error(), "still running") || recovered || contents(t, exe) != "candidate" {
		t.Fatalf("unsafe rollback: %v", err)
	}
	entries := installedEntries(t, dir)
	found := false
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".na-rollback-") && contents(t, filepath.Join(dir, e.Name())) == "old" {
			found = true
		}
	}
	if !found {
		t.Fatal("previous binary lost after failed stop")
	}
}

func TestCommitRetainsCandidateAndRemovesOnlyRequestedFile(t *testing.T) {
	dir := t.TempDir()
	exe, identity := filepath.Join(dir, "agent.exe"), filepath.Join(dir, "state")
	write(t, exe, "old")
	write(t, identity, "old identity")
	err := Apply([]File{{Path: exe, Data: []byte("candidate")}, {Path: identity, Remove: true}}, Hooks{Verify: func() error {
		if contents(t, exe) != "candidate" {
			t.Fatal("not activated")
		}
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	entries := installedEntries(t, dir)
	if len(entries) != 1 || entries[0].Name() != "agent.exe" {
		t.Fatalf("commit did not clean backups: %v", entries)
	}
}

func TestConcurrentInstallCannotStopOrReplaceAnotherCandidate(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "agent.exe")
	write(t, exe, "old")
	err := Apply([]File{{Path: exe, Data: []byte("first")}}, Hooks{Verify: func() error {
		stopped := false
		err := Apply([]File{{Path: exe, Data: []byte("second")}}, Hooks{Stop: func() error { stopped = true; return nil }})
		if err == nil || stopped || contents(t, exe) != "first" {
			t.Fatalf("concurrent install interrupted candidate: %v, stopped=%v", err, stopped)
		}
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	// Closing the transaction must release the lock for the next operation.
	if err := Apply([]File{{Path: exe, Data: []byte("next")}}, Hooks{}); err != nil {
		t.Fatal(err)
	}
}
