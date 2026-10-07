package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFailedStateReplacementRetainsPreviousRegistration(t *testing.T) {
	dir := t.TempDir()
	// A directory blocks the final rename after a complete staged write.
	path := filepath.Join(dir, "agent_state.json")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	old := filepath.Join(path, "previous")
	if err := os.WriteFile(old, []byte("previous registration"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeAgentState(path, agentState{DeviceID: 42, DeviceToken: "opaque"}); err == nil {
		t.Fatal("failed replacement reported success")
	}
	b, err := os.ReadFile(old)
	if err != nil || string(b) != "previous registration" {
		t.Fatalf("old registration damaged: %q %v", b, err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("failed write left credential temporary files: %v", entries)
	}
}
