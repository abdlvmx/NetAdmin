package main

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// A torn write would lose the personal token and turn a reboot into a failed
// enrollment. Prepare and sync beside the state before replacing its old copy.
func writeAgentState(path string, s agentState) error {
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".na-state-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
