package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestInstallationGuardRejectsUnsnapshottedDataDirectory(t *testing.T) {
	dir, expected, actual := t.TempDir(), t.TempDir(), t.TempDir()
	b, _ := json.Marshal(struct {
		DataDir string `json:"data_dir"`
	}{expected})
	if err := os.WriteFile(filepath.Join(dir, serverInstallGuardName), b, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := checkServerInstallDataDir(dir, actual); err == nil {
		t.Fatal("candidate permitted to mutate unsnapshotted database")
	}
	if err := checkServerInstallDataDir(dir, expected); err != nil {
		t.Fatal(err)
	}
}

func TestServerDataDirectoryUsesServiceSettingWithoutShellOverrides(t *testing.T) {
	installed, external := t.TempDir(), t.TempDir()
	t.Setenv("NETADMIN_DATA_DIR", t.TempDir())
	for _, tt := range []struct{ setting, want string }{{"", installed}, {external, external}} {
		got, err := serverDataDir(installed, tt.setting)
		if err != nil || got != tt.want {
			t.Fatalf("data dir %q: %q %v", tt.setting, got, err)
		}
	}
	if _, err := serverDataDir(installed, "relative-folder"); err == nil {
		t.Fatal("relative service directory accepted")
	}
}
