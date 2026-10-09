package edition

import (
	"os"
	"path/filepath"
	"runtime/debug"
	"testing"
)

func TestParseBuildInfoRecognizesExactEditionTag(t *testing.T) {
	for _, test := range []struct {
		tags string
		want string
	}{
		{"", "standard"},
		{"other", "standard"},
		{"securityevents", "events"},
		{"other,securityevents", "events"},
		{"other securityevents extra", "events"},
		{"other\tsecurityevents\nextra", "events"},
		{"securityevents_extra", "standard"},
		{"SecurityEvents", "standard"},
	} {
		got, err := ParseBuildInfo(&debug.BuildInfo{GoVersion: "go1.26.6", Settings: []debug.BuildSetting{{Key: "-tags", Value: test.tags}}})
		if err != nil || got != test.want {
			t.Fatalf("tags %q: got %q error %v, want %q", test.tags, got, err, test.want)
		}
	}
	got, err := ParseBuildInfo(&debug.BuildInfo{GoVersion: "go1.20"})
	if err != nil || got != "standard" {
		t.Fatalf("older standard metadata: %q %v", got, err)
	}
}

func TestParseBuildInfoRejectsUnknownAndAmbiguousMetadata(t *testing.T) {
	for _, info := range []*debug.BuildInfo{nil, {}, {GoVersion: "not-go"}, {GoVersion: "go1.26.6", Settings: []debug.BuildSetting{{Key: "-tags", Value: ""}, {Key: "-tags", Value: "securityevents"}}}} {
		if id, err := ParseBuildInfo(info); err == nil || id != "" {
			t.Fatalf("unknown metadata implied edition %q: %+v", id, info)
		}
	}
}

func TestReadBinaryRejectsUnknownFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "unknown.exe")
	if err := os.WriteFile(path, []byte("not a Go executable"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, candidate := range []string{path, path + ".missing"} {
		if id, err := ReadBinary(candidate); err == nil || id != "" {
			t.Fatalf("unreadable candidate implied edition %q: %v", id, err)
		}
	}
}

func TestReadBinaryRecognizesActualTestBinary(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	id, err := ReadBinary(exe)
	if err != nil || id != ID {
		t.Fatalf("actual binary edition=%q want=%q: %v", id, ID, err)
	}
}
