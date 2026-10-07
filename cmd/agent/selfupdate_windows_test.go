//go:build windows

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAgentUpdateConfirmsNewServiceBeforeCommit(t *testing.T) {
	dir, candidate, originals := updateFixture(t)
	stops, starts := 0, 0
	before := time.Now()
	err := applyAgentUpdate(dir, candidate, updateServiceOps{
		stop: func() error { stops++; return nil },
		start: func() error {
			starts++
			if got := updateFile(t, dir, "agent.exe"); got != "new binary" {
				t.Fatalf("service started from %q", got)
			}
			writeUpdateFile(t, dir, "agent_state.json", "new state")
			writeUpdateFile(t, dir, "agent_status.json", "fresh heartbeat")
			return nil
		},
		verify: func(since time.Time) error {
			if since.Before(before) || starts != 1 || updateFile(t, dir, "agent_status.json") != "fresh heartbeat" {
				t.Fatal("verification did not follow service start")
			}
			// Backup must still exist until verification succeeds.
			copies, _ := filepath.Glob(filepath.Join(dir, ".na-rollback-*"))
			if len(copies) == 0 {
				t.Fatal("old binary was discarded before verification")
			}
			return nil
		},
	})
	if err != nil || stops != 1 || starts != 1 {
		t.Fatalf("update=%v, stops=%d, starts=%d", err, stops, starts)
	}
	if updateFile(t, dir, "agent_state.json") != "new state" || updateFile(t, dir, "agent_config.json") != originals["agent_config.json"] {
		t.Fatal("successful update lost state or settings")
	}
	left, _ := filepath.Glob(filepath.Join(dir, ".na-*"))
	if len(left) != 0 {
		t.Fatalf("transaction copies left after confirmed update: %v", left)
	}
}

func TestAgentUpdateRestoresEntireInstallationOnFailure(t *testing.T) {
	for _, failAt := range []string{"stop", "start", "heartbeat"} {
		t.Run(failAt, func(t *testing.T) {
			dir, candidate, originals := updateFixture(t)
			stops, starts := 0, 0
			err := applyAgentUpdate(dir, candidate, updateServiceOps{
				stop: func() error {
					stops++
					if failAt == "stop" && stops == 1 {
						return errors.New("stop denied")
					}
					return nil
				},
				start: func() error {
					starts++
					if updateFile(t, dir, "agent.exe") == "new binary" {
						writeUpdateFile(t, dir, "agent_config.json", "candidate settings")
						writeUpdateFile(t, dir, "agent_state.json", "candidate credentials")
						writeUpdateFile(t, dir, "agent_status.json", "candidate status")
						if failAt == "start" {
							return errors.New("new service crashed")
						}
					}
					return nil
				},
				verify: func(time.Time) error { return errors.New("no authenticated heartbeat") },
			})
			if err == nil {
				t.Fatal("failed update reported success")
			}
			for name, want := range originals {
				if got := updateFile(t, dir, name); got != want {
					t.Errorf("%s after rollback = %q, want %q", name, got, want)
				}
			}
			if failAt == "stop" {
				if stops != 1 || starts != 1 {
					t.Fatalf("stop failure recovery: stops=%d starts=%d", stops, starts)
				}
			} else if stops != 2 || starts != 2 {
				t.Fatalf("candidate must stop before rollback, old service must restart: stops=%d starts=%d", stops, starts)
			}
		})
	}
}

func TestAgentUpdateResultRetainedUntilSignedAcknowledgement(t *testing.T) {
	dir := t.TempDir()
	oldURL, oldToken, oldID := serverURL, deviceToken, deviceID
	t.Cleanup(func() { serverURL, deviceToken, deviceID = oldURL, oldToken, oldID })
	key := "personal-test-token"
	state, _ := json.Marshal(agentState{DeviceID: 17, DeviceToken: protectString(key)})
	if err := os.WriteFile(filepath.Join(dir, "agent_state.json"), state, 0o600); err != nil {
		t.Fatal(err)
	}
	attempt := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempt++
		if attempt == 1 {
			http.Error(w, "temporarily unavailable", http.StatusServiceUnavailable)
			return
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if body["id"] != float64(91) || body["status"] != "failed" {
			t.Errorf("unexpected result: %#v", body)
		}
		data := []byte(`{"ok":true}`)
		if attempt == 3 {
			w.Header().Set(hdrSig, sign(key, data))
		}
		_, _ = w.Write(data)
	}))
	defer srv.Close()
	serverURL = srv.URL
	result := agentUpdateResult{TaskID: 91, DeviceID: 17, ServerURL: srv.URL, Status: "failed", Output: "rolled back", ExitCode: 1}
	if err := saveUpdateResult(dir, result); err != nil {
		t.Fatal(err)
	}
	serverURL = srv.URL + "/different-server"
	if sendUpdateResult(dir) || attempt != 0 {
		t.Fatal("old result was sent to a different server")
	}
	serverURL = srv.URL
	if sendUpdateResult(dir) || !fileExists(filepath.Join(dir, updateResultName)) {
		t.Fatal("transient failure discarded queued result")
	}
	if sendUpdateResult(dir) || !fileExists(filepath.Join(dir, updateResultName)) {
		t.Fatal("unsigned acknowledgement discarded queued result")
	}
	if !sendUpdateResult(dir) || fileExists(filepath.Join(dir, updateResultName)) {
		t.Fatal("signed successful acknowledgement did not remove queued result")
	}
}

func TestVersionProbeBoundedAndValidatesOutput(t *testing.T) {
	for _, mode := range []string{"valid", "empty", "multiline", "large", "hang"} {
		t.Run(mode, func(t *testing.T) {
			timeout := 3 * time.Second
			if mode == "hang" {
				timeout = 100 * time.Millisecond
			}
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestVersionProbeChild$")
			cmd.Env = append(os.Environ(), "NETADMIN_VERSION_TEST_CHILD="+mode)
			ver, err := runVersionProbe(ctx, cmd)
			if mode == "valid" {
				if err != nil || ver != "1.2.3" {
					t.Fatalf("version=%q error=%v", ver, err)
				}
			} else if err == nil {
				t.Fatalf("invalid %s response accepted: %q", mode, ver)
			}
		})
	}
}

func TestVersionProbeChild(t *testing.T) {
	mode := os.Getenv("NETADMIN_VERSION_TEST_CHILD")
	if mode == "" {
		return
	}
	switch mode {
	case "valid":
		fmt.Println("1.2.3")
	case "empty":
	case "multiline":
		fmt.Print("1.2.3\nextra output\n")
	case "large":
		fmt.Print(strings.Repeat("x", 10000))
	case "hang":
		time.Sleep(time.Hour)
	}
	os.Exit(0)
}

func TestAgentUpdateHashValidation(t *testing.T) {
	p := filepath.Join(t.TempDir(), "agent.exe.new")
	if err := os.WriteFile(p, []byte("candidate"), 0o600); err != nil {
		t.Fatal(err)
	}
	sum, err := fileSHA256(p)
	if err != nil {
		t.Fatal(err)
	}
	if !validUpdateHash(sum) || verifyUpdateFile(p, strings.ToUpper(sum)) != nil {
		t.Fatal("valid digest rejected")
	}
	if validUpdateHash(strings.Repeat("z", 64)) || validUpdateHash("") || verifyUpdateFile(p, strings.Repeat("0", 64)) == nil {
		t.Fatal("invalid digest accepted")
	}
}

func updateFixture(t *testing.T) (string, string, map[string]string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "Обновление с пробелами")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	originals := map[string]string{"agent.exe": "old binary", "agent_config.json": "old settings",
		"agent_state.json": "old credentials", "agent_status.json": "old heartbeat"}
	for name, content := range originals {
		writeUpdateFile(t, dir, name, content)
	}
	writeUpdateFile(t, dir, "agent.exe.new", "new binary")
	return dir, filepath.Join(dir, "agent.exe.new"), originals
}

func writeUpdateFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func updateFile(t *testing.T, dir, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
