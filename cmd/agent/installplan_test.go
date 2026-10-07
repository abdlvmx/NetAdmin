package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"netadmin/internal/agentstatus"
	"netadmin/internal/installtxn"
)

func writeInstallFixture(t *testing.T, dir string, cfg agentConfig, st agentState) {
	t.Helper()
	for name, value := range map[string]any{"agent_config.json": cfg, "agent_state.json": st} {
		b, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestInstallReinstallPreservesRegistrationWithoutEnrollmentCode(t *testing.T) {
	dir := t.TempDir()
	writeInstallFixture(t, dir, agentConfig{ServerURL: "http://NETADMIN:8765/"}, agentState{DeviceID: 42, DeviceToken: "dpapi:opaque"})
	plan, err := planAgentInstall(dir, "", "netadmin", "", false, false, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if plan.Config.ServerURL != "http://netadmin:8765" || plan.ArchivePath != "" {
		t.Fatalf("unexpected reinstall plan: %+v", plan)
	}
	if !plan.Files[1].Snapshot || plan.Files[1].Remove {
		t.Fatal("reinstall must preserve and protect personal registration")
	}
}

func TestInstallChangedAddressRequiresExplicitChoice(t *testing.T) {
	dir := t.TempDir()
	writeInstallFixture(t, dir, agentConfig{ServerURL: "http://192.168.1.10:8765"}, agentState{DeviceID: 42, DeviceToken: "dpapi:opaque"})
	if _, err := planAgentInstall(dir, "", "192.168.1.20", "new-code", false, false, time.Now()); err == nil || !strings.Contains(err.Error(), "-keep-registration") {
		t.Fatalf("URL change without choice must fail with instructions: %v", err)
	}
	plan, err := planAgentInstall(dir, "", "192.168.1.20", "", false, true, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Files[1].Snapshot || plan.ArchivePath != "" {
		t.Fatal("same-server address change must preserve registration")
	}
}

func TestInstallEnrollmentFallbackBelongsToSameServer(t *testing.T) {
	dir := t.TempDir()
	writeInstallFixture(t, dir, agentConfig{ServerURL: "http://SERVER:8765/", EnrollToken: "stored-code"}, agentState{})
	plan, err := planAgentInstall(dir, "", "server", "", false, false, time.Now())
	if err != nil || plan.Config.EnrollToken != "stored-code" {
		t.Fatalf("same server reinstall lost stored enrollment code: %+v %v", plan.Config, err)
	}
	if _, err := planAgentInstall(dir, "", "different-server", "", false, false, time.Now()); err == nil {
		t.Fatal("pending registration must not reuse another server's enrollment code")
	}
}

func TestInstallActiveUpdateBlocksInstallation(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "agent_update.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := planAgentInstall(dir, "", "new", "new-code", false, false, time.Now()); err == nil || !strings.Contains(err.Error(), "обновление агента") {
		t.Fatalf("active helper must block concurrent installation: %v", err)
	}
}

func TestInstallSameServerAddressChangeRetargetsBoundUpdateResult(t *testing.T) {
	dir := t.TempDir()
	writeInstallFixture(t, dir, agentConfig{ServerURL: "http://old:8765"}, agentState{DeviceID: 42, DeviceToken: "dpapi:opaque"})
	path := filepath.Join(dir, "agent_update_result.json")
	original := `{"task_id":7,"device_id":42,"server_url":"http://OLD:8765/","status":"done","output":"updated","exit_code":0,"future_field":{"preserve":true}}`
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	plan, err := planAgentInstall(dir, "", "new", "", false, true, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := installtxn.Apply(plan.Files, installtxn.Hooks{}); err != nil {
		t.Fatal(err)
	}
	var result map[string]json.RawMessage
	if err := readInstallJSON(path, &result); err != nil {
		t.Fatal(err)
	}
	if string(result["server_url"]) != `"http://new:8765"` || string(result["device_id"]) != "42" || string(result["task_id"]) != "7" || string(result["future_field"]) != `{"preserve":true}` {
		t.Fatalf("retarget lost original task or future fields: %+v", result)
	}
	if _, err := retargetInstallUpdateResult(path, "http://new:8765", "http://next:8765", 99); err == nil {
		t.Fatal("result belonging to another device must not retarget")
	}
}

func TestInstallTransferRequiresFreshCodeAndArchivesIdentity(t *testing.T) {
	dir := t.TempDir()
	old := agentState{DeviceID: 42, DeviceToken: "dpapi:opaque", LastSoftware: "yesterday"}
	writeInstallFixture(t, dir, agentConfig{ServerURL: "http://old:8765", EnrollToken: "old-code"}, old)
	if _, err := planAgentInstall(dir, "", "new", "", true, false, time.Now()); err == nil || !strings.Contains(err.Error(), "новый код") {
		t.Fatalf("old enrollment code must not authorize transfer: %v", err)
	}
	plan, err := planAgentInstall(dir, "", "new", "new-code", true, false, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if plan.Config.EnrollToken != "new-code" || !plan.Files[1].Remove || plan.ArchivePath == "" {
		t.Fatalf("unexpected transfer plan: %+v", plan)
	}
	if err := installtxn.Apply(plan.Files, installtxn.Hooks{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "agent_state.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("old identity survived transfer: %v", err)
	}
	var backup struct {
		ServerURL string     `json:"server_url"`
		State     agentState `json:"agent_state"`
	}
	if err := readInstallJSON(plan.ArchivePath, &backup); err != nil {
		t.Fatal(err)
	}
	if backup.ServerURL != "http://old:8765" || backup.State != old {
		t.Fatalf("backup lost old registration: %+v", backup)
	}
}

func TestInstallTransferFailureRestoresFilesAndIdentity(t *testing.T) {
	dir := t.TempDir()
	old := agentState{DeviceID: 42, DeviceToken: "dpapi:old"}
	writeInstallFixture(t, dir, agentConfig{ServerURL: "http://old:8765"}, old)
	if err := os.WriteFile(filepath.Join(dir, "agent.exe"), []byte("old-binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	oldResult := []byte(`{"task_id":7,"device_id":42,"server_url":"http://old:8765","status":"done"}`)
	if err := os.WriteFile(filepath.Join(dir, "agent_update_result.json"), oldResult, 0o600); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(t.TempDir(), "new.exe")
	if err := os.WriteFile(source, []byte("new-binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	plan, err := planAgentInstall(dir, source, "new", "new-code", true, false, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var steps []string
	failed := errors.New("registration rejected")
	err = installtxn.Apply(plan.Files, installtxn.Hooks{
		Stop: func() error { steps = append(steps, "stop"); return nil },
		Start: func() error {
			steps = append(steps, "start")
			// The service may register and clear the enrollment code before a
			// subsequent installation verification fails. Both changes revert.
			writeInstallFixture(t, dir, agentConfig{ServerURL: "http://new:8765"}, agentState{DeviceID: 99, DeviceToken: "dpapi:new"})
			return nil
		},
		Verify:  func() error { return failed },
		Recover: func() error { steps = append(steps, "recover"); return nil },
	})
	if !errors.Is(err, failed) || strings.Join(steps, ",") != "stop,start,stop,recover" {
		t.Fatalf("candidate must stop before rollback and old service recover: %v %v", err, steps)
	}
	cfg, st, err := readInstallIdentity(dir)
	if err != nil || cfg.ServerURL != "http://old:8765" || st != old {
		t.Fatalf("old installation was not restored: %+v %+v %v", cfg, st, err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "agent.exe"))
	if err != nil || string(b) != "old-binary" {
		t.Fatalf("binary rollback failed: %q %v", b, err)
	}
	if _, err := os.Stat(plan.ArchivePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed transfer must not leave a committed archive: %v", err)
	}
	if restored, err := os.ReadFile(filepath.Join(dir, "agent_update_result.json")); err != nil || string(restored) != string(oldResult) {
		t.Fatalf("failed transfer lost pending old-server result: %q %v", restored, err)
	}
}

func TestInstallFirstRegistrationFailureRemovesCandidateState(t *testing.T) {
	dir := t.TempDir()
	plan, err := planAgentInstall(dir, "", "new", "new-code", false, false, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	err = installtxn.Apply(plan.Files, installtxn.Hooks{
		Start: func() error {
			writeInstallFixture(t, dir, agentConfig{ServerURL: "http://new:8765"}, agentState{DeviceID: 99, DeviceToken: "new"})
			return nil
		},
		Verify: func() error { return errors.New("rejected") },
	})
	if err == nil {
		t.Fatal("failed candidate unexpectedly committed")
	}
	for _, name := range []string{"agent_config.json", "agent_state.json", "agent_status.json"} {
		if _, err := os.Stat(filepath.Join(dir, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("failed new installation left %s: %v", name, err)
		}
	}
}

func TestInstallRejectsDamagedSettingsAndUnsafeURLs(t *testing.T) {
	for _, raw := range []string{"", "ftp://server:8765", "http://user:password@server:8765", "http://server:0", "http://server:65536", "http://server:8765?token=secret", "http://server:8765#part"} {
		if _, err := installServerURL(raw); err == nil {
			t.Errorf("unsafe address accepted: %q", raw)
		}
	}
	dir := t.TempDir()
	if err := os.WriteFile(configPathIn(dir), []byte("invalid json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := planAgentInstall(dir, "", "new", "new-code", false, false, time.Now()); err == nil {
		t.Fatal("damaged settings must not silently overwrite existing installation")
	}
}

func TestInstallServerProbeExplainsFailures(t *testing.T) {
	for _, tc := range []struct {
		status int
		body   string
		want   string
	}{{200, "ok", ""}, {403, "Forbidden", "подсеть"}, {503, "unavailable", "не готов"}, {200, "login", "не готов"}, {302, "", "не готов"}} {
		t.Run(http.StatusText(tc.status)+tc.body, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.Path != "/healthz" {
					t.Errorf("probe changed data or used wrong route: %s %s", r.Method, r.URL.Path)
				}
				w.Header().Set("Location", "/login")
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			err := checkInstallServer(srv.URL)
			if tc.want == "" && err != nil || tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
				t.Fatalf("unexpected probe result: %v", err)
			}
		})
	}
}

func TestInstallVerifyRejectsStaleHeartbeatAndRequiresRealRegistration(t *testing.T) {
	dir := t.TempDir()
	since := time.Now()
	s := agentstatus.Status{ServerURL: "http://new:8765", Version: "test", DeviceID: 7, ProcessID: 12, HeartbeatAt: since.Add(-time.Minute)}
	if err := agentstatus.Save(dir, s); err != nil {
		t.Fatal(err)
	}
	if err := agentstatus.Wait(dir, s.ServerURL, s.Version, since, 0); err == nil {
		t.Fatal("previous process heartbeat must not confirm installation")
	}
	s.HeartbeatAt = since.Add(time.Second)
	s.DeviceID = 0
	if err := agentstatus.Save(dir, s); err != nil {
		t.Fatal(err)
	}
	if err := agentstatus.Wait(dir, s.ServerURL, s.Version, since, 0); err == nil {
		t.Fatal("heartbeat without registration must not confirm installation")
	}
	s.DeviceID = 7
	if err := agentstatus.Save(dir, s); err != nil {
		t.Fatal(err)
	}
	if err := agentstatus.Wait(dir, s.ServerURL, s.Version, since, 0); err != nil {
		t.Fatalf("fresh registered heartbeat must confirm installation: %v", err)
	}
}
