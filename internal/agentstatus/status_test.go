package agentstatus

import (
	"testing"
	"time"
)

func TestReadinessRejectsStaleOtherServerAndFailedHeartbeats(t *testing.T) {
	since := time.Now().UTC()
	s := Status{ServerURL: "http://server:8765", Version: "1", DeviceID: 42, ProcessID: 7, HeartbeatAt: since.Add(time.Second)}
	if !s.Matches(s.ServerURL, s.Version, since) {
		t.Fatal("fresh accepted heartbeat rejected")
	}
	if s.Matches("http://other:8765", s.Version, since) || s.Matches(s.ServerURL, "2", since) || s.Matches(s.ServerURL, s.Version, since.Add(2*time.Second)) {
		t.Fatal("wrong server/version or stale heartbeat accepted")
	}
	s.LastError = "HTTP 403"
	if s.Matches(s.ServerURL, s.Version, since) {
		t.Fatal("rejected heartbeat accepted")
	}
	s.LastError, s.DeviceID = "", 0
	if s.Matches(s.ServerURL, s.Version, since) {
		t.Fatal("unregistered agent accepted")
	}
}

func TestWaitRequiresFreshServiceHeartbeatAndExplainsRejection(t *testing.T) {
	dir := t.TempDir()
	since := time.Now().UTC()
	s := Status{ServerURL: "http://server:8765", Version: "1", DeviceID: 42, ProcessID: 7, AttemptAt: since, HeartbeatAt: since.Add(-time.Hour), LastError: "HTTP 401: code expired"}
	if err := Save(dir, s); err != nil {
		t.Fatal(err)
	}
	if err := Wait(dir, s.ServerURL, "1", since, 0); err == nil {
		t.Fatal("old heartbeat accepted")
	}
	s.HeartbeatAt, s.LastError = since, ""
	if err := Save(dir, s); err != nil {
		t.Fatal(err)
	}
	if err := Wait(dir, s.ServerURL, "1", since, 0); err != nil {
		t.Fatal(err)
	}
}
