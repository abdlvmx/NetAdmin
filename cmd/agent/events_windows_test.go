//go:build securityevents && windows

package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"netadmin/internal/eventlog"
	"netadmin/internal/securityevents"
)

func eventTestIdentity(t *testing.T) {
	t.Helper()
	oldURL, oldClient, oldRead := serverURL, httpClient, readEventLog
	oldKey, oldID := agentIdentity()
	t.Cleanup(func() {
		serverURL, httpClient, readEventLog = oldURL, oldClient, oldRead
		setAgentIdentity(oldKey, oldID)
	})
	setAgentIdentity("events-test-key", 123)
}

func eventSignedReply(w http.ResponseWriter, value any) {
	b, _ := json.Marshal(value)
	w.Header().Set(hdrSig, sign("events-test-key", b))
	w.Write(b)
}

func TestEventsDisabledNeverReadsOrCreatesQueue(t *testing.T) {
	eventTestIdentity(t)
	var reads atomic.Int32
	readEventLog = func(context.Context, string, eventlog.Cursor, int) (eventlog.ReadResult, error) {
		reads.Add(1)
		return eventlog.ReadResult{}, nil
	}
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { eventSignedReply(w, securityevents.PollResponse{}) }))
	defer s.Close()
	serverURL = s.URL
	httpClient = s.Client()
	p := filepath.Join(t.TempDir(), "events.db")
	worker := &eventsWorker{path: p}
	for i := 0; i < 3; i++ {
		worker.step(context.Background())
	}
	if reads.Load() != 0 || worker.queue != nil {
		t.Fatal("disabled module read journal or created queue")
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatalf("disabled module wrote queue: %v", err)
	}
}

func TestEventsHTTPNeverReadsOrCreatesQueue(t *testing.T) {
	eventTestIdentity(t)
	var requests, reads atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1) }))
	defer s.Close()
	serverURL = s.URL
	readEventLog = func(context.Context, string, eventlog.Cursor, int) (eventlog.ReadResult, error) {
		reads.Add(1)
		return eventlog.ReadResult{}, nil
	}
	worker := &eventsWorker{path: filepath.Join(t.TempDir(), "events.db")}
	worker.step(context.Background())
	if requests.Load() != 0 || reads.Load() != 0 || worker.queue != nil || worker.status.State != "paused" {
		t.Fatal("HTTP started collection")
	}
}

func TestEventsLostAcknowledgementRetriesSameBatchAfterRestart(t *testing.T) {
	eventTestIdentity(t)
	const generation = "0123456789abcdef0123456789abcdef"
	var reads, attempts atomic.Int32
	var enabled atomic.Bool
	enabled.Store(true)
	var firstID string
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if r.Header.Get(hdrDevice) != "123" || r.Header.Get(hdrSig) != sign("events-test-key", b) {
			t.Error("wrong registered identity or signature")
		}
		if r.URL.Path == "/api/agent-events/poll" {
			eventSignedReply(w, securityevents.PollResponse{Policy: securityevents.Policy{Enabled: enabled.Load(), Profile: "system", Generation: generation}})
			return
		}
		var p struct {
			Batch securityevents.Batch `json:"batch"`
		}
		if json.Unmarshal(b, &p) != nil || len(p.Batch.Events) != 1 {
			t.Errorf("invalid delivered batch: %s", b)
		}
		n := attempts.Add(1)
		if n == 1 {
			firstID = p.Batch.ID
			http.Error(w, "temporary failure", 503)
			return
		}
		if p.Batch.ID != firstID {
			t.Error("retry changed batch ID")
		}
		if n == 2 {
			w.Write([]byte(`{"ok":true}`))
			return
		}
		eventSignedReply(w, map[string]any{"ok": true})
	}))
	defer s.Close()
	serverURL = s.URL
	httpClient = s.Client()
	readEventLog = func(_ context.Context, channel string, c eventlog.Cursor, _ int) (eventlog.ReadResult, error) {
		reads.Add(1)
		if c.Bookmark == "" {
			return eventlog.ReadResult{Cursor: eventlog.Cursor{Bookmark: "tail", StreamID: generation}}, nil
		}
		if c.Bookmark == "tail" {
			return eventlog.ReadResult{Cursor: eventlog.Cursor{Bookmark: "done", StreamID: generation}, Events: []eventlog.Event{{StreamID: generation, Channel: channel, Provider: "EventLog", EventID: 6005, RecordID: 42, TimeUTC: time.Now().UTC()}}}, nil
		}
		return eventlog.ReadResult{Cursor: c}, nil
	}
	worker := &eventsWorker{path: filepath.Join(t.TempDir(), "events.db")}
	defer func() {
		if worker.queue != nil {
			worker.queue.Close()
		}
	}()
	worker.step(context.Background()) // Establish tail, no history.
	worker.step(context.Background()) // Queue one selected event.
	worker.step(context.Background()) // HTTP failure, retain batch.
	worker.step(context.Background()) // Lost/unsigned ACK, retain batch.
	if reads.Load() != 2 || attempts.Load() != 2 {
		t.Fatalf("read while delivery paused: reads=%d attempts=%d", reads.Load(), attempts.Load())
	}
	worker.queue.Close()
	worker.queue = nil
	worker = &eventsWorker{path: worker.path}
	worker.step(context.Background()) // Restore bookmark, send exact batch, ACK.
	if attempts.Load() != 3 {
		t.Fatalf("batch not retried: %d", attempts.Load())
	}
	if _, ok, err := worker.queue.Oldest(); err != nil || ok {
		t.Fatalf("ACK not consumed: %v", err)
	}
	if worker.state.Cursors["System"].Bookmark != "done" {
		t.Fatal("bookmark lost across restart")
	}
	before := reads.Load()
	enabled.Store(false)
	worker.step(context.Background())
	if reads.Load() != before || worker.status.State != "disabled" || len(worker.state.Cursors) != 0 {
		t.Fatal("disabling continued reading or kept bookmarks")
	}
}

func TestEventsCommitFailureDoesNotAdvanceInMemoryCursor(t *testing.T) {
	eventTestIdentity(t)
	const generation = "0123456789abcdef0123456789abcdef"
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		eventSignedReply(w, securityevents.PollResponse{Policy: securityevents.Policy{Enabled: true, Profile: "system", Generation: generation}})
	}))
	defer s.Close()
	serverURL = s.URL
	httpClient = s.Client()
	p := filepath.Join(t.TempDir(), "events.db")
	q, err := securityevents.OpenQueue(p)
	if err != nil {
		t.Fatal(err)
	}
	state := securityevents.QueueState{ServerURL: s.URL, DeviceID: 123, Policy: securityevents.Policy{Enabled: true, Profile: "system", Generation: generation}, Cursors: map[string]securityevents.Cursor{"System": {Bookmark: "old", StreamID: generation}}}
	state, err = q.Commit(context.Background(), state, nil)
	if err != nil {
		t.Fatal(err)
	}
	worker := &eventsWorker{path: p, queue: q, state: state}
	readEventLog = func(_ context.Context, _ string, c eventlog.Cursor, _ int) (eventlog.ReadResult, error) {
		q.Close() // Storage fails after reading, before the atomic commit.
		return eventlog.ReadResult{Cursor: eventlog.Cursor{Bookmark: "new", StreamID: c.StreamID}}, nil
	}
	worker.step(context.Background())
	if worker.state.Cursors["System"].Bookmark != "old" {
		t.Fatal("cursor advanced after transaction failure")
	}
}

func TestEventsWorkerInitializesNativeSystemTailWithoutHistory(t *testing.T) {
	eventTestIdentity(t)
	const generation = "0123456789abcdef0123456789abcdef"
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		eventSignedReply(w, securityevents.PollResponse{Policy: securityevents.Policy{Enabled: true, Profile: "system", Generation: generation}})
	}))
	defer s.Close()
	serverURL = s.URL
	httpClient = s.Client()
	worker := &eventsWorker{path: filepath.Join(t.TempDir(), "events.db")}
	defer func() {
		if worker.queue != nil {
			worker.queue.Close()
		}
	}()
	worker.step(context.Background())
	if worker.status.State != "collecting" || len(worker.status.Channels) != 1 || worker.status.Channels[0].State != "ready" {
		t.Fatalf("native collector failed: %+v", worker.status)
	}
	if worker.state.Cursors["System"].Bookmark == "" {
		t.Fatal("initial tail bookmark missing")
	}
	if _, ok, err := worker.queue.Oldest(); err != nil || ok {
		t.Fatalf("first pass backfilled historical events: %v", err)
	}
}

func TestEventsDisabledAfterRestartPurgesExistingQueueWithoutReading(t *testing.T) {
	eventTestIdentity(t)
	const generation = "0123456789abcdef0123456789abcdef"
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { eventSignedReply(w, securityevents.PollResponse{}) }))
	defer s.Close()
	serverURL = s.URL
	httpClient = s.Client()
	p := filepath.Join(t.TempDir(), "events.db")
	q, err := securityevents.OpenQueue(p)
	if err != nil {
		t.Fatal(err)
	}
	state := securityevents.QueueState{ServerURL: s.URL, DeviceID: 123, Policy: securityevents.Policy{Enabled: true, Profile: "system", Generation: generation}, Cursors: map[string]securityevents.Cursor{"System": {Bookmark: "old", StreamID: generation}}, Status: securityevents.Status{Dropped: 7}}
	if _, err = q.Commit(context.Background(), state, []securityevents.Batch{{ID: generation, Generation: generation, Events: []securityevents.Event{{RecordID: 42}}}}); err != nil {
		t.Fatal(err)
	}
	q.Close()
	var reads atomic.Int32
	readEventLog = func(context.Context, string, eventlog.Cursor, int) (eventlog.ReadResult, error) {
		reads.Add(1)
		return eventlog.ReadResult{}, nil
	}
	worker := &eventsWorker{path: p}
	defer func() {
		if worker.queue != nil {
			worker.queue.Close()
		}
	}()
	worker.step(context.Background())
	if reads.Load() != 0 || worker.state.Policy.Enabled || len(worker.state.Cursors) > 0 || worker.status.State != "disabled" {
		t.Fatalf("revoked policy kept collection: %+v", worker.status)
	}
	if _, ok, err := worker.queue.Oldest(); err != nil || ok {
		t.Fatalf("revoked policy kept queued events: %v", err)
	}
	if worker.status.Dropped != 8 {
		t.Fatalf("restart lost drop counter: %d", worker.status.Dropped)
	}
}

func TestEventsReadFailurePreservesLastSuccessfulCollection(t *testing.T) {
	eventTestIdentity(t)
	const generation = "0123456789abcdef0123456789abcdef"
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		eventSignedReply(w, securityevents.PollResponse{Policy: securityevents.Policy{Enabled: true, Profile: "system", Generation: generation}})
	}))
	defer s.Close()
	serverURL, httpClient = s.URL, s.Client()
	worker := &eventsWorker{path: filepath.Join(t.TempDir(), "events.db")}
	defer func() {
		if worker.queue != nil {
			worker.queue.Close()
		}
	}()
	readEventLog = func(_ context.Context, _ string, c eventlog.Cursor, _ int) (eventlog.ReadResult, error) {
		return eventlog.ReadResult{Cursor: c}, nil
	}
	worker.step(context.Background())
	last := worker.status.LastCollected
	readEventLog = func(context.Context, string, eventlog.Cursor, int) (eventlog.ReadResult, error) {
		return eventlog.ReadResult{}, errors.New(strings.Repeat("Ошибка ", 100))
	}
	worker.step(context.Background())
	if worker.status.State != "error" || !worker.status.LastCollected.Equal(last) || len(worker.status.Channels[0].Error) > 256 {
		t.Fatalf("failed read reported as successful: %+v", worker.status)
	}
}
