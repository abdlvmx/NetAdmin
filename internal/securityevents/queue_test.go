//go:build securityevents

package securityevents

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func queueTestState() QueueState {
	return QueueState{ServerURL: "https://test.example", DeviceID: 1, Policy: Policy{true, "system", "generation"}, Cursors: map[string]Cursor{"System": {Bookmark: "bookmark-42", StreamID: "stream"}}, Status: Status{Generation: "generation", State: "collecting"}}
}

func TestQueuePersistsBatchAndBookmarkUntilAcknowledged(t *testing.T) {
	p := filepath.Join(t.TempDir(), "queue.db")
	q, err := OpenQueue(p)
	if err != nil {
		t.Fatal(err)
	}
	s := queueTestState()
	b := Batch{ID: "packet-1", Generation: s.Policy.Generation, Events: []Event{{Channel: "System", RecordID: 42}}}
	if _, err = q.Commit(context.Background(), s, []Batch{b}); err != nil {
		t.Fatal(err)
	}
	q.Close()
	q, err = OpenQueue(p)
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	got, err := q.State()
	if err != nil || got.Cursors["System"].Bookmark != "bookmark-42" {
		t.Fatalf("cursor lost: %+v %v", got, err)
	}
	for i := 0; i < 2; i++ {
		pending, ok, err := q.Oldest()
		if err != nil || !ok || pending.ID != b.ID || pending.Events[0].RecordID != 42 {
			t.Fatalf("pending batch lost: %+v %v", pending, err)
		}
	}
	if err = q.Acknowledge(context.Background(), b.ID); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := q.Oldest(); err != nil || ok {
		t.Fatal("acknowledged batch retained")
	}
	got, _ = q.State()
	if got.Cursors["System"].Bookmark != "bookmark-42" {
		t.Fatal("ack deleted bookmark")
	}
}

func TestQueueOverflowCountsDroppedAndPersistsProgress(t *testing.T) {
	q, err := OpenQueue(filepath.Join(t.TempDir(), "queue.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	q.maxBytes = 1
	s := queueTestState()
	s, err = q.Commit(context.Background(), s, []Batch{{ID: "packet-1", Generation: "generation", Events: []Event{{RecordID: 42}}}})
	if err != nil || s.Status.Dropped != 1 || s.Status.QueueBytes != 0 {
		t.Fatalf("overflow: %+v %v", s, err)
	}
	got, _ := q.State()
	if got.Status.Dropped != 1 || got.Cursors["System"].Bookmark != "bookmark-42" {
		t.Fatal("overflow progress lost")
	}
}

func TestQueueRollbackDoesNotAdvanceBookmarkWhenBatchFails(t *testing.T) {
	q, err := OpenQueue(filepath.Join(t.TempDir(), "queue.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	s := queueTestState()
	_, err = q.Commit(context.Background(), s, []Batch{{ID: "bad", Generation: "wrong"}})
	if err == nil {
		t.Fatal("invalid packet accepted")
	}
	got, _ := q.State()
	if len(got.Cursors) != 0 {
		t.Fatal("bookmark advanced without batch")
	}
}

func TestQueueResetRemovesOldRegistrationData(t *testing.T) {
	q, err := OpenQueue(filepath.Join(t.TempDir(), "queue.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	s := queueTestState()
	s, _ = q.Commit(context.Background(), s, []Batch{{ID: "old", Generation: "generation", Events: []Event{{RecordID: 42}}}})
	s.DeviceID = 2
	s.Policy.Generation = "new"
	s, err = q.Reset(context.Background(), s)
	if err != nil || s.DeviceID != 2 || len(s.Cursors) != 0 || s.Status.Dropped != 1 {
		t.Fatalf("reset: %+v %v", s, err)
	}
	if _, ok, _ := q.Oldest(); ok {
		t.Fatal("old identity data retained for delivery")
	}
}

func TestSplitBatchesBoundsSerializedPayload(t *testing.T) {
	events := make([]Event, 300)
	for i := range events {
		events[i] = Event{RecordID: uint64(i + 1), TimeUTC: time.Now().UTC(), Fields: map[string]string{"field": strings.Repeat("x", 3000)}}
	}
	n := 0
	batches, err := SplitBatches("generation", events, nil, Status{}, func() string { n++; return strings.Repeat("a", n) })
	if err != nil || len(batches) < 3 {
		t.Fatalf("split: %d %v", len(batches), err)
	}
	total := 0
	for _, b := range batches {
		total += len(b.Events)
		if len(b.Events) > MaxBatchEvents {
			t.Fatal("event bound exceeded")
		}
	}
	if total != 300 {
		t.Fatalf("split lost events: %d", total)
	}
}
