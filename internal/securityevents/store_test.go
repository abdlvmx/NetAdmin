//go:build securityevents

package securityevents

import (
	"context"
	"errors"
	"fmt"
	"math"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func openTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "security-events.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	return s
}

func enabledStorePolicy(t *testing.T, s *Store, deviceID int64, profile string) Policy {
	t.Helper()
	p, err := s.SetPolicy(context.Background(), deviceID, "personal-token", true, profile)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func validStoreEvent() Event {
	return Event{StreamID: strings.Repeat("a", 32), Channel: "System", Provider: "Service Control Manager", EventID: 7045, RecordID: 42, TimeUTC: time.Now().UTC(), Fields: map[string]string{"ServiceName": "Printer", "ServiceType": "user mode service", "StartType": "auto start"}}
}

func validStoreBatch(p Policy) Batch {
	return Batch{ID: strings.Repeat("b", 32), Generation: p.Generation, Events: []Event{validStoreEvent()}, Gaps: []Gap{{Channel: "System", Reason: "bookmark_reused"}}, Health: []ChannelStatus{{Channel: "System", State: "ready"}}, Dropped: 12}
}

func tableCount(t *testing.T, s *Store, table string) int {
	t.Helper()
	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func TestStoreConsentRequiresCurrentRegistrationAndFreshGeneration(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	p, err := s.Policy(ctx, 1, "personal-token")
	if err != nil || p.Enabled || p.Profile != "system" {
		t.Fatalf("default policy=%+v err=%v", p, err)
	}
	if err = s.UpdateStatus(ctx, 1, "personal-token", Status{State: "disabled"}); err != nil {
		t.Fatalf("default-off poll: %v", err)
	}
	p = enabledStorePolicy(t, s, 1, "system")
	if !p.Enabled || !validHexID(p.Generation) {
		t.Fatalf("enabled policy=%+v", p)
	}
	var storedHash string
	if err = s.db.QueryRow(`SELECT consent_hash FROM events_policies WHERE device_id=1`).Scan(&storedHash); err != nil || storedHash != tokenHash("personal-token") || strings.Contains(storedHash, "personal-token") {
		t.Fatalf("unexpected consent hash %q, %v", storedHash, err)
	}
	changed, err := s.RegistrationChanged(ctx, 1, "replacement-token")
	if err != nil || !changed {
		t.Fatalf("registration change=%v err=%v", changed, err)
	}
	disabled, err := s.Policy(ctx, 1, "replacement-token")
	if err != nil || disabled.Enabled || disabled.Generation == p.Generation {
		t.Fatalf("changed registration policy=%+v err=%v", disabled, err)
	}
	if old, err := s.Policy(ctx, 1, "personal-token"); err != nil || old.Enabled {
		t.Fatalf("old token restored consent: %+v %v", old, err)
	}
	if err = s.UpdateStatus(ctx, 1, "replacement-token", Status{Generation: p.Generation, State: "collecting", Dropped: 15}); err != nil {
		t.Fatal(err)
	}
	if status, err := s.Status(ctx, 1); err != nil || status.State != "disabled" || status.Dropped != 0 {
		t.Fatalf("disabled status=%+v err=%v", status, err)
	}
	if err = s.AcceptBatch(ctx, 1, "replacement-token", validStoreBatch(p)); !errors.Is(err, ErrDisabled) {
		t.Fatalf("changed registration accepted old batch: %v", err)
	}
	next, err := s.SetPolicy(ctx, 1, "replacement-token", true, "security")
	if err != nil || !next.Enabled || next.Generation == disabled.Generation || next.Generation == p.Generation {
		t.Fatalf("renewed consent=%+v err=%v", next, err)
	}
	if err = s.AcceptBatch(ctx, 1, "replacement-token", validStoreBatch(p)); !errors.Is(err, ErrGeneration) {
		t.Fatalf("old generation accepted: %v", err)
	}
	changed, err = s.RegistrationChanged(ctx, 1, "replacement-token")
	if err != nil || changed {
		t.Fatalf("renewed token mismatch: %v %v", changed, err)
	}
	if revoked, err := s.Policy(ctx, 1, ""); err != nil || revoked.Enabled {
		t.Fatalf("revoked registration policy=%+v err=%v", revoked, err)
	}
	if _, err := s.SetPolicy(ctx, 1, "", false, "security"); err != nil {
		t.Fatalf("cannot disable revoked device: %v", err)
	}
	if _, err := s.SetPolicy(ctx, 1, "", true, "security"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("enabled revoked registration: %v", err)
	}
}

func TestStoreCommittedReceiptsAndRecordDedupSurviveRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "security-events.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	p := enabledStorePolicy(t, s, 1, "system")
	b := validStoreBatch(p)
	ctx := context.Background()
	if err = s.AcceptBatch(ctx, 1, "personal-token", b); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err = s.AcceptBatch(ctx, 1, "personal-token", b); err != nil {
		t.Fatalf("retry after restart: %v", err)
	}
	if tableCount(t, s, "events_records") != 1 || tableCount(t, s, "events_gaps") != 1 || tableCount(t, s, "events_receipts") != 1 {
		t.Fatal("retry duplicated committed contents")
	}
	conflict := b
	conflict.Dropped++
	if err = s.AcceptBatch(ctx, 1, "personal-token", conflict); !errors.Is(err, ErrBatchConflict) {
		t.Fatalf("batch-ID conflict=%v", err)
	}
	second := b
	second.ID = strings.Repeat("c", 32)
	second.Gaps = nil
	if err = s.AcceptBatch(ctx, 1, "personal-token", second); err != nil {
		t.Fatal(err)
	}
	if tableCount(t, s, "events_records") != 1 || tableCount(t, s, "events_receipts") != 2 {
		t.Fatal("same record across batches was duplicated")
	}
	third := second
	third.ID = strings.Repeat("d", 32)
	firstNew := validStoreEvent()
	firstNew.RecordID++
	changedRecord := b.Events[0]
	changedRecord.Fields = map[string]string{"ServiceName": "different"}
	third.Events = []Event{firstNew, changedRecord}
	if err = s.AcceptBatch(ctx, 1, "personal-token", third); !errors.Is(err, ErrEventConflict) {
		t.Fatalf("record conflict=%v", err)
	}
	if tableCount(t, s, "events_records") != 1 || tableCount(t, s, "events_receipts") != 2 {
		t.Fatal("failed batch partly committed or recorded an ACK receipt")
	}
	// A changed stream denotes clearing/reusing a record ID and remains distinct.
	freshStream := second
	freshStream.ID = strings.Repeat("e", 32)
	freshStream.Events = append([]Event(nil), b.Events...)
	freshStream.Events[0].StreamID = strings.Repeat("f", 32)
	if err = s.AcceptBatch(ctx, 1, "personal-token", freshStream); err != nil {
		t.Fatal(err)
	}
	if tableCount(t, s, "events_records") != 2 {
		t.Fatal("record ID reuse across streams lost an event")
	}
	// Record IDs are unsigned 64-bit values, even beyond SQLite's signed range.
	last := freshStream
	last.ID = strings.Repeat("1", 32)
	last.Events = append([]Event(nil), freshStream.Events...)
	last.Events[0].RecordID = math.MaxUint64
	if err = s.AcceptBatch(ctx, 1, "personal-token", last); err != nil {
		t.Fatalf("uint64 record ID: %v", err)
	}
}

func TestStoreDroppedIsCumulativeMaximumAndStalePollCannotOverwrite(t *testing.T) {
	s := openTestStore(t)
	p := enabledStorePolicy(t, s, 1, "system")
	ctx := context.Background()
	status := Status{Generation: p.Generation, State: "collecting", Dropped: 90, QueueBytes: 100, Channels: []ChannelStatus{{Channel: "System", State: "ready"}}}
	if err := s.UpdateStatus(ctx, 1, "personal-token", status); err != nil {
		t.Fatal(err)
	}
	b := validStoreBatch(p)
	if err := s.AcceptBatch(ctx, 1, "personal-token", b); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetStatus(ctx, 1)
	if err != nil || got.Dropped != 90 || got.LastReceived.IsZero() {
		t.Fatalf("batch status=%+v err=%v", got, err)
	}
	status.Dropped = math.MaxUint64
	if err := s.UpdateStatus(ctx, 1, "personal-token", status); err != nil {
		t.Fatal(err)
	}
	newPolicy, err := s.SetPolicy(ctx, 1, "personal-token", true, "security")
	if err != nil || newPolicy.Generation == p.Generation {
		t.Fatalf("profile change=%+v err=%v", newPolicy, err)
	}
	status.State = "error"
	status.Dropped = 0
	status.Error = "stale poll"
	if err := s.UpdateStatus(ctx, 1, "personal-token", status); err != nil {
		t.Fatalf("stale poll prevented policy response: %v", err)
	}
	got, err = s.GetStatus(ctx, 1)
	if err != nil || got.Generation != newPolicy.Generation || got.State != "pending" || got.Error != "" || got.Dropped != math.MaxUint64 {
		t.Fatalf("stale status overwrote current state=%+v err=%v", got, err)
	}
}

func TestStoreRejectsInvalidDataWithoutWritingReceipt(t *testing.T) {
	s := openTestStore(t)
	p := enabledStorePolicy(t, s, 1, "system")
	cases := map[string]func(*Batch){
		"upper batch ID":      func(b *Batch) { b.ID = strings.Repeat("A", 32) },
		"short generation":    func(b *Batch) { b.Generation = "abc" },
		"zero record ID":      func(b *Batch) { b.Events[0].RecordID = 0 },
		"invalid stream ID":   func(b *Batch) { b.Events[0].StreamID = "stream" },
		"negative version":    func(b *Batch) { b.Events[0].Version = -1 },
		"oversized version":   func(b *Batch) { b.Events[0].Version = 256 },
		"unselected provider": func(b *Batch) { b.Events[0].Provider = "Other Service Control Manager" },
		"unselected ID":       func(b *Batch) { b.Events[0].EventID = 7040 },
		"unknown field":       func(b *Batch) { b.Events[0].Fields["ImagePath"] = "private" },
		"oversized field":     func(b *Batch) { b.Events[0].Fields["ServiceName"] = strings.Repeat("x", 257) },
		"invalid UTF8":        func(b *Batch) { b.Events[0].Fields["ServiceName"] = "\xff" },
		"control field":       func(b *Batch) { b.Events[0].Fields["ServiceName"] = "line\nnext" },
		"zero timestamp":      func(b *Batch) { b.Events[0].TimeUTC = time.Time{} },
		"old timestamp":       func(b *Batch) { b.Events[0].TimeUTC = time.Date(1600, 1, 1, 0, 0, 0, 0, time.UTC) },
		"future timestamp":    func(b *Batch) { b.Events[0].TimeUTC = time.Now().UTC().Add(time.Hour) },
		"nonUTC timestamp":    func(b *Batch) { b.Events[0].TimeUTC = time.Now().In(time.FixedZone("offset", 3600)) },
		"wrong profile": func(b *Batch) {
			b.Events[0].Channel, b.Events[0].Provider, b.Events[0].EventID, b.Events[0].Fields = "Security", "Microsoft-Windows-Security-Auditing", 4625, nil
		},
		"duplicate gaps":   func(b *Batch) { b.Gaps = append(b.Gaps, b.Gaps[0]) },
		"unknown gap":      func(b *Batch) { b.Gaps[0].Reason = "arbitrary text" },
		"duplicate health": func(b *Batch) { b.Health = append(b.Health, b.Health[0]) },
		"oversized health": func(b *Batch) { b.Health[0].Error = strings.Repeat("x", 257) },
		"too many events": func(b *Batch) {
			b.Events = make([]Event, MaxBatchEvents+1)
			for i := range b.Events {
				b.Events[i] = validStoreEvent()
			}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			b := validStoreBatch(p)
			mutate(&b)
			if err := s.AcceptBatch(context.Background(), 1, "personal-token", b); !errors.Is(err, ErrInvalid) {
				t.Fatalf("invalid data error=%v", err)
			}
			if tableCount(t, s, "events_records") != 0 || tableCount(t, s, "events_receipts") != 0 {
				t.Fatal("invalid data was stored/acknowledged")
			}
		})
	}
	securityPolicy := enabledStorePolicy(t, s, 2, "security")
	large := validStoreEvent()
	large.Channel, large.Provider, large.EventID = "Security", "Microsoft-Windows-Security-Auditing", 4625
	large.Fields = map[string]string{}
	for _, name := range []string{"TargetUserName", "TargetDomainName", "IpAddress", "LogonType", "Status", "SubStatus", "FailureReason"} {
		large.Fields[name] = strings.Repeat("<", 256)
	}
	b := validStoreBatch(securityPolicy)
	b.Events = []Event{large}
	if err := s.AcceptBatch(context.Background(), 2, "personal-token", b); !errors.Is(err, ErrInvalid) {
		t.Fatalf("event JSON size over4KiB accepted: %v", err)
	}
	for name := range large.Fields {
		large.Fields[name] = strings.Repeat("x", 200)
	}
	b.Events = make([]Event, MaxBatchEvents)
	for i := range b.Events {
		b.Events[i] = large
		b.Events[i].RecordID = uint64(i + 1)
	}
	if err := s.AcceptBatch(context.Background(), 2, "personal-token", b); !errors.Is(err, ErrInvalid) {
		t.Fatalf("batch JSON size over256KiB accepted: %v", err)
	}
}

func TestStoreRejectsUnboundedStatus(t *testing.T) {
	s := openTestStore(t)
	for name, status := range map[string]Status{
		"long error":      {State: "error", Error: strings.Repeat("x", 513)},
		"negative queue":  {State: "collecting", QueueBytes: -1},
		"large queue":     {State: "collecting", QueueBytes: MaxQueueBytes + 1},
		"unknown state":   {State: "arbitrary"},
		"unknown channel": {State: "error", Channels: []ChannelStatus{{Channel: "Application", State: "error"}}},
	} {
		t.Run(name, func(t *testing.T) {
			if err := s.UpdateStatus(context.Background(), 1, "personal-token", status); !errors.Is(err, ErrInvalid) {
				t.Fatalf("invalid status accepted: %v", err)
			}
		})
	}
}

func TestStoreRetentionAndCapacityCleanup(t *testing.T) {
	s := openTestStore(t)
	p := enabledStorePolicy(t, s, 1, "system")
	ctx := context.Background()
	b := validStoreBatch(p)
	if err := s.AcceptBatch(ctx, 1, "personal-token", b); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-8 * 24 * time.Hour).UnixMilli()
	for _, table := range []string{"events_records", "events_receipts", "events_gaps"} {
		if _, err := s.db.Exec(`UPDATE `+table+` SET received_at=?`, old); err != nil {
			t.Fatal(err)
		}
	}
	if visible, err := s.Events(ctx, 1, 100); err != nil || len(visible) != 0 {
		t.Fatalf("expired event visible before cleanup: %v %v", visible, err)
	}
	if err := s.cleanup(ctx); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"events_records", "events_receipts", "events_gaps"} {
		if tableCount(t, s, table) != 0 {
			t.Fatalf("retention left old %s", table)
		}
	}
	now := time.Now().UnixMilli()
	// Populate past each cap with one SQL statement. Cleanup must bound all
	// three tables, including many valid small receipts and gaps.
	for _, item := range []struct {
		name  string
		limit int
		query string
	}{
		{"events_records", maxStoredEvents, `INSERT INTO events_records(device_id,channel,stream_id,record_id,event_time,received_at,payload,payload_hash) SELECT 1,'System','stream',CAST(n AS TEXT),?,?,'{}','hash' FROM counter`},
		{"events_receipts", maxStoredReceipts, `INSERT INTO events_receipts(device_id,batch_id,payload_hash,received_at) SELECT 1,CAST(n AS TEXT),'hash',? FROM counter`},
		{"events_gaps", maxStoredGaps, `INSERT INTO events_gaps(device_id,channel,reason,received_at) SELECT 1,'System','bookmark_reused',? FROM counter`},
	} {
		query := fmt.Sprintf(`WITH RECURSIVE counter(n) AS(VALUES(1) UNION ALL SELECT n+1 FROM counter WHERE n<%d) `, item.limit+3) + item.query
		args := []any{now}
		if item.name == "events_records" {
			args = append(args, now)
		}
		if _, err := s.db.Exec(query, args...); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.cleanup(ctx); err != nil {
		t.Fatal(err)
	}
	if tableCount(t, s, "events_records") != maxStoredEvents || tableCount(t, s, "events_receipts") != maxStoredReceipts || tableCount(t, s, "events_gaps") != maxStoredGaps {
		t.Fatal("cleanup did not enforce all row caps")
	}
	var oldestRecord string
	if err := s.db.QueryRow(`SELECT record_id FROM events_records ORDER BY seq LIMIT 1`).Scan(&oldestRecord); err != nil || oldestRecord != "4" {
		t.Fatalf("cleanup kept wrong end: %q %v", oldestRecord, err)
	}
}

func TestStoreFiltersAndDeviceDeletion(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	for deviceID := int64(1); deviceID <= 2; deviceID++ {
		p := enabledStorePolicy(t, s, deviceID, "security")
		b := validStoreBatch(p)
		b.Events[0].TimeUTC = time.Now().UTC().Add(-time.Duration(deviceID) * time.Minute)
		if deviceID == 2 {
			b.Events[0].Channel, b.Events[0].Provider, b.Events[0].EventID, b.Events[0].Fields = "Security", "Microsoft-Windows-Eventlog", 1102, nil
		}
		if err := s.AcceptBatch(ctx, deviceID, "personal-token", b); err != nil {
			t.Fatal(err)
		}
	}
	all, err := s.Events(ctx, 0, 100)
	if err != nil || len(all) != 2 || all[0].DeviceID != 1 {
		t.Fatalf("all devices/time ordering=%+v %v", all, err)
	}
	filtered, err := s.EventsFiltered(ctx, EventFilter{Channel: "Security", From: time.Now().UTC().Add(-3 * time.Minute), To: time.Now().UTC(), Limit: 100})
	if err != nil || len(filtered) != 1 || filtered[0].DeviceID != 2 {
		t.Fatalf("filtered events=%+v %v", filtered, err)
	}
	if err := s.DeleteDevice(ctx, 1); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"events_policies", "events_registrations", "events_status", "events_records", "events_receipts", "events_gaps"} {
		var count int
		if err := s.db.QueryRow(`SELECT COUNT(*) FROM ` + table + ` WHERE device_id=1`).Scan(&count); err != nil || count != 0 {
			t.Fatalf("device data remained in %s: count=%d err=%v", table, count, err)
		}
	}
	remaining, err := s.Events(ctx, 0, 100)
	if err != nil || len(remaining) != 1 || remaining[0].DeviceID != 2 {
		t.Fatalf("deletion affected other device: %+v %v", remaining, err)
	}
}

func TestStoreChangedRegistrationCannotInheritPreviousDeviceData(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	p := enabledStorePolicy(t, s, 1, "system")
	if err := s.AcceptBatch(ctx, 1, "personal-token", validStoreBatch(p)); err != nil {
		t.Fatal(err)
	}
	// Changing consent directly must clear previous data, even if the UI has
	// not previously polled Policy with the replacement registration token.
	next, err := s.SetPolicy(ctx, 1, "new-device-token", true, "system")
	if err != nil || !next.Enabled || next.Generation == p.Generation {
		t.Fatalf("new registration consent=%+v err=%v", next, err)
	}
	for _, table := range []string{"events_records", "events_receipts", "events_gaps"} {
		if tableCount(t, s, table) != 0 {
			t.Fatalf("new device inherited %s", table)
		}
	}
	status, err := s.GetStatus(ctx, 1)
	if err != nil || !status.LastReceived.IsZero() || status.Dropped != 0 || len(status.Channels) != 0 {
		t.Fatalf("new registration inherited status=%+v err=%v", status, err)
	}
	b := validStoreBatch(next)
	b.Dropped = 3
	if err := s.AcceptBatch(ctx, 1, "new-device-token", b); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err := s.Policy(ctx, 1, "new-device-token"); err != nil {
			t.Fatal(err)
		}
	}
	if tableCount(t, s, "events_records") != 1 {
		t.Fatal("repeat polls erased current registration data")
	}
	// A later change observed while disabled must still purge old records.
	if _, err := s.SetPolicy(ctx, 1, "new-device-token", false, "system"); err != nil {
		t.Fatal(err)
	}
	if p, err := s.Policy(ctx, 1, "third-device-token"); err != nil || p.Enabled {
		t.Fatalf("disabled registration change=%+v %v", p, err)
	}
	if tableCount(t, s, "events_records") != 0 || tableCount(t, s, "events_gaps") != 0 {
		t.Fatal("disabled registration inherited previous data")
	}
	changed, err := s.RegistrationChanged(ctx, 1, "third-device-token")
	if err != nil || !changed {
		t.Fatalf("registration notice lost: %v %v", changed, err)
	}
}

func TestStoreCloseStopsCleanupAndCancelledBatchCannotAcknowledge(t *testing.T) {
	s := openTestStore(t)
	p := enabledStorePolicy(t, s, 1, "system")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.AcceptBatch(ctx, 1, "personal-token", validStoreBatch(p)); err == nil {
		t.Fatal("cancelled batch returned success")
	}
	if tableCount(t, s, "events_receipts") != 0 {
		t.Fatal("cancelled batch recorded ACK receipt")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-s.done:
	default:
		t.Fatal("cleanup goroutine still running after Close")
	}
}
