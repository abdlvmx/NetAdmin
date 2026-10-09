//go:build securityevents

package securityevents

import (
	"context"
	"testing"
	"time"
)

func TestDeliveryDistinguishesQuietLogsLossOfContactAndStalledQueue(t *testing.T) {
	now := time.Now().UTC()
	p := Policy{Enabled: true, Generation: "current"}
	base := DeviceStatus{Status: Status{Generation: "current", State: "collecting", LastCollected: now}, PolicySince: now.Add(-time.Hour), LastContact: now}
	cases := []struct {
		name, code string
		mutate     func(*DeviceStatus)
	}{
		{"no events but fresh reading", "healthy", func(s *DeviceStatus) {}},
		{"stale connected-looking report", "stale", func(s *DeviceStatus) { s.LastContact = now.Add(-4 * time.Minute) }},
		{"never contacted", "no_contact", func(s *DeviceStatus) { s.LastContact = time.Time{} }},
		{"startup grace", "pending", func(s *DeviceStatus) { s.LastContact = time.Time{}; s.PolicySince = now }},
		{"reader failure", "collector_error", func(s *DeviceStatus) { s.State = "error" }},
		{"paused sender", "paused", func(s *DeviceStatus) { s.State = "paused" }},
		{"stale reading with fresh poll", "not_collecting", func(s *DeviceStatus) { s.LastCollected = now.Add(-4 * time.Minute) }},
		{"queue without progress", "queue_stalled", func(s *DeviceStatus) { s.QueueBytes = 100; s.QueueSince = now.Add(-11 * time.Minute) }},
		{"queue with fresh progress", "queued", func(s *DeviceStatus) {
			s.QueueBytes = 100
			s.QueueSince = now.Add(-11 * time.Minute)
			s.LastReceived = now
		}},
		{"recent loss", "loss", func(s *DeviceStatus) { s.Dropped = 12; s.LastLoss = now.Add(-time.Hour) }},
		{"historic counter", "healthy", func(s *DeviceStatus) { s.Dropped = 12; s.LastLoss = now.Add(-25 * time.Hour) }},
		{"stale generation", "pending", func(s *DeviceStatus) { s.Generation = "old" }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := base
			c.mutate(&s)
			if h := AssessDelivery(p, s, now); h.Code != c.code {
				t.Fatalf("got %+v want %s", h, c.code)
			}
		})
	}
	p.Enabled = false
	base.State = "error"
	if h := AssessDelivery(p, base, now); h.Code != "disabled" || h.Level != "info" {
		t.Fatal("disabled device alarmed", h)
	}
}

func TestDeliveryServerTimesPersistAndResetOnPolicyAndRegistration(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	s.now = func() time.Time { return now }
	p := enabledStorePolicy(t, s, 1, "system")
	status, err := s.GetStatus(ctx, 1)
	if err != nil || !status.PolicySince.Equal(now) || !status.LastContact.IsZero() {
		t.Fatalf("policy clock: %+v %v", status, err)
	}
	now = now.Add(time.Minute)
	health := Status{Generation: p.Generation, State: "collecting", LastCollected: now, QueueBytes: 100, Dropped: 2}
	if err = s.UpdateStatus(ctx, 1, "personal-token", health); err != nil {
		t.Fatal(err)
	}
	status, _ = s.GetStatus(ctx, 1)
	if !status.LastContact.Equal(now) || !status.QueueSince.Equal(now) || !status.LastLoss.Equal(now) || !status.LastReceived.IsZero() {
		t.Fatalf("poll falsely counted as packet or failed clocks: %+v", status)
	}
	queueAt, lossAt := status.QueueSince, status.LastLoss
	now = now.Add(time.Minute)
	health.LastCollected = now
	if err = s.UpdateStatus(ctx, 1, "personal-token", health); err != nil {
		t.Fatal(err)
	}
	status, _ = s.GetStatus(ctx, 1)
	if !status.QueueSince.Equal(queueAt) || !status.LastLoss.Equal(lossAt) || !status.LastContact.Equal(now) {
		t.Fatal("repeat report renewed loss/queue clock", status)
	}
	health.QueueBytes = 0
	if err = s.UpdateStatus(ctx, 1, "personal-token", health); err != nil {
		t.Fatal(err)
	}
	status, _ = s.GetStatus(ctx, 1)
	if !status.QueueSince.IsZero() {
		t.Fatal("drained queue still stalled")
	}
	batch := validStoreBatch(p)
	if err = s.AcceptBatch(ctx, 1, "personal-token", batch); err != nil {
		t.Fatal(err)
	}
	status, _ = s.GetStatus(ctx, 1)
	if !status.LastReceived.Equal(now) {
		t.Fatal("batch did not update receipt")
	}
	now = now.Add(time.Second)
	// The original packet can be retried without new events; its signed ACK is
	// still fresh connectivity/progress. Keep its event time stable for dedup.
	if err = s.AcceptBatch(ctx, 1, "personal-token", batch); err != nil {
		t.Fatal(err)
	}
	status, _ = s.GetStatus(ctx, 1)
	if !status.LastReceived.Equal(now) || tableCount(t, s, "events_records") != 1 {
		t.Fatal("retry did not refresh delivery or duplicated records")
	}
	_, err = s.SetPolicy(ctx, 1, "personal-token", true, "security")
	if err != nil {
		t.Fatal(err)
	}
	status, _ = s.GetStatus(ctx, 1)
	if !status.LastContact.IsZero() || !status.LastReceived.IsZero() || !status.QueueSince.IsZero() {
		t.Fatal("new policy inherited stale health", status)
	}
	if _, err = s.Policy(ctx, 1, "replacement-token"); err != nil {
		t.Fatal(err)
	}
	if tableCount(t, s, "events_delivery") != 0 {
		t.Fatal("old registration retained delivery times")
	}
	if err = s.DeleteDevice(ctx, 1); err != nil {
		t.Fatal(err)
	}
}
