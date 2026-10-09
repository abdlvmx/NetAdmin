//go:build securityevents

package securityevents

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func failedEvent(record uint64, stamp time.Time, ip string) Event {
	return Event{StreamID: strings.Repeat("a", 32), Channel: "Security", Provider: "Microsoft-Windows-Security-Auditing", EventID: 4625, RecordID: record, TimeUTC: stamp, Fields: map[string]string{"TargetUserName": "alice", "TargetDomainName": "ORG", "IpAddress": ip, "LogonType": "10"}}
}
func acceptFindingEvents(t *testing.T, s *Store, p Policy, device, batch int64, events ...Event) Batch {
	t.Helper()
	b := Batch{ID: fmt.Sprintf("%032x", batch), Generation: p.Generation, Events: events}
	if err := s.AcceptBatch(context.Background(), device, "personal-token", b); err != nil {
		t.Fatal(err)
	}
	return b
}
func allFindings(t *testing.T, s *Store) []Finding {
	t.Helper()
	f, err := s.Findings(context.Background(), FindingFilter{Status: "all"})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestFindingSeriesSurvivesRestartAndDeduplicatesDelivery(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "events.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { s.Close() }()
	p := enabledStorePolicy(t, s, 1, "security")
	base := time.Now().UTC().Add(-time.Minute)
	b := acceptFindingEvents(t, s, p, 1, 1, failedEvent(1, base, "10.0.0.1"), failedEvent(2, base.Add(10*time.Second), "10.0.0.1"))
	if err = s.AcceptBatch(ctx, 1, "personal-token", b); err != nil {
		t.Fatal(err)
	}
	acceptFindingEvents(t, s, p, 1, 2, b.Events[0]) // Same record in another packet.
	acceptFindingEvents(t, s, p, 1, 3, failedEvent(3, base.Add(20*time.Second), "10.0.0.1"), failedEvent(4, base.Add(30*time.Second), "10.0.0.1"))
	if len(allFindings(t, s)) != 0 {
		t.Fatal("rule fired below threshold")
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	b = acceptFindingEvents(t, s, p, 1, 4, failedEvent(5, base.Add(15*time.Second), "10.0.0.1")) // Late event.
	if err = s.AcceptBatch(ctx, 1, "personal-token", b); err != nil {
		t.Fatal(err)
	}
	f := allFindings(t, s)
	if len(f) != 1 || f[0].EventCount != 5 || f[0].Threshold != 5 {
		t.Fatalf("incorrect correlation: %+v", f)
	}
	d, err := s.Finding(ctx, f[0].ID)
	if err != nil || len(d.Evidence) != 5 {
		t.Fatalf("evidence missing: %+v %v", d, err)
	}
	for i := uint64(6); i <= 10; i++ {
		acceptFindingEvents(t, s, p, 1, int64(i), failedEvent(i, base.Add(40*time.Second), "10.0.0.2"))
	}
	if len(allFindings(t, s)) != 2 {
		t.Fatal("different source IP was merged")
	}
	acceptFindingEvents(t, s, p, 1, 11, failedEvent(11, base.Add(45*time.Second), "10.0.0.1"))
	if err = s.UpdateFinding(ctx, f[0].ID, f[0].Revision, "closed", 0, "stale comment", "admin"); !errors.Is(err, ErrFindingConflict) {
		t.Fatalf("stale write accepted: %v", err)
	}
	d, err = s.Finding(ctx, f[0].ID)
	if err != nil || d.EventCount != 6 || len(d.Comments) != 0 {
		t.Fatalf("repeat/stale edit changed evidence: %+v %v", d, err)
	}
	if err = s.UpdateFinding(ctx, d.ID, d.Revision, "closed", 0, strings.Repeat("Я", 2000), "admin"); err != nil {
		t.Fatal(err)
	}
	for i := uint64(12); i <= 15; i++ {
		acceptFindingEvents(t, s, p, 1, int64(i), failedEvent(i, base.Add(50*time.Second), "10.0.0.1"))
	}
	if len(allFindings(t, s)) != 2 {
		t.Fatal("closed series reused old threshold")
	}
	acceptFindingEvents(t, s, p, 1, 16, failedEvent(16, base.Add(55*time.Second), "10.0.0.1"))
	f = allFindings(t, s)
	if len(f) != 3 || f[0].EventCount != 5 {
		t.Fatalf("fresh series incorrect: %+v", f)
	}
}

func TestFindingExceptionsExpireAndRegistrationDoesNotInheritData(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	s.now = func() time.Time { return now }
	p := enabledStorePolicy(t, s, 1, "security")
	ex := Exception{DeviceID: 1, RuleID: "service_installed", Scope: "service", Value: "Printer", Reason: "Плановое обновление", ExpiresAt: now.Add(time.Hour)}
	if err := s.AddException(ctx, ex); err != nil {
		t.Fatal(err)
	}
	e := validStoreEvent()
	e.TimeUTC = now
	acceptFindingEvents(t, s, p, 1, 1, e)
	if len(allFindings(t, s)) != 0 || tableCount(t, s, "events_records") != 1 {
		t.Fatal("exception either alerted or removed raw evidence")
	}
	p2 := enabledStorePolicy(t, s, 2, "system")
	acceptFindingEvents(t, s, p2, 2, 2, e)
	if f := allFindings(t, s); len(f) != 1 || f[0].DeviceID != 2 {
		t.Fatalf("device exception leaked: %+v", f)
	}
	now = now.Add(2 * time.Hour)
	e.RecordID++
	e.TimeUTC = now
	acceptFindingEvents(t, s, p, 1, 3, e)
	if len(allFindings(t, s)) != 2 {
		t.Fatal("expired exception suppressed event")
	}
	if _, err := s.Policy(ctx, 1, "replacement-token"); err != nil {
		t.Fatal(err)
	}
	f := allFindings(t, s)
	if len(f) != 1 || f[0].DeviceID != 2 || tableCount(t, s, "events_rule_exceptions") != 0 {
		t.Fatalf("new registration inherited findings: %+v", f)
	}
}

func TestFindingRulesStartFreshAndDoNotBackfillHistory(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	p := enabledStorePolicy(t, s, 1, "security")
	base := time.Now().UTC().Add(-time.Minute)
	acceptFindingEvents(t, s, p, 1, 1, failedEvent(1, base, "10.0.0.1"), failedEvent(2, base, "10.0.0.1"))
	rules, err := s.Rules(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var logon, service Rule
	for _, r := range rules {
		if r.ID == "failed_logons" {
			logon = r
		}
		if r.ID == "service_installed" {
			service = r
		}
	}
	logon.Threshold, logon.WindowMinutes = 3, 1
	if err = s.SetRule(ctx, logon); err != nil {
		t.Fatal(err)
	}
	if err = s.SetRule(ctx, logon); !errors.Is(err, ErrFindingConflict) {
		t.Fatalf("stale rule update: %v", err)
	}
	acceptFindingEvents(t, s, p, 1, 2, failedEvent(3, base, "10.0.0.1"), failedEvent(4, base, "10.0.0.1"))
	if len(allFindings(t, s)) != 0 {
		t.Fatal("settings change reused old samples")
	}
	acceptFindingEvents(t, s, p, 1, 3, failedEvent(5, base.Add(5*time.Second), "10.0.0.1"))
	if f := allFindings(t, s); len(f) != 1 || f[0].Threshold != 3 {
		t.Fatalf("new threshold ignored: %+v", f)
	}
	service.Enabled = false
	if err = s.SetRule(ctx, service); err != nil {
		t.Fatal(err)
	}
	e := validStoreEvent()
	b := acceptFindingEvents(t, s, p, 1, 4, e)
	if len(allFindings(t, s)) != 1 {
		t.Fatal("disabled rule fired")
	}
	service.Enabled = true
	service.Revision++
	if err = s.SetRule(ctx, service); err != nil {
		t.Fatal(err)
	}
	if err = s.AcceptBatch(ctx, 1, "personal-token", b); err != nil {
		t.Fatal(err)
	}
	if len(allFindings(t, s)) != 1 {
		t.Fatal("enabling backfilled old event")
	}
	e.RecordID++
	acceptFindingEvents(t, s, p, 1, 5, e)
	if len(allFindings(t, s)) != 2 {
		t.Fatal("enabled rule missed fresh event")
	}
}

func TestFindingWindowIsolationAndEventKinds(t *testing.T) {
	s := openTestStore(t)
	p := enabledStorePolicy(t, s, 1, "security")
	base := time.Now().UTC()
	for i := uint64(1); i <= 4; i++ {
		acceptFindingEvents(t, s, p, 1, int64(i), failedEvent(i, base.Add(-10*time.Minute), "10.0.0.1"))
	}
	acceptFindingEvents(t, s, p, 1, 5, failedEvent(5, base, "10.0.0.1"))
	if len(allFindings(t, s)) != 0 {
		t.Fatal("old window counted")
	}
	clear := Event{StreamID: strings.Repeat("a", 32), Channel: "Security", Provider: "Microsoft-Windows-Eventlog", EventID: 1102, RecordID: 10, TimeUTC: base}
	acceptFindingEvents(t, s, p, 1, 6, clear)
	clear.RecordID++
	acceptFindingEvents(t, s, p, 1, 7, clear)
	f := allFindings(t, s)
	if len(f) != 1 || f[0].RuleID != "log_cleared" || f[0].Severity != "high" || f[0].EventCount != 2 {
		t.Fatalf("clear signal wrong: %+v", f)
	}
	clear.Channel = "System"
	clear.EventID = 104
	clear.RecordID = 12
	clear.Fields = map[string]string{"Channel": "System"}
	acceptFindingEvents(t, s, p, 1, 8, clear)
	if len(allFindings(t, s)) != 2 {
		t.Fatal("different cleared channel was merged")
	}
}

func TestFindingEvidenceBoundsRetentionAndAtomicFailure(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	p := enabledStorePolicy(t, s, 1, "system")
	now := time.Now().UTC()
	s.now = func() time.Time { return now }
	var events []Event
	for i := 0; i < 70; i++ {
		e := validStoreEvent()
		e.RecordID = uint64(i + 1)
		e.TimeUTC = now.Add(-time.Duration(i) * time.Second)
		events = append(events, e)
	}
	acceptFindingEvents(t, s, p, 1, 1, events...)
	f := allFindings(t, s)
	if len(f) != 1 || f[0].EventCount != 70 {
		t.Fatalf("group count: %+v", f)
	}
	d, err := s.Finding(ctx, f[0].ID)
	if err != nil || len(d.Evidence) != MaxFindingEvidence {
		t.Fatalf("evidence bound: %d %v", len(d.Evidence), err)
	}
	if err = s.UpdateFinding(ctx, d.ID, d.Revision, "false_positive", 0, "Тест <script>alert(1)</script>", "admin"); err != nil {
		t.Fatal(err)
	}
	now = now.Add(8 * 24 * time.Hour)
	if err = s.cleanup(ctx); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"events_findings", "events_finding_evidence", "events_finding_comments", "events_rule_samples"} {
		if tableCount(t, s, table) != 0 {
			t.Fatalf("retained expired %s", table)
		}
	}
	if _, err = s.db.Exec(`DROP TABLE events_findings`); err != nil {
		t.Fatal(err)
	}
	e := validStoreEvent()
	e.TimeUTC = now
	batch := Batch{ID: fmt.Sprintf("%032x", 2), Generation: p.Generation, Events: []Event{e}}
	if err = s.AcceptBatch(ctx, 1, "personal-token", batch); err == nil {
		t.Fatal("finding storage failure acknowledged")
	}
	if tableCount(t, s, "events_records") != 0 || tableCount(t, s, "events_receipts") != 0 {
		t.Fatal("failed finding transaction left partial events")
	}
}
