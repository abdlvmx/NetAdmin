//go:build securityevents

package handlers

import (
	"context"
	"fmt"
	"net/url"
	"netadmin/internal/deviceaccess"
	"netadmin/internal/securityevents"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestEventsScopeFiltersEvidenceAndRejectsUnreachableAssignee(t *testing.T) {
	a := newEventsTestApp(t)
	own := findingFixture(t, a)
	otherID := eventsTestPC(t, a, "different-events-key")
	if _, err := a.DB.Exec("UPDATE devices SET hostname='FOREIGN-EVENT-PC' WHERE id=?", otherID); err != nil {
		t.Fatal(err)
	}
	policy, err := a.Events.SetPolicy(context.Background(), otherID, "different-events-key", true, "system")
	if err != nil {
		t.Fatal(err)
	}
	batch := eventsTestBatch(policy)
	batch.Events[0].Fields = map[string]string{"ServiceName": "FOREIGN-SERVICE"}
	if err = a.Events.AcceptBatch(context.Background(), otherID, "different-events-key", batch); err != nil {
		t.Fatal(err)
	}
	foreign, err := a.Events.Findings(context.Background(), securityevents.FindingFilter{DeviceID: otherID})
	if err != nil || len(foreign) != 1 {
		t.Fatal("foreign finding missing")
	}
	analyst := sessionFor(t, a, "scope-analyst", "analyst")
	otherAnalyst := sessionFor(t, a, "no-grant-analyst", "analyst")
	_ = otherAnalyst
	var user, unreachable int64
	a.DB.QueryRow("SELECT id FROM users WHERE username='scope-analyst'").Scan(&user)
	a.DB.QueryRow("SELECT id FROM users WHERE username='no-grant-analyst'").Scan(&unreachable)
	group, err := deviceaccess.CreateGroup(context.Background(), a.DB, "События отдела", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if err = deviceaccess.UpdateGroup(context.Background(), a.DB, deviceaccess.Group{ID: group, Revision: 1, Name: "События отдела"}, []int64{own.DeviceID}, 0); err != nil {
		t.Fatal(err)
	}
	if err = deviceaccess.SetUserScope(context.Background(), a.DB, user, deviceaccess.Scope{Mode: "groups", GroupIDs: []int64{group}}, 0); err != nil {
		t.Fatal(err)
	}
	if err = deviceaccess.SetUserScope(context.Background(), a.DB, unreachable, deviceaccess.Scope{Mode: "groups"}, 0); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/events", "/events?tab=logs", fmt.Sprintf("/events/findings/%d", own.ID)} {
		w := mfaRequest(a, "GET", path, nil, analyst)
		if w.Code != 200 || strings.Contains(w.Body.String(), "FOREIGN-") {
			t.Fatalf("Events leak on %s: %d %s", path, w.Code, w.Body.String())
		}
	}
	for _, path := range []string{fmt.Sprintf("/events?tab=logs&device=%d", otherID), fmt.Sprintf("/events/findings/%d", foreign[0].ID)} {
		if w := mfaRequest(a, "GET", path, nil, analyst); w.Code != 404 {
			t.Fatalf("foreign Events route accepted: %s %d", path, w.Code)
		}
	}
	path := fmt.Sprintf("/events/findings/%d", own.ID)
	form := url.Values{"revision": {strconv.FormatInt(own.Revision, 10)}, "status": {"in_progress"}, "assignee": {strconv.FormatInt(unreachable, 10)}, "comment": {"Visible comment"}}
	if w := mfaRequest(a, "POST", path, form, analyst); w.Code != 400 {
		t.Fatal("assigned finding to analyst without device grant")
	}
	form.Set("assignee", strconv.FormatInt(user, 10))
	if w := mfaRequest(a, "POST", path, form, analyst); w.Code != 303 {
		t.Fatalf("valid investigation refused: %d %s", w.Code, w.Body.String())
	}
	scope, err := deviceaccess.UserScope(context.Background(), a.DB, user)
	if err != nil {
		t.Fatal(err)
	}
	if err = deviceaccess.SetUserScope(context.Background(), a.DB, user, deviceaccess.Scope{Mode: "groups", Revision: scope.Revision}, 0); err != nil {
		t.Fatal(err)
	}
	if w := mfaRequest(a, "GET", path, nil, analyst); w.Code != 404 {
		t.Fatal("old session retained finding evidence after revocation")
	}
	w := mfaRequest(a, "GET", "/events?tab=logs", nil, analyst)
	if w.Code != 200 || strings.Contains(w.Body.String(), "FOREIGN-") {
		t.Fatal("empty scope returned all events")
	}
}

func TestEventsFilteringHappensBeforeLimitAndEmptyScopeIsNotUnrestricted(t *testing.T) {
	a := newEventsTestApp(t)
	finding := findingFixture(t, a)
	events, err := a.Events.EventsFiltered(context.Background(), securityevents.EventFilter{DeviceIDs: []int64{finding.DeviceID}, Limit: 1})
	if err != nil || len(events) != 1 {
		t.Fatal("scoped event missing")
	}
	for _, ids := range [][]int64{{}, {999999}} {
		events, err = a.Events.EventsFiltered(context.Background(), securityevents.EventFilter{DeviceIDs: ids, Limit: 1})
		if err != nil || len(events) != 0 {
			t.Fatal("empty/unrelated event scope broadened")
		}
		findings, err := a.Events.Findings(context.Background(), securityevents.FindingFilter{DeviceIDs: ids, Limit: 1})
		if err != nil || len(findings) != 0 {
			t.Fatal("empty/unrelated finding scope broadened")
		}
		gaps, err := a.Events.GapsScoped(context.Background(), 0, 1, ids)
		if err != nil || len(gaps) != 0 {
			t.Fatal("empty/unrelated gap scope broadened")
		}
	}
	// A newer foreign finding must not consume the selected device's limit.
	other := eventsTestPC(t, a, "newer-events-key")
	policy, err := a.Events.SetPolicy(context.Background(), other, "newer-events-key", true, "system")
	if err != nil {
		t.Fatal(err)
	}
	batch := eventsTestBatch(policy)
	batch.Events[0].TimeUTC = time.Now().UTC().Add(time.Second)
	if err = a.Events.AcceptBatch(context.Background(), other, "newer-events-key", batch); err != nil {
		t.Fatal(err)
	}
	findings, err := a.Events.Findings(context.Background(), securityevents.FindingFilter{DeviceIDs: []int64{finding.DeviceID}, Limit: 1})
	if err != nil || len(findings) != 1 || findings[0].DeviceID != finding.DeviceID {
		t.Fatal("foreign record displaced scoped result")
	}
}
