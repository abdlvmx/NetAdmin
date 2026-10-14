//go:build securityevents

package handlers

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

func TestEventsAnalystInvestigatesWithoutAdministration(t *testing.T) {
	a := newEventsTestApp(t)
	finding := findingFixture(t, a)
	analyst := sessionFor(t, a, "events-analyst", "analyst")
	var analystID int64
	if err := a.DB.QueryRow("SELECT id FROM users WHERE username='events-analyst'").Scan(&analystID); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/events", "/events?tab=logs", fmt.Sprintf("/events/findings/%d", finding.ID)} {
		w := mfaRequest(a, "GET", path, nil, analyst)
		if w.Code != 200 {
			t.Fatalf("analyst cannot read %s: %d %s", path, w.Code, w.Body.String())
		}
		if strings.Contains(w.Body.String(), "Правила и исключения</a>") || strings.Contains(w.Body.String(), ">Настроить расписание</a>") {
			t.Fatalf("administrative control exposed on %s", path)
		}
	}
	for _, path := range []string{"/events?tab=collection", "/events?tab=rules", "/events?tab=backups"} {
		if w := mfaRequest(a, "GET", path, nil, analyst); w.Code != 403 {
			t.Fatalf("analyst read admin tab %s: %d", path, w.Code)
		}
	}
	for _, path := range []string{"/events/devices/1/policy", "/events/rules/service_installed", "/events/rules/service_installed/exceptions", "/events/exceptions/1/delete", "/events/backups/now", "/events/backups/verify", "/events/backups/restore", "/events/backups/cancel"} {
		if w := mfaRequest(a, "POST", path, nil, analyst); w.Code != 403 {
			t.Fatalf("analyst changed admin state %s: %d", path, w.Code)
		}
	}
	w := mfaRequest(a, "POST", fmt.Sprintf("/events/findings/%d", finding.ID), url.Values{
		"revision": {strconv.FormatInt(finding.Revision, 10)}, "status": {"in_progress"}, "assignee": {strconv.FormatInt(analystID, 10)}, "comment": {"Проверяю установку службы."},
	}, analyst)
	if w.Code != 303 {
		t.Fatalf("analyst cannot investigate: %d %s", w.Code, w.Body.String())
	}
	saved, err := a.Events.Finding(context.Background(), finding.ID)
	if err != nil || saved.AssigneeID != analystID || saved.Status != "in_progress" || len(saved.Comments) != 1 {
		t.Fatalf("investigation not saved: %+v %v", saved, err)
	}
	w = mfaRequest(a, "POST", "/login", url.Values{"username": {"events-analyst"}, "password": {"Parol12345"}})
	if w.Code != 303 || w.Header().Get("Location") != "/events" {
		t.Fatal("analyst login did not open investigations")
	}
}

func TestEventsAnalystRoleCreationAndStoreUnavailable(t *testing.T) {
	a := newTestApp(t)
	admin := sessionFor(t, a, "role-admin", "admin")
	w := mfaRequest(a, "POST", "/users/create", url.Values{"username": {"new-analyst"}, "role": {"analyst"}, "password": {"Parol12345"}}, admin)
	if w.Code != 303 {
		t.Fatal("analyst creation failed")
	}
	var role string
	if err := a.DB.QueryRow("SELECT role FROM users WHERE username='new-analyst'").Scan(&role); err != nil || role != "analyst" {
		t.Fatalf("wrong role: %s %v", role, err)
	}
	analyst := sessionFor(t, a, "offline-analyst", "analyst")
	if w := mfaRequest(a, "GET", "/events", nil, analyst); w.Code != 503 {
		t.Fatalf("unavailable store: %d", w.Code)
	}
	if w := mfaRequest(a, "POST", "/events/backups/now", nil, analyst); w.Code != 403 {
		t.Fatal("store unavailable bypassed admin guard")
	}
}
