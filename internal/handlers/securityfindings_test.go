//go:build securityevents

package handlers

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"netadmin/internal/securityevents"
)

func findingFixture(t *testing.T, a *App) securityevents.Finding {
	t.Helper()
	id := eventsTestPC(t, a, "event-token")
	p, err := a.Events.SetPolicy(context.Background(), id, "event-token", true, "system")
	if err != nil {
		t.Fatal(err)
	}
	if err = a.Events.AcceptBatch(context.Background(), id, "event-token", eventsTestBatch(p)); err != nil {
		t.Fatal(err)
	}
	f, err := a.Events.Findings(context.Background(), securityevents.FindingFilter{})
	if err != nil || len(f) != 1 {
		t.Fatalf("finding fixture: %+v %v", f, err)
	}
	return f[0]
}
func findingFormCall(a *App, cookie *http.Cookie, path, id string, form url.Values, h http.HandlerFunc) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", path, strings.NewReader(form.Encode()))
	r.SetPathValue("id", id)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	h(w, r)
	return w
}

func TestFindingRolesBeforeStoreAndDemoCannotWrite(t *testing.T) {
	a := newTestApp(t)
	for _, role := range []string{"viewer", "user"} {
		cookie := sessionFor(t, a, "finding-"+role, role)
		for _, h := range []http.HandlerFunc{a.SecurityFindingPage, a.UpdateSecurityFinding, a.UpdateSecurityRule, a.AddSecurityException, a.DeleteSecurityException} {
			w := findingFormCall(a, cookie, "/events/findings/1", "1", url.Values{}, h)
			if w.Code != 403 {
				t.Fatalf("role %s bypassed guard: %d", role, w.Code)
			}
		}
	}
	a = newEventsTestApp(t)
	f := findingFixture(t, a)
	admin := sessionFor(t, a, "finding-admin", "admin")
	a.Demo = true
	w := findingFormCall(a, admin, "/events/findings/1", strconv.FormatInt(f.ID, 10), url.Values{}, a.UpdateSecurityFinding)
	if w.Code != 403 {
		t.Fatalf("demo writes: %d", w.Code)
	}
}

func TestFindingAssignmentCommentsConflictAndEscapedPage(t *testing.T) {
	a := newEventsTestApp(t)
	f := findingFixture(t, a)
	cookie := sessionFor(t, a, "finding-admin", "admin")
	sessionFor(t, a, "operator", "user")
	var adminID, operatorID int64
	a.DB.QueryRow(`SELECT id FROM users WHERE username='finding-admin'`).Scan(&adminID)
	a.DB.QueryRow(`SELECT id FROM users WHERE username='operator'`).Scan(&operatorID)
	form := url.Values{"revision": {strconv.FormatInt(f.Revision, 10)}, "status": {"in_progress"}, "assignee": {strconv.FormatInt(operatorID, 10)}, "comment": {"<img src=x onerror=alert(1)>"}}
	path := fmt.Sprintf("/events/findings/%d", f.ID)
	id := strconv.FormatInt(f.ID, 10)
	w := findingFormCall(a, cookie, path, id, form, a.UpdateSecurityFinding)
	if w.Code != 400 {
		t.Fatalf("assigned unreadable finding to operator: %d", w.Code)
	}
	form.Set("assignee", strconv.FormatInt(adminID, 10))
	w = findingFormCall(a, cookie, path, id, form, a.UpdateSecurityFinding)
	if w.Code != 303 {
		t.Fatalf("save: %d %s", w.Code, w.Body.String())
	}
	w = findingFormCall(a, cookie, path, id, form, a.UpdateSecurityFinding)
	if w.Code != 409 {
		t.Fatalf("stale overwrite accepted: %d", w.Code)
	}
	d, err := a.Events.Finding(context.Background(), f.ID)
	if err != nil || d.AssigneeID != adminID || d.Status != "in_progress" || len(d.Comments) != 1 {
		t.Fatalf("incorrect edit: %+v %v", d, err)
	}
	r := httptest.NewRequest("GET", path, nil)
	r.SetPathValue("id", id)
	r.AddCookie(cookie)
	w = httptest.NewRecorder()
	a.SecurityFindingPage(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Разбирается") || !strings.Contains(w.Body.String(), "Имя службы") || strings.Contains(w.Body.String(), "<img src=x") || strings.Contains(w.Body.String(), "<script>alert(1)</script>") {
		t.Fatalf("unsafe or unclear finding page: %d", w.Code)
	}
	form.Set("revision", strconv.FormatInt(d.Revision, 10))
	form.Set("status", "false_positive")
	form.Set("comment", "")
	w = findingFormCall(a, cookie, path, id, form, a.UpdateSecurityFinding)
	if w.Code != 303 {
		t.Fatalf("false positive failed: %d", w.Code)
	}
	var audits int
	a.DB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='events_finding'`).Scan(&audits)
	if audits != 2 {
		t.Fatalf("missing audit: %d", audits)
	}
	if _, err = a.DB.Exec(`UPDATE devices SET agent_token='replacement' WHERE id=?`, f.DeviceID); err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	a.SecurityFindingPage(w, r)
	if w.Code != 404 {
		t.Fatalf("new registration inherited finding page: %d", w.Code)
	}
}

func TestFindingRuleAndExceptionValidationAndCSRF(t *testing.T) {
	a := newEventsTestApp(t)
	cookie := sessionFor(t, a, "rules-admin", "admin")
	rules, err := a.Events.Rules(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	rule := rules[0]
	form := url.Values{"revision": {strconv.FormatInt(rule.Revision, 10)}, "enabled": {"1"}, "threshold": {"3"}, "window": {"5"}}
	w := findingFormCall(a, cookie, "/events/rules/failed_logons", "failed_logons", form, a.UpdateSecurityRule)
	if w.Code != 303 {
		t.Fatalf("rule save: %d %s", w.Code, w.Body.String())
	}
	w = findingFormCall(a, cookie, "/events/rules/failed_logons", "failed_logons", form, a.UpdateSecurityRule)
	if w.Code != 409 {
		t.Fatalf("stale rule save: %d", w.Code)
	}
	ex := url.Values{"device": {"0"}, "scope": {"account"}, "value": {"ORG\\alice"}, "reason": {"Тест обслуживания"}, "hours": {"24"}}
	w = findingFormCall(a, cookie, "/events/rules/failed_logons/exceptions", "failed_logons", ex, a.AddSecurityException)
	if w.Code != 303 {
		t.Fatalf("exception save: %d %s", w.Code, w.Body.String())
	}
	ex.Set("hours", "169")
	w = findingFormCall(a, cookie, "/events/rules/failed_logons/exceptions", "failed_logons", ex, a.AddSecurityException)
	if w.Code != 400 {
		t.Fatalf("unbounded exception accepted: %d", w.Code)
	}
	entries, err := a.Events.Exceptions(context.Background())
	if err != nil || len(entries) != 1 {
		t.Fatalf("invalid exception stored: %+v %v", entries, err)
	}
	r := httptest.NewRequest("POST", "/events/exceptions/"+strconv.FormatInt(entries[0].ID, 10)+"/delete", nil)
	r.AddCookie(cookie)
	r.RemoteAddr = "127.0.0.1:1234"
	w = httptest.NewRecorder()
	a.Routes().ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatalf("CSRF-less deletion succeeded: %d", w.Code)
	}
	w = findingFormCall(a, cookie, r.URL.Path, strconv.FormatInt(entries[0].ID, 10), url.Values{}, a.DeleteSecurityException)
	if w.Code != 303 {
		t.Fatalf("deletion failed: %d", w.Code)
	}
}
