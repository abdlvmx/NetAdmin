//go:build securityevents

package handlers

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"netadmin/internal/config"
	"netadmin/internal/securityevents"
)

func newEventsTestApp(t *testing.T) *App {
	t.Helper()
	a := newTestApp(t)
	closeStore, err := a.StartEvents(config.DataDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(closeStore)
	return a
}

func eventsTestPC(t *testing.T, a *App, token string) int64 {
	t.Helper()
	res, err := a.DB.Exec(`INSERT INTO devices(hostname,os_type,device_type,agent_token,agent_capabilities)
		VALUES('Events-PC','Windows','ПК',?,'["security_events_v1"]')`, token)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := res.LastInsertId()
	return id
}

func eventsSignedCall(t *testing.T, a *App, id int64, token, path string, payload map[string]any, secure bool) *httptest.ResponseRecorder {
	t.Helper()
	payload["timestamp"] = time.Now().Unix()
	payload["nonce"] = testNonce(t)
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", path, bytes.NewReader(body))
	r.Header.Set(hdrDevice, strconv.FormatInt(id, 10))
	r.Header.Set(hdrSig, mac(token, body))
	r.Header.Set("X-Forwarded-Proto", "https")
	r.RemoteAddr = "127.0.0.1:1234"
	if secure {
		r.TLS = &tls.ConnectionState{}
	}
	w := httptest.NewRecorder()
	a.Routes().ServeHTTP(w, r)
	return w
}

func eventsPolicyCall(t *testing.T, a *App, id int64, cookie *http.Cookie, form url.Values, secure bool) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest("POST", "/events/devices/"+strconv.FormatInt(id, 10)+"/policy", strings.NewReader(form.Encode()))
	r.SetPathValue("id", strconv.FormatInt(id, 10))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if cookie != nil {
		r.AddCookie(cookie)
	}
	if secure {
		r.TLS = &tls.ConnectionState{}
	}
	w := httptest.NewRecorder()
	a.SetSecurityEventsPolicy(w, r)
	return w
}

func eventsConfigureTLS(t *testing.T) {
	t.Helper()
	c := config.Load()
	c.TLSCertFile, c.TLSKeyFile, c.PublicURL = "server.crt", "server.key", "https://localhost:8765"
	if err := config.Save(c); err != nil {
		t.Fatal(err)
	}
}

func eventsTestBatch(p securityevents.Policy) securityevents.Batch {
	return securityevents.Batch{ID: strings.Repeat("a", 32), Generation: p.Generation,
		Events: []securityevents.Event{{StreamID: strings.Repeat("b", 32), Channel: "System", Provider: "Service Control Manager", EventID: 7045,
			RecordID: 41, TimeUTC: time.Now().UTC().Truncate(time.Second), Fields: map[string]string{"ServiceName": "<script>alert(1)</script>"}}}}
}

func TestEventsAdministratorsOnlyBeforeStoreAvailability(t *testing.T) {
	a := newTestApp(t)
	for _, role := range []string{"", "user", "viewer", "admin"} {
		var cookie *http.Cookie
		if role != "" {
			cookie = sessionFor(t, a, "events-"+role, role)
		}
		r := httptest.NewRequest("GET", "/events", nil)
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		a.SecurityEventsPage(w, r)
		want := http.StatusForbidden
		if role == "admin" {
			want = http.StatusServiceUnavailable
		}
		if w.Code != want {
			t.Errorf("page role=%q status=%d want=%d", role, w.Code, want)
		}
		w = eventsPolicyCall(t, a, 1, cookie, url.Values{"enabled": {"1"}}, true)
		if w.Code != want {
			t.Errorf("policy role=%q status=%d want=%d", role, w.Code, want)
		}
	}
}

func TestEventsDefaultOffAndRequiresNativeHTTPS(t *testing.T) {
	a := newEventsTestApp(t)
	id := eventsTestPC(t, a, "event-token")
	payload := map[string]any{"capabilities": []string{securityevents.Capability}, "status": securityevents.Status{State: "disabled"}}
	for _, path := range []string{"/api/agent-events/poll", "/api/agent-events/batch"} {
		w := eventsSignedCall(t, a, id, "event-token", path, payload, false)
		if w.Code != http.StatusForbidden || w.Header().Get(hdrSig) != "" {
			t.Fatalf("HTTP accepted %s: %d", path, w.Code)
		}
	}
	w := eventsSignedCall(t, a, id, "event-token", "/api/agent-events/poll", payload, true)
	var response securityevents.PollResponse
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &response) != nil || response.Policy.Enabled || w.Header().Get(hdrSig) != mac("event-token", w.Body.Bytes()) {
		t.Fatalf("default-off signed response: %d %s", w.Code, w.Body.String())
	}
	w = eventsSignedCall(t, a, id, "event-token", "/api/agent-events/batch", map[string]any{"batch": eventsTestBatch(response.Policy)}, true)
	if w.Code == http.StatusOK || w.Header().Get(hdrSig) != "" {
		t.Fatalf("disabled batch acknowledged: %d %s", w.Code, w.Body.String())
	}
}

func TestEventsConsentProfilesEligibilityAndAudit(t *testing.T) {
	a := newEventsTestApp(t)
	id := eventsTestPC(t, a, "event-token")
	admin := sessionFor(t, a, "events-admin", "admin")
	form := url.Values{"enabled": {"1"}, "profile": {"system"}, "consent": {"1"}}
	if w := eventsPolicyCall(t, a, id, admin, form, true); w.Code != http.StatusForbidden {
		t.Fatalf("enable without configured native HTTPS: %d", w.Code)
	}
	eventsConfigureTLS(t)
	if w := eventsPolicyCall(t, a, id, admin, form, false); w.Code != http.StatusForbidden {
		t.Fatalf("enable over HTTP: %d", w.Code)
	}
	form.Del("consent")
	if w := eventsPolicyCall(t, a, id, admin, form, true); w.Code != http.StatusBadRequest {
		t.Fatalf("enable without consent: %d", w.Code)
	}
	form.Set("consent", "1")
	form.Set("profile", "security")
	if w := eventsPolicyCall(t, a, id, admin, form, true); w.Code != http.StatusBadRequest {
		t.Fatalf("Security without privacy consent: %d", w.Code)
	}
	form.Set("security_privacy", "1")
	for _, field := range []string{"agent_capabilities", "agent_token", "device_type"} {
		var previous string
		if err := a.DB.QueryRow("SELECT "+field+" FROM devices WHERE id=?", id).Scan(&previous); err != nil {
			t.Fatal(err)
		}
		unavailable := "unsupported"
		if field == "agent_token" {
			unavailable = ""
		}
		if _, err := a.DB.Exec("UPDATE devices SET "+field+"=? WHERE id=?", unavailable, id); err != nil {
			t.Fatal(err)
		}
		if w := eventsPolicyCall(t, a, id, admin, form, true); w.Code != http.StatusConflict {
			t.Fatalf("unsupported %s enabled: %d %s", field, w.Code, w.Body.String())
		}
		if _, err := a.DB.Exec("UPDATE devices SET "+field+"=? WHERE id=?", previous, id); err != nil {
			t.Fatal(err)
		}
	}
	a.Demo = true
	if w := eventsPolicyCall(t, a, id, admin, form, true); w.Code != http.StatusForbidden {
		t.Fatalf("demo enabled: %d", w.Code)
	}
	a.Demo = false
	if w := eventsPolicyCall(t, a, id, admin, form, true); w.Code != http.StatusSeeOther {
		t.Fatalf("enable with consent: %d %s", w.Code, w.Body.String())
	}
	p, err := a.Events.Policy(context.Background(), id, "event-token")
	if err != nil || !p.Enabled || p.Profile != "security" || p.Generation == "" {
		t.Fatalf("saved policy: %+v %v", p, err)
	}
	var audit string
	if err := a.DB.QueryRow(`SELECT detail FROM audit_log WHERE action='events_policy'`).Scan(&audit); err != nil || !strings.Contains(audit, "security_privacy=true") || strings.Contains(audit, "event-token") {
		t.Fatalf("consent audit: %q %v", audit, err)
	}
}

func TestEventsCommittedRetriesBadBatchAndTokenChange(t *testing.T) {
	a := newEventsTestApp(t)
	id := eventsTestPC(t, a, "event-token")
	p, err := a.Events.SetPolicy(context.Background(), id, "event-token", true, "system")
	if err != nil {
		t.Fatal(err)
	}
	batch := eventsTestBatch(p)
	for i := 0; i < 2; i++ {
		w := eventsSignedCall(t, a, id, "event-token", "/api/agent-events/batch", map[string]any{"batch": batch}, true)
		if w.Code != http.StatusOK || w.Body.String() != `{"ok":true}` || w.Header().Get(hdrSig) != mac("event-token", w.Body.Bytes()) {
			t.Fatalf("committed retry %d: %d %s", i, w.Code, w.Body.String())
		}
	}
	rows, err := a.Events.Events(context.Background(), id, 100)
	if err != nil || len(rows) != 1 {
		t.Fatalf("retry duplicated events: %d %v", len(rows), err)
	}
	bad := eventsTestBatch(p)
	bad.ID = strings.Repeat("c", 32)
	bad.Events[0].RecordID++
	bad.Events[0].Fields["CommandLine"] = "sensitive"
	w := eventsSignedCall(t, a, id, "event-token", "/api/agent-events/batch", map[string]any{"batch": bad}, true)
	if w.Code != http.StatusBadRequest || w.Header().Get(hdrSig) != "" {
		t.Fatalf("bad batch acknowledged: %d %s", w.Code, w.Body.String())
	}
	if _, err := a.DB.Exec("UPDATE devices SET agent_token='changed-token' WHERE id=?", id); err != nil {
		t.Fatal(err)
	}
	w = eventsSignedCall(t, a, id, "changed-token", "/api/agent-events/poll", map[string]any{"capabilities": []string{securityevents.Capability},
		"status": securityevents.Status{Generation: p.Generation, State: "paused", QueueBytes: 128}}, true)
	var changed securityevents.PollResponse
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &changed) != nil || changed.Policy.Enabled {
		t.Fatalf("token rotation retained consent: %d %s", w.Code, w.Body.String())
	}
	w = eventsSignedCall(t, a, id, "changed-token", "/api/agent-events/batch", map[string]any{"batch": batch}, true)
	if w.Code != http.StatusForbidden || w.Header().Get(hdrSig) != "" {
		t.Fatalf("batch accepted after token change: %d %s", w.Code, w.Body.String())
	}
}

func TestEventsPageUnenrolledPCFiltersAndEscaping(t *testing.T) {
	a := newEventsTestApp(t)
	id := eventsTestPC(t, a, "event-token")
	eventsTestPC(t, a, "")
	p, err := a.Events.SetPolicy(context.Background(), id, "event-token", true, "system")
	if err != nil {
		t.Fatal(err)
	}
	if err = a.Events.AcceptBatch(context.Background(), id, "event-token", eventsTestBatch(p)); err != nil {
		t.Fatal(err)
	}
	admin := sessionFor(t, a, "events-page-admin", "admin")
	for _, filter := range []string{"?tab=collection", "?tab=logs", "?device=" + strconv.FormatInt(id, 10) + "&channel=System", "?channel=Security"} {
		r := httptest.NewRequest("GET", "/events"+filter, nil)
		r.AddCookie(admin)
		w := httptest.NewRecorder()
		a.SecurityEventsPage(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("page filter %q: %d %s", filter, w.Code, w.Body.String())
		}
		if filter == "?tab=collection" && !strings.Contains(w.Body.String(), "Агент не зарегистрирован") {
			t.Fatal("collection omits unenrolled PC")
		}
		if strings.Contains(w.Body.String(), "<script>alert(1)</script>") {
			t.Fatal("unescaped event fields")
		}
		recent := w.Body.String()
		if start := strings.Index(recent, `<table id="events-recent">`); start >= 0 {
			recent = recent[start:]
			if end := strings.Index(recent, `</table>`); end >= 0 {
				recent = recent[:end]
			}
		}
		if filter == "?channel=Security" && strings.Contains(recent, "alert(1)") {
			t.Fatal("channel filter did not exclude System event")
		}
	}
}

func TestEventsBatchLimitsAndFailedCommitHaveNoACK(t *testing.T) {
	a := newEventsTestApp(t)
	id := eventsTestPC(t, a, "event-token")
	p, err := a.Events.SetPolicy(context.Background(), id, "event-token", true, "system")
	if err != nil {
		t.Fatal(err)
	}
	batch := eventsTestBatch(p)
	oversized := map[string]any{"batch": batch, "padding": strings.Repeat("x", securityevents.MaxBatchBytes)}
	w := eventsSignedCall(t, a, id, "event-token", "/api/agent-events/batch", oversized, true)
	if w.Code == http.StatusOK || w.Header().Get(hdrSig) != "" {
		t.Fatalf("oversized batch acknowledged: %d", w.Code)
	}
	tooMany := batch
	tooMany.Events = make([]securityevents.Event, securityevents.MaxBatchEvents+1)
	for i := range tooMany.Events {
		tooMany.Events[i] = batch.Events[0]
		tooMany.Events[i].RecordID = uint64(i + 1)
	}
	w = eventsSignedCall(t, a, id, "event-token", "/api/agent-events/batch", map[string]any{"batch": tooMany}, true)
	if w.Code != http.StatusBadRequest || w.Header().Get(hdrSig) != "" {
		t.Fatalf("too many events acknowledged: %d %s", w.Code, w.Body.String())
	}
	if err = a.Events.Close(); err != nil {
		t.Fatal(err)
	}
	w = eventsSignedCall(t, a, id, "event-token", "/api/agent-events/batch", map[string]any{"batch": batch}, true)
	if w.Code != http.StatusServiceUnavailable || w.Header().Get(hdrSig) != "" || strings.Contains(w.Body.String(), `"ok":true`) {
		t.Fatalf("failed commit acknowledged: %d %s", w.Code, w.Body.String())
	}
}

func TestEventsCapabilityLossRequiresFreshConsent(t *testing.T) {
	a := newEventsTestApp(t)
	id := eventsTestPC(t, a, "event-token")
	p, err := a.Events.SetPolicy(context.Background(), id, "event-token", true, "system")
	if err != nil {
		t.Fatal(err)
	}
	for _, caps := range [][]string{{}, {securityevents.Capability}} {
		w := eventsSignedCall(t, a, id, "event-token", "/api/agent-events/poll", map[string]any{"capabilities": caps,
			"status": securityevents.Status{State: "collecting", Generation: p.Generation}}, true)
		var response securityevents.PollResponse
		if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &response) != nil || response.Policy.Enabled {
			t.Fatalf("capability loss restored consent: %d %s", w.Code, w.Body.String())
		}
	}
	stored, err := a.Events.Policy(context.Background(), id, "event-token")
	if err != nil || stored.Enabled {
		t.Fatalf("incompatible policy remains enabled: %+v %v", stored, err)
	}
}
