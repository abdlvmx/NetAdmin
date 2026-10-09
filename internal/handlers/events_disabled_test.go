//go:build !securityevents

package handlers

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestStandardEditionDoesNotCreateEventsStoreOrExposeRoutes(t *testing.T) {
	a := newTestApp(t)
	dir := t.TempDir()
	closeEvents, err := a.StartEvents(dir)
	if err != nil {
		t.Fatal(err)
	}
	closeEvents()
	if _, err = os.Stat(filepath.Join(dir, "security-events.db")); !os.IsNotExist(err) {
		t.Fatal("standard edition created Events storage")
	}
	h := a.Routes()
	for _, p := range []string{"/events", "/events/findings/1", "/events/rules/failed_logons", "/events/rules/failed_logons/exceptions", "/events/exceptions/1/delete", "/events/backups/now", "/events/backups/verify", "/events/backups/restore", "/events/backups/cancel", "/api/agent-events/poll", "/api/agent-events/batch"} {
		method := "POST"
		if p == "/events" || p == "/events/findings/1" {
			method = "GET"
		}
		r := httptest.NewRequest(method, p, nil)
		r.AddCookie(&http.Cookie{Name: csrfCookie, Value: "standard-test"})
		r.Header.Set("X-CSRF-Token", "standard-test")
		r.RemoteAddr = "127.0.0.1:1234"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 404 {
			t.Errorf("standard module route %s responded %d", p, w.Code)
		}
	}
}
