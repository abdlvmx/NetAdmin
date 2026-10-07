package handlers

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"

	"netadmin/internal/version"
)

func TestHealthReportsReadyBuildAndProcessWithoutLogin(t *testing.T) {
	app := newTestApp(t)
	r := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	r.RemoteAddr = "127.0.0.1:4567"
	w := httptest.NewRecorder()
	app.Routes().ServeHTTP(w, r)
	if w.Code != http.StatusOK || w.Body.String() != "ok" {
		t.Fatalf("health = %d %q; want 200 ok", w.Code, w.Body.String())
	}
	if got := w.Header().Get("X-NetAdmin-Version"); got != version.Value {
		t.Errorf("health build = %q; want %q", got, version.Value)
	}
	if got := w.Header().Get("X-NetAdmin-PID"); got != strconv.Itoa(os.Getpid()) {
		t.Errorf("health process = %q; want %d", got, os.Getpid())
	}
}

func TestHealthDoesNotReportReadyWhenDatabaseIsClosed(t *testing.T) {
	app := newTestApp(t)
	if err := app.DB.Close(); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	r.RemoteAddr = "127.0.0.1:4567"
	w := httptest.NewRecorder()
	app.Routes().ServeHTTP(w, r)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("health with closed database = %d %q; want 503", w.Code, w.Body.String())
	}
}
