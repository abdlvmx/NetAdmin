//go:build securityevents

package handlers

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"netadmin/internal/config"
	"netadmin/internal/securityevents"
)

func backupTestApp(t *testing.T) *App {
	t.Helper()
	a := newTestApp(t)
	c := config.Load()
	c.BackupIntervalHours = 0
	c.BackupKeep = 7
	if err := config.Save(c); err != nil {
		t.Fatal(err)
	}
	closeEvents, err := a.StartEvents(config.DataDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(closeEvents)
	return a
}

func backupActionCall(a *App, cookie *http.Cookie, operation string, form url.Values, csrf bool) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "/events/backups/"+operation, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.RemoteAddr = "127.0.0.1:1234"
	if cookie != nil {
		r.AddCookie(cookie)
	}
	if csrf {
		r.AddCookie(&http.Cookie{Name: csrfCookie, Value: "backup-test"})
		r.Header.Set("X-CSRF-Token", "backup-test")
	}
	w := httptest.NewRecorder()
	a.Routes().ServeHTTP(w, r)
	return w
}

func TestEventsBackupsAccessCSRFValidationAndAudit(t *testing.T) {
	a := backupTestApp(t)
	for _, role := range []string{"user", "viewer"} {
		cookie := sessionFor(t, a, "copy-"+role, role)
		for _, op := range []string{"now", "verify", "restore", "cancel"} {
			if w := backupActionCall(a, cookie, op, url.Values{}, true); w.Code != 403 {
				t.Fatalf("%s/%s status=%d", role, op, w.Code)
			}
		}
	}
	admin := sessionFor(t, a, "copy-admin", "admin")
	dir := eventsBackupDirectory(config.DataDir(), config.Load())
	if w := backupActionCall(a, admin, "now", url.Values{}, false); w.Code != 403 {
		t.Fatal("CSRF bypass", w.Code)
	}
	if list, _ := securityevents.ListBackups(dir); len(list) != 0 {
		t.Fatal("unauthorized copy created")
	}
	w := backupActionCall(a, admin, "now", url.Values{}, true)
	if w.Code != 303 {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	list, err := securityevents.ListBackups(dir)
	if err != nil || len(list) != 1 {
		t.Fatal("copy not created", err)
	}
	name := list[0].Name
	for _, op := range []string{"verify", "restore"} {
		form := url.Values{"name": {name}, "confirm": {"1"}}
		w = backupActionCall(a, admin, op, form, true)
		if w.Code != 303 {
			t.Fatalf("%s: %d %s", op, w.Code, w.Body.String())
		}
	}
	if !a.eventsBackupPanel().Pending {
		t.Fatal("staged restore not displayed")
	}
	w = backupActionCall(a, admin, "cancel", url.Values{}, true)
	if w.Code != 303 || a.eventsBackupPanel().Pending {
		t.Fatal("cancel failed", w.Code)
	}
	w = backupActionCall(a, admin, "restore", url.Values{"name": {name}}, true)
	if w.Code != 400 || a.eventsBackupPanel().Pending {
		t.Fatal("missing restore consent accepted", w.Code)
	}
	w = backupActionCall(a, admin, "restore", url.Values{"name": {"../netadmin.db"}, "confirm": {"1"}}, true)
	if w.Code == 303 || a.eventsBackupPanel().Pending {
		t.Fatal("foreign path staged")
	}
	var n int
	if err = a.DB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action IN('events_backup','events_backup_verify','events_restore_stage','events_restore_cancel')`).Scan(&n); err != nil || n != 4 {
		t.Fatalf("audit count=%d err=%v", n, err)
	}
	a.Demo = true
	for _, op := range []string{"now", "verify", "restore", "cancel"} {
		if w = backupActionCall(a, admin, op, url.Values{"name": {name}, "confirm": {"1"}}, true); w.Code != 403 {
			t.Fatalf("demo %s writes: %d", op, w.Code)
		}
	}
}

func TestEventsScheduledBackupIsIndependentAndDoesNotRepeatEarly(t *testing.T) {
	a := backupTestApp(t)
	cfg := config.Load()
	cfg.BackupIntervalHours = 24
	cfg.BackupKeep = 2
	cfg.BackupDir = filepath.Join(t.TempDir(), "copies")
	if err := config.Save(cfg); err != nil {
		t.Fatal(err)
	}
	// A fresh inventory backup must not postpone the first Events copy.
	if err := os.MkdirAll(cfg.BackupDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfg.BackupDir, "netadmin-2026-10-09-0000.db"), []byte("inventory"), 0600); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	a.eventsBackupTick(ctx, config.DataDir())
	a.eventsBackupTick(ctx, config.DataDir())
	list, err := securityevents.ListBackups(eventsBackupDirectory(config.DataDir(), cfg))
	if err != nil || len(list) != 1 {
		t.Fatalf("schedule %+v %v", list, err)
	}
	if err = securityevents.VerifyBackup(ctx, filepath.Join(eventsBackupDirectory(config.DataDir(), cfg), list[0].Name)); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-25 * time.Hour)
	if err = os.Chtimes(filepath.Join(eventsBackupDirectory(config.DataDir(), cfg), list[0].Name), old, old); err != nil {
		t.Fatal(err)
	}
	if a.eventsBackupPanel().Problem == "" {
		t.Fatal("overdue copy not reported")
	}
	a.eventsBackupTick(ctx, config.DataDir())
	list, _ = securityevents.ListBackups(eventsBackupDirectory(config.DataDir(), cfg))
	if len(list) != 2 || a.eventsBackupPanel().Problem != "" {
		t.Fatal("due copy not refreshed")
	}
	cfg.BackupIntervalHours = 0
	if err = config.Save(cfg); err != nil {
		t.Fatal(err)
	}
	a.eventsBackupTick(ctx, config.DataDir())
	list, _ = securityevents.ListBackups(eventsBackupDirectory(config.DataDir(), cfg))
	if len(list) != 2 {
		t.Fatal("disabled schedule wrote")
	}
}

func TestEventsDeliverySummaryIsAdminOnlyAndQuietLogsAreHealthy(t *testing.T) {
	a := backupTestApp(t)
	id := eventsTestPC(t, a, "event-token")
	ctx := context.Background()
	p, err := a.Events.SetPolicy(ctx, id, "event-token", true, "system")
	if err != nil {
		t.Fatal(err)
	}
	s := securityevents.Status{Generation: p.Generation, State: "collecting", LastCollected: time.Now().UTC(), Channels: []securityevents.ChannelStatus{{Channel: "System", State: "ready"}}}
	if err = a.Events.UpdateStatus(ctx, id, "event-token", s); err != nil {
		t.Fatal(err)
	}
	admin := sessionFor(t, a, "delivery-admin", "admin")
	viewer := sessionFor(t, a, "delivery-viewer", "viewer")
	r := httptest.NewRequest("GET", "/dashboard", nil)
	r.AddCookie(admin)
	if groups := a.eventsIssueGroups(r); len(groups) != 0 {
		t.Fatal("quiet logs treated as failure", groups)
	}
	// Age only server contact, keeping the historical collecting report intact.
	d, err := sql.Open("sqlite", filepath.Join(config.DataDir(), "security-events.db"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = d.Exec(`UPDATE events_delivery SET last_poll=? WHERE device_id=?`, time.Now().Add(-4*time.Minute).UnixMilli(), id)
	d.Close()
	if err != nil {
		t.Fatal(err)
	}
	groups := a.eventsIssueGroups(r)
	if len(groups) != 1 || groups[0].Total != 1 || groups[0].Items[0].Detail != "Нет связи Events" {
		t.Fatal("stale connection not reported", groups)
	}
	w := httptest.NewRecorder()
	a.Dashboard(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Нет связи Events") {
		t.Fatal("dashboard missing issue", w.Code)
	}
	r = httptest.NewRequest("GET", "/dashboard", nil)
	r.AddCookie(viewer)
	if groups = a.eventsIssueGroups(r); len(groups) != 0 {
		t.Fatal("Events leaked to viewer", groups)
	}
	w = httptest.NewRecorder()
	a.Dashboard(w, r)
	if strings.Contains(w.Body.String(), "Сбор и доставка Events") {
		t.Fatal("Events dashboard leaked to viewer")
	}
	r = httptest.NewRequest("GET", "/events?tab=collection", nil)
	r.AddCookie(admin)
	w = httptest.NewRecorder()
	a.SecurityEventsPage(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Прежний статус сбора устарел") {
		t.Fatal("page missing stale status/backup panel", w.Code)
	}
	if _, err = a.Events.SetPolicy(ctx, id, "event-token", false, "system"); err != nil {
		t.Fatal(err)
	}
	r = httptest.NewRequest("GET", "/dashboard", nil)
	r.AddCookie(admin)
	if groups = a.eventsIssueGroups(r); len(groups) != 0 {
		t.Fatal("disabled PC alarmed", groups)
	}
}
