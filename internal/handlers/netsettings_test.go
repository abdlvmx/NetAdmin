package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"netadmin/internal/config"
)

func location(rec *httptest.ResponseRecorder) string { return rec.Header().Get("Location") }

// TestUpdateNetworkRefusesSelfLockout — главная защита формы: список подсетей,
// не включающий адрес того, кто его задаёт, после перезапуска отрезал бы доступ
// к интерфейсу, и вернуть его можно было бы только правкой config.json руками
// на самой машине.
func TestUpdateNetworkRefusesSelfLockout(t *testing.T) {
	app := newTestApp(t)
	admin := sessionFor(t, app, "admin", "admin")

	form := url.Values{"allow_subnets": {"10.0.0.0/8"}}
	r := httptest.NewRequest("POST", "/settings/network", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.RemoteAddr = "192.168.1.50:40000"
	r.AddCookie(admin)
	rec := httptest.NewRecorder()

	app.UpdateNetwork(rec, r)

	if !strings.Contains(location(rec), "error=") {
		t.Fatalf("список без своего адреса принят, перенаправление: %s", location(rec))
	}
	if got := config.Load().AllowSubnets; got != "" {
		t.Errorf("настройка сохранена вопреки отказу: %q", got)
	}
}

// TestUpdateNetworkSavesValidValues — обратная сторона: список со своим адресом
// проходит и сохраняется.
func TestUpdateNetworkSavesValidValues(t *testing.T) {
	app := newTestApp(t)
	admin := sessionFor(t, app, "admin", "admin")

	form := url.Values{
		"allow_subnets": {"192.168.1.0/24"},
		"listen_addr":   {"0.0.0.0:8765"},
	}
	r := httptest.NewRequest("POST", "/settings/network", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.RemoteAddr = "192.168.1.50:40000"
	r.AddCookie(admin)
	rec := httptest.NewRecorder()

	app.UpdateNetwork(rec, r)

	if strings.Contains(location(rec), "error=") {
		t.Fatalf("верные значения отклонены: %s", location(rec))
	}
	cfg := config.Load()
	if cfg.AllowSubnets != "192.168.1.0/24" || cfg.ListenAddr != "0.0.0.0:8765" {
		t.Errorf("сохранено %q / %q", cfg.AllowSubnets, cfg.ListenAddr)
	}
}

// TestValidListenAddr — адрес читается только при старте, поэтому опечатка
// в нём обнаружилась бы лишь после перезапуска, когда сервер уже не поднялся.
func TestValidListenAddr(t *testing.T) {
	good := []string{"", "0.0.0.0:8765", ":9000", "127.0.0.1:8765"}
	bad := []string{"8765", "0.0.0.0", "0.0.0.0:0", "0.0.0.0:70000", "0.0.0.0:порт"}

	for _, s := range good {
		if err := validListenAddr(s); err != nil {
			t.Errorf("отклонён верный адрес %q: %v", s, err)
		}
	}
	for _, s := range bad {
		if err := validListenAddr(s); err == nil {
			t.Errorf("принят негодный адрес %q", s)
		}
	}
}

// TestRestoreBackupRejectsUnknownName — имя копии приходит из формы, и путь по
// нему не собирается: файл ищется среди уже известных копий.
func TestRestoreBackupRejectsUnknownName(t *testing.T) {
	app := newTestApp(t)
	admin := sessionFor(t, app, "admin", "admin")

	for _, name := range []string{"нет-такой.db", `..\..\windows\system32\config\SAM`, ""} {
		form := url.Values{"name": {name}}
		r := httptest.NewRequest("POST", "/settings/backup/restore", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.AddCookie(admin)
		rec := httptest.NewRecorder()

		app.RestoreBackup(rec, r)

		if !strings.Contains(location(rec), "error=") {
			t.Errorf("имя %q принято, перенаправление: %s", name, location(rec))
		}
	}
}

// TestRestartServerWithoutService — из консоли перезапуск невозможен, и
// интерфейс должен это объяснить, а не молча ничего не сделать.
func TestRestartServerWithoutService(t *testing.T) {
	app := newTestApp(t)
	admin := sessionFor(t, app, "admin", "admin")

	r := httptest.NewRequest("POST", "/settings/restart", nil)
	r.AddCookie(admin)
	rec := httptest.NewRecorder()

	app.RestartServer(rec, r)

	if !strings.Contains(location(rec), "error=") {
		t.Errorf("перезапуск без службы не объяснён: %s", location(rec))
	}
}

// TestNetworkSettingsRequireAdmin — обе формы меняют доступ к серверу целиком.
func TestNetworkSettingsRequireAdmin(t *testing.T) {
	app := newTestApp(t)
	viewer := sessionFor(t, app, "viewer", "viewer")

	for _, tc := range []struct {
		path string
		fn   func(http.ResponseWriter, *http.Request)
	}{
		{"/settings/network", app.UpdateNetwork},
		{"/settings/backup/restore", app.RestoreBackup},
		{"/settings/backup/restore/cancel", app.CancelRestore},
		{"/settings/restart", app.RestartServer},
	} {
		r := httptest.NewRequest("POST", tc.path, nil)
		r.AddCookie(viewer)
		rec := httptest.NewRecorder()
		tc.fn(rec, r)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s: viewer получил %d, ожидался 403", tc.path, rec.Code)
		}
	}
}
