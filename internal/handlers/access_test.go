package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"netadmin/internal/netaccess"
)

// call прогоняет запрос через полный роутер от имени указанного адреса.
func call(t *testing.T, app *App, method, path, remoteIP string) int {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	req.RemoteAddr = remoteIP + ":54321"
	rec := httptest.NewRecorder()
	app.Routes().ServeHTTP(rec, req)
	return rec.Code
}

// Обращение из неразрешённой сети отбивается на входе — до аутентификации,
// до публичного портала заявок и до эндпоинтов агента.
func TestAccessBlockedFromForeignNetwork(t *testing.T) {
	app := newTestApp(t)
	app.Allow = netaccess.Default()

	paths := []struct{ method, path string }{
		{"GET", "/healthz"},
		{"GET", "/login"},
		{"GET", "/help"}, // публичный портал тоже закрыт снаружи
		{"POST", "/api/agent-heartbeat"},
	}
	for _, p := range paths {
		if code := call(t, app, p.method, p.path, "203.0.113.9"); code != http.StatusForbidden {
			t.Errorf("%s %s из публичной сети: ожидался 403, получено %d", p.method, p.path, code)
		}
	}
}

// Из локальной сети запрос проходит фильтр и попадает в обработчик.
func TestAccessAllowedFromLAN(t *testing.T) {
	app := newTestApp(t)
	app.Allow = netaccess.Default()

	for _, ip := range []string{"127.0.0.1", "192.168.1.64", "10.0.5.7"} {
		if code := call(t, app, "GET", "/healthz", ip); code != http.StatusOK {
			t.Errorf("%s: ожидался 200, получено %d", ip, code)
		}
	}
}

// Явный список подсетей вытесняет умолчания: адрес из другой частной сети
// перестаёт проходить.
func TestAccessExplicitList(t *testing.T) {
	app := newTestApp(t)
	l, err := netaccess.Parse("192.168.1.0/24")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	app.Allow = l

	if code := call(t, app, "GET", "/healthz", "192.168.1.64"); code != http.StatusOK {
		t.Errorf("адрес из списка: ожидался 200, получено %d", code)
	}
	if code := call(t, app, "GET", "/healthz", "10.0.5.7"); code != http.StatusForbidden {
		t.Errorf("частный адрес вне списка: ожидался 403, получено %d", code)
	}
}

// Незаполненное поле Allow не должно открывать сервер наружу.
func TestAccessZeroValueBlocksPublic(t *testing.T) {
	app := newTestApp(t) // Allow не задан
	if code := call(t, app, "GET", "/healthz", "8.8.8.8"); code != http.StatusForbidden {
		t.Errorf("нулевое значение Allow: ожидался 403, получено %d", code)
	}
	if code := call(t, app, "GET", "/healthz", "192.168.0.2"); code != http.StatusOK {
		t.Errorf("нулевое значение Allow: локальный адрес должен проходить, получено %d", code)
	}
}
