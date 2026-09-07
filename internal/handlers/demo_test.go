package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// postRaw бьёт в маршрут без сессии и без CSRF-токена. Проверка демо-режима
// стоит в middleware раньше CSRF, поэтому по тексту ответа видно, какая из них
// сработала — этого достаточно, чтобы отличить «заблокировано демо» от
// «дошло дальше».
func postRaw(t *testing.T, app *App, path string) (int, string) {
	t.Helper()
	srv := httptest.NewServer(app.Routes())
	t.Cleanup(srv.Close)

	resp, err := srv.Client().Post(srv.URL+path, "application/x-www-form-urlencoded", nil)
	if err != nil {
		t.Fatalf("post %s: %v", path, err)
	}
	defer resp.Body.Close()
	buf := make([]byte, 512)
	n, _ := resp.Body.Read(buf)
	return resp.StatusCode, string(buf[:n])
}

const demoRefusal = "демонстрационном режиме"

// TestDemoBlocksNetworkActions стережёт обещание, напечатанное в баннере демо и
// в README: показ продукта не должен трогать сеть смотрящего. Кнопки ping и
// скана остаются на страницах, поэтому запрет живёт на маршрутах.
func TestDemoBlocksNetworkActions(t *testing.T) {
	app := newTestApp(t)
	app.Demo = true

	for _, path := range []string{
		"/api/scan",
		"/api/ping",
		"/devices/1/scan-ports",
		"/snmp/1/poll",
	} {
		code, body := postRaw(t, app, path)
		if code != http.StatusForbidden || !strings.Contains(body, demoRefusal) {
			t.Errorf("%s в демо: получен %d %q, ожидался отказ демо-режима",
				path, code, strings.TrimSpace(body))
		}
	}
}

// TestDemoLeavesAgentAndNormalModeAlone — обратная сторона: запрет не должен
// цеплять чужие маршруты. У агента свой /api/agent-tasks/poll, который к сети
// смотрящего отношения не имеет, а вне демо не блокируется ничего.
func TestDemoLeavesAgentAndNormalModeAlone(t *testing.T) {
	app := newTestApp(t)
	app.Demo = true

	if _, body := postRaw(t, app, "/api/agent-tasks/poll"); strings.Contains(body, demoRefusal) {
		t.Error("/api/agent-tasks/poll заблокирован демо-режимом, хотя это маршрут агента")
	}

	app.Demo = false
	for _, path := range []string{"/api/scan", "/api/ping", "/devices/1/scan-ports", "/snmp/1/poll"} {
		if _, body := postRaw(t, app, path); strings.Contains(body, demoRefusal) {
			t.Errorf("%s заблокирован вне демо-режима", path)
		}
	}
}
