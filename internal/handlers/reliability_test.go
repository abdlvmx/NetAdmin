package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Паника в обработчике не должна ронять запрос молча: клиент получает 500,
// а сбой попадает в журнал.
func TestRecoverTurnsPanicInto500(t *testing.T) {
	h := withRecover(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("тестовая паника")
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/devices", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("ожидался 500, получено %d", rec.Code)
	}
}

// http.ErrAbortHandler — служебный сигнал net/http для намеренного обрыва,
// его перехватывать нельзя.
func TestRecoverPassesAbortHandler(t *testing.T) {
	h := withRecover(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic(http.ErrAbortHandler)
	}))
	defer func() {
		if v := recover(); v != http.ErrAbortHandler {
			t.Fatalf("ErrAbortHandler должен пробрасываться, получено %v", v)
		}
	}()
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))
	t.Fatal("паника должна была дойти до вызывающего")
}

// Обычный запрос проходит сквозь withRecover без изменений.
func TestRecoverPassesThrough(t *testing.T) {
	h := withRecover(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != http.StatusTeapot {
		t.Fatalf("ожидался 418, получено %d", rec.Code)
	}
}

// Раньше ошибка запроса приводила к обращению по nil-указателю и падению
// обработчика: rows.Next() вызывался на nil. Теперь возвращается пустой список.
func TestAgentDeviceIDsSurvivesQueryFailure(t *testing.T) {
	app := newTestApp(t)
	app.DB.Close() // любой запрос теперь вернёт ошибку

	ids := app.agentDeviceIDs() // не должно паниковать
	if ids != nil {
		t.Fatalf("при ошибке запроса ожидался пустой список, получено %v", ids)
	}
}

// На исправной базе возвращаются только устройства с агентом.
func TestAgentDeviceIDsOnlyEnrolled(t *testing.T) {
	app := newTestApp(t)
	app.DB.Exec("INSERT INTO devices (hostname, status, agent_token) VALUES ('with-agent','online','TOK1')")
	app.DB.Exec("INSERT INTO devices (hostname, status) VALUES ('no-agent','online')")
	app.DB.Exec("INSERT INTO devices (hostname, status, agent_token) VALUES ('empty-token','online','')")

	if ids := app.agentDeviceIDs(); len(ids) != 1 {
		t.Fatalf("ожидалось 1 устройство с агентом, получено %d", len(ids))
	}
}
