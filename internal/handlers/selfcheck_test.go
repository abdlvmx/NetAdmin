package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

// deviceWithAgent заводит устройство с персональным токеном — то есть такое,
// на котором агент действительно зарегистрирован.
func deviceWithAgent(t *testing.T, app *App, hostname, token string) int64 {
	t.Helper()
	res, err := app.DB.Exec("INSERT INTO devices (hostname, agent_token, status) VALUES (?,?, 'online')",
		hostname, token)
	if err != nil {
		t.Fatalf("устройство: %v", err)
	}
	id, _ := res.LastInsertId()
	return id
}

func selfCheckReq(t *testing.T, c *http.Cookie, id int64) *http.Request {
	t.Helper()
	r := httptest.NewRequest("POST", "/devices/"+strconv.FormatInt(id, 10)+"/selfcheck", nil)
	r.SetPathValue("id", strconv.FormatInt(id, 10))
	if c != nil {
		r.AddCookie(c)
	}
	return r
}

func decodeJSON(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("ответ не разобран (%q): %v", rec.Body.String(), err)
	}
	return out
}

// Самодиагностика ставится задачей агенту, а не выполняется на сервере.
//
// Отвечает на самый частый вопрос про машину, которая числится онлайн, а данных
// от неё нет: прежде за ответом приходилось идти к машине и запускать
// agent.exe -check руками.
func TestSelfCheckEnqueuesTaskForAgent(t *testing.T) {
	app := newTestApp(t)
	admin := sessionFor(t, app, "admin", "admin")
	id := deviceWithAgent(t, app, "PC-1", "личный-токен")

	rec := httptest.NewRecorder()
	app.DeviceSelfCheck(rec, selfCheckReq(t, admin, id))

	if got := decodeJSON(t, rec)["ok"]; got != true {
		t.Fatalf("запрос отклонён: %s", rec.Body.String())
	}

	var kind, status string
	if err := app.DB.QueryRow(`SELECT kind, status FROM agent_tasks WHERE device_id=?`, id).
		Scan(&kind, &status); err != nil {
		t.Fatalf("задача не поставлена: %v", err)
	}
	if kind != "check" || status != "pending" {
		t.Errorf("поставлена задача %q со статусом %q, ожидалась check/pending", kind, status)
	}
}

// Устройству без агента диагностировать нечего, и обещать отчёт нельзя: задача
// осталась бы в очереди навсегда, а человек ждал бы ответа.
func TestSelfCheckRefusesDeviceWithoutAgent(t *testing.T) {
	app := newTestApp(t)
	admin := sessionFor(t, app, "admin", "admin")
	res, err := app.DB.Exec("INSERT INTO devices (hostname, status) VALUES ('PC-2','online')")
	if err != nil {
		t.Fatal(err)
	}
	id, _ := res.LastInsertId()

	rec := httptest.NewRecorder()
	app.DeviceSelfCheck(rec, selfCheckReq(t, admin, id))

	if got := decodeJSON(t, rec)["ok"]; got != false {
		t.Fatalf("запрос принят на устройстве без агента: %s", rec.Body.String())
	}
	var n int
	app.DB.QueryRow("SELECT COUNT(*) FROM agent_tasks WHERE device_id=?", id).Scan(&n)
	if n != 0 {
		t.Errorf("поставлено задач: %d, ожидалось 0", n)
	}
}

// Читатель не может ставить задачи устройствам: самодиагностика — действие,
// а не просмотр.
func TestSelfCheckRequiresWriteAccess(t *testing.T) {
	app := newTestApp(t)
	viewer := sessionFor(t, app, "viewer", "viewer")
	id := deviceWithAgent(t, app, "PC-3", "личный-токен")

	rec := httptest.NewRecorder()
	app.DeviceSelfCheck(rec, selfCheckReq(t, viewer, id))

	if rec.Code != http.StatusForbidden {
		t.Errorf("код %d, ожидался 403", rec.Code)
	}
}
