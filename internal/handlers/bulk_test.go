package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"netadmin/internal/auth"
)

// sessionFor заводит пользователя с нужной ролью и возвращает cookie сессии.
func sessionFor(t *testing.T, app *App, username, role string) *http.Cookie {
	t.Helper()
	hash, err := auth.HashPassword("Parol12345")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	res, err := app.DB.Exec("INSERT INTO users (username, role, password_hash) VALUES (?,?,?)",
		username, role, hash)
	if err != nil {
		t.Fatalf("user: %v", err)
	}
	id, _ := res.LastInsertId()
	tok, err := auth.CreateSession(app.DB, id)
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	return &http.Cookie{Name: "session", Value: tok}
}

func bulkReq(t *testing.T, c *http.Cookie, form url.Values) *http.Request {
	t.Helper()
	r := httptest.NewRequest("POST", "/devices/bulk", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if c != nil {
		r.AddCookie(c)
	}
	return r
}

func threeDevices(t *testing.T, app *App) {
	t.Helper()
	for _, h := range []string{"PC-1", "PC-2", "PC-3"} {
		if _, err := app.DB.Exec("INSERT INTO devices (hostname, status) VALUES (?, 'online')", h); err != nil {
			t.Fatalf("device: %v", err)
		}
	}
}

// Действие применяется только к выбранным устройствам, остальные не трогаются.
func TestBulkUpdatesOnlySelected(t *testing.T) {
	app := newTestApp(t)
	threeDevices(t, app)
	c := sessionFor(t, app, "op", "user")

	rec := httptest.NewRecorder()
	app.BulkDevices(rec, bulkReq(t, c, url.Values{
		"action": {"location"}, "value": {"каб. 201"}, "device": {"1", "2"},
	}))

	var changed, untouched int
	app.DB.QueryRow("SELECT COUNT(*) FROM devices WHERE location='каб. 201'").Scan(&changed)
	app.DB.QueryRow("SELECT COUNT(*) FROM devices WHERE COALESCE(location,'')=''").Scan(&untouched)
	if changed != 2 {
		t.Errorf("расположение изменено у %d устройств, ожидалось 2", changed)
	}
	if untouched != 1 {
		t.Errorf("невыбранных должно остаться 1, осталось %d", untouched)
	}
}

// Пустой владелец снимает привязку, а не пишет нулевой идентификатор.
func TestBulkEmployeeClears(t *testing.T) {
	app := newTestApp(t)
	threeDevices(t, app)
	app.DB.Exec("INSERT INTO employees (full_name, is_active) VALUES ('Иванов', 1)")
	app.DB.Exec("UPDATE devices SET employee_id=1 WHERE id IN (1,2)")
	c := sessionFor(t, app, "op", "user")

	app.BulkDevices(httptest.NewRecorder(), bulkReq(t, c, url.Values{
		"action": {"employee"}, "value": {""}, "device": {"1"},
	}))

	var isNull int
	app.DB.QueryRow("SELECT COUNT(*) FROM devices WHERE id=1 AND employee_id IS NULL").Scan(&isNull)
	if isNull != 1 {
		t.Error("пустое значение должно снимать привязку к сотруднику")
	}
	var still int
	app.DB.QueryRow("SELECT COUNT(*) FROM devices WHERE id=2 AND employee_id=1").Scan(&still)
	if still != 1 {
		t.Error("невыбранное устройство не должно меняться")
	}
}

// Наблюдатель не может менять инвентарь.
func TestBulkForbiddenForViewer(t *testing.T) {
	app := newTestApp(t)
	threeDevices(t, app)
	c := sessionFor(t, app, "viewer", "viewer")

	rec := httptest.NewRecorder()
	app.BulkDevices(rec, bulkReq(t, c, url.Values{
		"action": {"location"}, "value": {"цех"}, "device": {"1"},
	}))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("ожидался 403, получено %d", rec.Code)
	}
	var n int
	app.DB.QueryRow("SELECT COUNT(*) FROM devices WHERE location='цех'").Scan(&n)
	if n != 0 {
		t.Error("наблюдатель не должен менять данные")
	}
}

// Групповое удаление доступно только администратору — как и удаление по одному.
func TestBulkDeleteRequiresAdmin(t *testing.T) {
	app := newTestApp(t)
	threeDevices(t, app)

	op := sessionFor(t, app, "op", "user")
	rec := httptest.NewRecorder()
	app.BulkDevices(rec, bulkReq(t, op, url.Values{"action": {"delete"}, "device": {"1"}}))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("оператору удаление должно быть запрещено, получено %d", rec.Code)
	}
	var n int
	app.DB.QueryRow("SELECT COUNT(*) FROM devices").Scan(&n)
	if n != 3 {
		t.Fatalf("после отказа должно остаться 3 устройства, осталось %d", n)
	}

	admin := sessionFor(t, app, "root", "admin")
	app.BulkDevices(httptest.NewRecorder(), bulkReq(t, admin, url.Values{
		"action": {"delete"}, "device": {"1", "2"},
	}))
	app.DB.QueryRow("SELECT COUNT(*) FROM devices").Scan(&n)
	if n != 1 {
		t.Fatalf("администратор должен удалить два устройства, осталось %d", n)
	}
}

// Неизвестное действие ничего не меняет.
func TestBulkUnknownActionIsNoop(t *testing.T) {
	app := newTestApp(t)
	threeDevices(t, app)
	c := sessionFor(t, app, "root", "admin")

	rec := httptest.NewRecorder()
	app.BulkDevices(rec, bulkReq(t, c, url.Values{
		"action": {"drop-table"}, "value": {"x"}, "device": {"1"},
	}))
	loc, _ := url.QueryUnescape(rec.Header().Get("Location"))
	if !strings.Contains(loc, "Неизвестное действие") {
		t.Errorf("ожидалось сообщение об ошибке, получено %q", loc)
	}
	var n int
	app.DB.QueryRow("SELECT COUNT(*) FROM devices").Scan(&n)
	if n != 3 {
		t.Errorf("данные не должны меняться, устройств осталось %d", n)
	}
}

// Пустой список выбора обрабатывается сообщением, а не запросом без условия.
func TestBulkEmptySelection(t *testing.T) {
	app := newTestApp(t)
	threeDevices(t, app)
	c := sessionFor(t, app, "root", "admin")

	rec := httptest.NewRecorder()
	app.BulkDevices(rec, bulkReq(t, c, url.Values{"action": {"delete"}}))
	loc, _ := url.QueryUnescape(rec.Header().Get("Location"))
	if !strings.Contains(loc, "Не выбраны устройства") {
		t.Errorf("ожидалось сообщение о пустом выборе, получено %q", loc)
	}
	var n int
	app.DB.QueryRow("SELECT COUNT(*) FROM devices").Scan(&n)
	if n != 3 {
		t.Fatalf("без выбора удалять нечего, осталось %d", n)
	}
}
