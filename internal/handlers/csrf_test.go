package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// post прогоняет форму через полный роутер от имени локального адреса.
func post(t *testing.T, app *App, path string, form url.Values, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "192.168.1.5:1234"
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	app.Routes().ServeHTTP(rec, req)
	return rec
}

// Вход без CSRF-токена должен отвергаться: иначе с чужой страницы можно
// залогинить пользователя в подставную учётную запись.
func TestLoginRequiresCSRF(t *testing.T) {
	app := newTestApp(t)
	app.DB.Exec("INSERT INTO users (username, role, password_hash) VALUES ('admin','admin','x')")

	rec := post(t, app, "/login", url.Values{"username": {"admin"}, "password": {"Parol12345"}})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("вход без CSRF-токена: ожидался 403, получено %d", rec.Code)
	}
}

// С корректным токеном форма доходит до обработчика (пароль неверный, но это
// уже ответ логики входа, а не отказ CSRF).
func TestLoginPassesWithCSRF(t *testing.T) {
	app := newTestApp(t)
	app.DB.Exec("INSERT INTO users (username, role, password_hash) VALUES ('admin','admin','x')")

	const tok = "0123456789abcdef"
	rec := post(t, app, "/login",
		url.Values{"username": {"admin"}, "password": {"неверный"}, "csrf_token": {tok}},
		&http.Cookie{Name: csrfCookie, Value: tok})
	if rec.Code == http.StatusForbidden {
		t.Fatal("с корректным токеном CSRF не должен отклонять вход")
	}
	if !strings.Contains(rec.Body.String(), "Неверный логин или пароль") {
		t.Fatalf("ожидался ответ формы входа, получено %d", rec.Code)
	}
}

// Первичная настройка защищена так же.
func TestSetupRequiresCSRF(t *testing.T) {
	app := newTestApp(t)
	rec := post(t, app, "/setup", url.Values{"username": {"root"}, "password": {"Parol12345"}})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("настройка без CSRF-токена: ожидался 403, получено %d", rec.Code)
	}
	var n int
	app.DB.QueryRow("SELECT COUNT(*) FROM users").Scan(&n)
	if n != 0 {
		t.Fatal("администратор не должен создаваться без CSRF-токена")
	}
}

// Страница входа обязана отдавать токен в скрытом поле: она рендерится без
// общего layout, который подставляет его скриптом на остальных страницах.
func TestLoginPageCarriesCSRFField(t *testing.T) {
	app := newTestApp(t)
	app.DB.Exec("INSERT INTO users (username, role, password_hash) VALUES ('admin','admin','x')")

	req := httptest.NewRequest("GET", "/login", nil)
	req.RemoteAddr = "192.168.1.5:1234"
	rec := httptest.NewRecorder()
	app.Routes().ServeHTTP(rec, req)

	body := rec.Body.String()
	if !strings.Contains(body, `name="csrf_token"`) {
		t.Fatal("в форме входа нет поля csrf_token")
	}
	if strings.Contains(body, `value=""`) && !strings.Contains(body, `name="csrf_token" value="`) {
		t.Fatal("токен не подставлен в форму входа")
	}
}

// Выход должен требовать POST: по GET его дёргала любая картинка с чужой
// страницы, и пользователя выкидывало из системы.
func TestLogoutRejectsGET(t *testing.T) {
	app := newTestApp(t)
	req := httptest.NewRequest("GET", "/logout", nil)
	req.RemoteAddr = "192.168.1.5:1234"
	rec := httptest.NewRecorder()
	app.Routes().ServeHTTP(rec, req)

	if rec.Code == http.StatusFound || rec.Code == http.StatusOK {
		t.Fatalf("выход по GET не должен срабатывать, получено %d", rec.Code)
	}
}
