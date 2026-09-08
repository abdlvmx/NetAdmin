package handlers

import (
	"net/http/httptest"
	"strings"
	"testing"

	"netadmin/internal/auth"
	"netadmin/internal/web"
)

// За версией в интерфейс приходят тогда, когда что-то пошло не так и надо
// ответить, какая это сборка. Строка должна там остаться.
func TestSettingsPageShowsVersion(t *testing.T) {
	rec := httptest.NewRecorder()
	web.RenderPage(rec, "settings", settingsData{
		User:    &auth.User{ID: 1, Username: "admin", Role: "admin"},
		Active:  "settings",
		Version: "9.9.9 · deadbee",
	})
	body := rec.Body.String()
	if strings.Contains(body, "template error") {
		t.Fatalf("ошибка шаблона: %s", body)
	}
	if !strings.Contains(body, "9.9.9 · deadbee") {
		t.Error("версия сборки на странице настроек не показана")
	}
}
