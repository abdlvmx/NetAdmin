package handlers

import (
	"net/http/httptest"
	"strings"
	"testing"

	"netadmin/internal/auth"
	"netadmin/internal/web"
)

// Две вещи, за которыми в интерфейс приходят, когда что-то пошло не так:
// какая это сборка и что делать с потерянным паролем. Обе — на странице
// настроек, и обе должны там остаться.
func TestSettingsPageShowsVersionAndRecovery(t *testing.T) {
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
	if !strings.Contains(body, "-reset-password") {
		t.Error("нет подсказки, как восстановить доступ при потерянном пароле")
	}
}
