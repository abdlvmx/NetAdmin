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

// Часовой пояс выбирается списком, а не набирается руками: «Asia/Krasnoyarsk»
// с опечаткой в одну букву даёт отказ, причину которого искать негде.
func TestSettingsShowsTimezoneChoice(t *testing.T) {
	rec := httptest.NewRecorder()
	web.RenderPage(rec, "settings", settingsData{
		User:          &auth.User{ID: 1, Username: "admin", Role: "admin"},
		Active:        "settings",
		Timezone:      "Asia/Yekaterinburg",
		TimezoneLabel: "Asia/Yekaterinburg, UTC+5",
		Zones:         zoneChoices(),
	})
	body := rec.Body.String()
	if strings.Contains(body, "template error") {
		t.Fatalf("ошибка шаблона: %s", body)
	}
	if !strings.Contains(body, "Как на этом сервере") {
		t.Error("нет варианта «как на сервере» — а он же по умолчанию")
	}
	if !strings.Contains(body, `value="Asia/Yekaterinburg" selected`) {
		t.Error("выбранный пояс не отмечен в списке")
	}
	// Плюс в разметке уезжает как &#43; — так html/template экранирует его в
	// тексте; браузер показывает обычный «+», поэтому сверяем без него.
	if !strings.Contains(body, "Asia/Yekaterinburg, UTC") {
		t.Error("не сказано, какой пояс действует сейчас")
	}
	// Смещения считаются, а не вписаны в разметку: закон их меняет.
	if !strings.Contains(body, "Москва, Санкт-Петербург — UTC") {
		t.Error("у пояса не показано смещение")
	}
}
