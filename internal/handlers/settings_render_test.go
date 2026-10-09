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

func TestHTTPSSettingsKeepCertificateNameInsteadOfLANAddressPicker(t *testing.T) {
	w := httptest.NewRecorder()
	web.RenderPage(w, "settings", settingsData{User: &auth.User{ID: 1, Username: "admin", Role: "admin"}, HTTPS: true, HTTPSAgentURL: "https://panel.example.test:8765"})
	body := w.Body.String()
	if strings.Contains(body, "template error") || !strings.Contains(body, "https://panel.example.test:8765") || strings.Contains(body, `data-act-change="pickHost"`) {
		t.Fatal("HTTPS settings replaced certificate name with LAN picker")
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

// Разделы скрывают подробности, но не отключают поля: сохранение раскрытой
// формы должно по-прежнему отправлять реальные текущие настройки.
func TestSettingsSectionsPreserveConfiguredValues(t *testing.T) {
	rec := httptest.NewRecorder()
	web.RenderPage(rec, "settings", settingsData{
		User:              &auth.User{ID: 42, Username: "admin", Role: "admin"},
		OrgName:           "Тестовая организация",
		AgentToken:        "current-token",
		ListenAddr:        "127.0.0.1:9012",
		AllowSubnets:      "192.168.40.0/24",
		SMTPHost:          "mail.example.test",
		SMTPPort:          465,
		SMTPUser:          "mailer",
		ScanIntervalHours: 12,
		HelpdeskEnabled:   true,
		BackupKeep:        9,
		BackupDir:         `D:\Backups`,
	})
	body := rec.Body.String()
	for _, want := range []string{
		`id="settings-organization"`, `id="settings-agents"`, `id="settings-backup"`,
		`id="settings-notifications" data-settings-section>`,
		`id="settings-network" data-settings-section>`,
		`name="listen_addr" value="127.0.0.1:9012"`,
		`name="allow_subnets" value="192.168.40.0/24"`,
		`name="smtp_host" value="mail.example.test"`,
		`name="smtp_port" type="number" value="465"`,
		`name="scan_interval_hours" min="0" max="168" value="12"`,
		`name="helpdesk_enabled" value="1" style="width:auto" checked`,
		`name="keep" min="0" max="365" value="9"`,
		`name="dir" value="D:\Backups"`,
		`value="current-token"`, `href="/settings/diagnostics"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("настройки потеряли поле или действие %q", want)
		}
	}
	if basic, additional := strings.Index(body, `id="settings-backup"`), strings.Index(body, `id="settings-additional"`); basic < 0 || additional <= basic {
		t.Error("резервные копии должны быть видны среди основных настроек")
	}
}

func TestSettingsReopensSectionAfterFeedback(t *testing.T) {
	for _, tc := range []struct{ message, problem, section string }{
		{"notifications_saved", "", "notifications"},
		{"test_sent", "", "notifications"},
		{"", "test_failed", "notifications"},
		{"helpdesk_saved", "", "helpdesk"},
		{"scan_saved", "", "scan"},
		{"network_saved", "", "network"},
		{"agent_token_rotated", "", "token"},
	} {
		t.Run(tc.section+tc.message+tc.problem, func(t *testing.T) {
			rec := httptest.NewRecorder()
			web.RenderPage(rec, "settings", settingsData{
				User:    &auth.User{ID: 1, Username: "admin", Role: "admin"},
				Message: tc.message,
				Error:   tc.problem,
			})
			if want := `id="settings-` + tc.section + `" data-settings-section open>`; !strings.Contains(rec.Body.String(), want) {
				t.Errorf("после сохранения/ошибки раздел должен оставаться открытым: %s", want)
			}
		})
	}
}
