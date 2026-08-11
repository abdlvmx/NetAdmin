package handlers

import (
	"net/http/httptest"
	"strings"
	"testing"

	"netadmin/internal/auth"
	"netadmin/internal/web"
)

// Смоук-тест: дашборд рендерится без ошибок шаблона.
func TestDashboardRenders(t *testing.T) {
	rec := httptest.NewRecorder()
	data := dashData{
		User:          &auth.User{ID: 1, Username: "admin", Role: "admin"},
		Active:        "dashboard",
		LastHeartbeat: "только что",
	}
	web.RenderPage(rec, "dashboard", data)

	body := rec.Body.String()
	if strings.Contains(body, "template error") {
		t.Fatalf("ошибка выполнения шаблона: %s", body)
	}
	for _, want := range []string{"Дашборд", "Статус устройств"} {
		if !strings.Contains(body, want) {
			t.Fatalf("в выводе нет %q", want)
		}
	}
}
