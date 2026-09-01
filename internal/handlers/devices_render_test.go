package handlers

import (
	"net/http/httptest"
	"strings"
	"testing"

	"netadmin/internal/auth"
	"netadmin/internal/web"
)

// Фильтры на странице устройств работают на клиенте по data-атрибутам строки:
// разметка обязана их проставлять, иначе выбор в списке ничего не отфильтрует.
func TestDevicesPageFilterAttributes(t *testing.T) {
	rec := httptest.NewRecorder()
	web.RenderPage(rec, "devices", devicesData{
		User: &auth.User{ID: 1, Username: "admin", Role: "admin"}, Active: "devices",
		Devices: []deviceRow{
			{ID: 1, Hostname: "WS-1", IP: "192.168.1.10", Status: "online", HasToken: true, Alert: false},
			{ID: 2, Hostname: "SW-1", IP: "192.168.1.2", Status: "offline", HasToken: false, Alert: true},
		},
	})
	body := rec.Body.String()
	if strings.Contains(body, "template error") {
		t.Fatalf("ошибка шаблона: %s", body)
	}
	for _, want := range []string{
		`data-status="online"`, `data-agent="yes"`, `data-alert="0"`,
		`data-status="offline"`, `data-agent="no"`, `data-alert="1"`,
		`data-col="agent"`, `data-col="alert"`, `data-col="status"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("в разметке нет %s", want)
		}
	}
}
