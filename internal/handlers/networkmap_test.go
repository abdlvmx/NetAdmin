package handlers

import (
	"net/http/httptest"
	"strings"
	"testing"

	"netadmin/internal/auth"
	"netadmin/internal/web"
)

// Смоук: страница карты сети рендерится без ошибок шаблона.
func TestNetworkMapRenders(t *testing.T) {
	rec := httptest.NewRecorder()
	web.RenderPage(rec, "network_map", map[string]any{
		"User": &auth.User{ID: 1, Username: "admin", Role: "admin"}, "Active": "network_map",
	})
	body := rec.Body.String()
	if strings.Contains(body, "template error") {
		t.Fatalf("ошибка шаблона карты: %s", body)
	}
	for _, want := range []string{"Карта сети", "map-search", "pp-list", "/api/network-map"} {
		if !strings.Contains(body, want) {
			t.Fatalf("в выводе карты нет %q", want)
		}
	}
}

func TestInferDeviceType(t *testing.T) {
	cases := []struct {
		dtype, os, vendor, host, ports, want string
	}{
		{"Сервер", "", "", "", "", "server"},                        // ручной тип
		{"", "", "Hewlett Packard", "", "", "printer"},               // вендор-принтер
		{"", "", "", "office-pc", "9100", "printer"},                 // порт печати
		{"", "", "Hikvision", "cam-12", "", "camera"},                // камера
		{"", "", "MikroTik", "", "", "network"},                      // сетевое
		{"", "", "Xiaomi", "", "", "phone"},                          // телефон
		{"", "Windows 10 Pro", "Dell", "ws-01", "", "pc"},            // ПК по ОС
		{"", "Windows Server 2019", "", "", "", "server"},            // сервер по ОС
		{"", "Android 13", "", "", "", "phone"},                      // android → телефон
		{"", "", "Unknown Vendor", "", "", "other"},                  // прочее
	}
	for _, c := range cases {
		if got := inferDeviceType(c.dtype, c.os, c.vendor, c.host, c.ports); got != c.want {
			t.Errorf("inferDeviceType(%q,%q,%q,%q,%q)=%q, ожидалось %q",
				c.dtype, c.os, c.vendor, c.host, c.ports, got, c.want)
		}
	}
}

func TestSubnetOf(t *testing.T) {
	if subnetOf("192.168.1.64") != "192.168.1.0/24" {
		t.Fatalf("неверная подсеть: %q", subnetOf("192.168.1.64"))
	}
	if subnetOf("") != "" {
		t.Fatal("пустой IP → пустая подсеть")
	}
}
