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
	// Адрес API больше не встречается в разметке: скрипт вынесен в /static
	// ради политики безопасности, поэтому страница ссылается на файл, а сам
	// запрос проверяем в нём.
	for _, want := range []string{"Карта сети", "map-search", "pp-list", "/static/network_map.js"} {
		if !strings.Contains(body, want) {
			t.Fatalf("в выводе карты нет %q", want)
		}
	}
}

// Скрипт карты действительно ходит за данными: страница сама по себе пуста,
// и без этой проверки вынос кода в статику прошёл бы незамеченным.
func TestNetworkMapScriptFetchesAPI(t *testing.T) {
	js, err := web.StaticFile("network_map.js")
	if err != nil {
		t.Fatalf("скрипт карты недоступен: %v", err)
	}
	if !strings.Contains(string(js), "/api/network-map") {
		t.Fatal("скрипт карты не запрашивает /api/network-map")
	}
}

func TestInferDeviceType(t *testing.T) {
	cases := []struct {
		dtype, os, vendor, host, ports, want string
	}{
		{"Сервер", "", "", "", "", "server"},              // ручной тип
		{"", "", "Hewlett Packard", "", "", "printer"},    // вендор-принтер
		{"", "", "", "office-pc", "9100", "printer"},      // порт печати
		{"", "", "Hikvision", "cam-12", "", "camera"},     // камера
		{"", "", "MikroTik", "", "", "network"},           // сетевое
		{"", "", "Xiaomi", "", "", "phone"},               // телефон
		{"", "Windows 10 Pro", "Dell", "ws-01", "", "pc"}, // ПК по ОС
		{"", "Windows Server 2019", "", "", "", "server"}, // сервер по ОС
		{"", "Android 13", "", "", "", "phone"},           // android → телефон
		{"", "", "Unknown Vendor", "", "", "other"},       // прочее
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

// Тип, заданный администратором вручную, не должен переопределяться догадкой
// по вендору: устройство HP, помеченное как «Видеорегистратор», превращалось
// в принтер только потому, что HP делает принтеры.
func TestInferDeviceTypeKeepsExplicitType(t *testing.T) {
	if got := inferDeviceType("Видеорегистратор", "", "Hewlett-Packard", "NVR-01", ""); got != "other" {
		t.Errorf("явный неизвестный тип должен давать other, получено %q", got)
	}
	if got := inferDeviceType("Сервер", "", "Hewlett-Packard", "SRV-1", ""); got != "server" {
		t.Errorf("явный тип «Сервер» должен давать server, получено %q", got)
	}
	if got := inferDeviceType("Принтер", "", "Cisco", "PRN-1", ""); got != "printer" {
		t.Errorf("явный тип должен побеждать вендора, получено %q", got)
	}
	// без явного типа эвристика по-прежнему работает
	if got := inferDeviceType("", "", "Hewlett-Packard", "PRN-2", ""); got != "printer" {
		t.Errorf("без явного типа вендор HP → принтер, получено %q", got)
	}
	if got := inferDeviceType("", "Windows 10", "", "WS-1", ""); got != "pc" {
		t.Errorf("без явного типа Windows → pc, получено %q", got)
	}
}
