package handlers

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"netadmin/internal/auth"
	"netadmin/internal/web"
)

func detailJSON(d snmpDetail) string {
	b, _ := json.Marshal(d)
	return string(b)
}

func TestSnmpSummarySwitch(t *testing.T) {
	s, warn := snmpSummary("switch", detailJSON(snmpDetail{PortsUp: 3, PortsDown: 2, PortsTotal: 5}))
	if !strings.Contains(s, "3 из 5") {
		t.Fatalf("switch summary: %q", s)
	}
	if !warn {
		t.Fatal("при наличии down-портов нужен флаг тревоги")
	}
}

func TestSnmpSummaryUPSOnBattery(t *testing.T) {
	s, warn := snmpSummary("ups", detailJSON(snmpDetail{OnBattery: true, BatteryPct: 80, RuntimeMin: 12, LoadPct: 40}))
	if !warn {
		t.Fatal("работа от батареи должна давать тревогу")
	}
	if !strings.Contains(s, "от батареи") || !strings.Contains(s, "80%") {
		t.Fatalf("ups summary: %q", s)
	}
}

func TestSnmpSummaryPrinterLow(t *testing.T) {
	s, warn := snmpSummary("printer", detailJSON(snmpDetail{Supplies: []snmpSupply{{Name: "Чёрный тонер", Pct: 8, Known: true}}}))
	if !warn {
		t.Fatal("низкий уровень расходника (<15%) должен давать тревогу")
	}
	if !strings.Contains(s, "Чёрный тонер 8%") {
		t.Fatalf("printer summary: %q", s)
	}
}

func TestSnmpPageRenders(t *testing.T) {
	rec := httptest.NewRecorder()
	web.RenderPage(rec, "snmp", snmpData{
		User: &auth.User{ID: 1, Username: "admin", Role: "admin"}, Active: "snmp",
		Total: 1, Up: 1, Kinds: snmpKinds,
		Rows: []snmpRow{{ID: 1, Name: "SW-1", IP: "192.168.1.2", Kind: "switch",
			KindRu: "Коммутатор", Status: "up", SysName: "sw1", Uptime: "3д 4ч",
			Summary: "Порты: 10 из 24 активны", Enabled: true}},
	})
	body := rec.Body.String()
	if strings.Contains(body, "template error") {
		t.Fatalf("ошибка шаблона: %s", body)
	}
	if !strings.Contains(body, "SNMP-устройства") {
		t.Fatal("в выводе нет заголовка страницы")
	}
}

// Опрос недоступного адреса должен завершаться статусом down без паники.
func TestPollSNMPUnreachable(t *testing.T) {
	if testing.Short() {
		t.Skip("сетевой тест пропущен в -short")
	}
	status, _, _, uptime, _, _ := pollSNMP("192.0.2.1", 161, "public", "auto") // TEST-NET-1, не отвечает
	if status != "down" {
		t.Fatalf("ожидался down для недоступного хоста, получено %q", status)
	}
	if uptime != 0 {
		t.Fatalf("аптайм недоступного хоста должен быть 0, получено %d", uptime)
	}
}

func TestPortRate(t *testing.T) {
	if r := portRate(2000, 1000, 1); r != 8000 { // 1000 байт/с = 8000 бит/с
		t.Fatalf("portRate обычный: %d, ожидалось 8000", r)
	}
	if r := portRate(500, 1000, 1); r != 0 { // обнуление счётчика
		t.Fatalf("portRate wrap должен давать 0, получено %d", r)
	}
	if r := portRate(2000, 1000, 0); r != 0 { // нет интервала
		t.Fatalf("portRate без интервала должен давать 0, получено %d", r)
	}
}

func TestHumanRate(t *testing.T) {
	cases := map[int64]string{0: "0", 500: "500 бит/с", 8000: "8.0 Кбит/с", 8_000_000: "8.0 Мбит/с"}
	for bps, want := range cases {
		if got := humanRate(bps); got != want {
			t.Errorf("humanRate(%d)=%q, ожидалось %q", bps, got, want)
		}
	}
}

func TestSnmpPortsRenders(t *testing.T) {
	rec := httptest.NewRecorder()
	web.RenderPage(rec, "snmp_ports", snmpPortsData{
		User: &auth.User{ID: 1, Username: "admin", Role: "admin"}, Active: "snmp",
		Device: "SW-1", IP: "192.168.1.2", UpCount: 1, Total: 2,
		Rows: []portRow{{Name: "Gi0/1", Up: true, InRate: "8.0 Мбит/с", OutRate: "2.0 Мбит/с", Speed: "1.00 Гбит/с"}},
	})
	body := rec.Body.String()
	if strings.Contains(body, "template error") {
		t.Fatalf("ошибка шаблона: %s", body)
	}
	if !strings.Contains(body, "Gi0/1") {
		t.Fatal("в выводе нет порта")
	}
}

func TestHumanUptime(t *testing.T) {
	cases := map[int64]string{
		90000: "1д 1ч",
		7200:  "2ч 0м",
		120:   "2м",
	}
	for sec, want := range cases {
		if got := humanUptime(sec); got != want {
			t.Errorf("humanUptime(%d)=%q, ожидалось %q", sec, got, want)
		}
	}
}
