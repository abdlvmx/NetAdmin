package handlers

import (
	"testing"

	"netadmin/internal/netscan"
)

// Машина, сменившая адрес по DHCP, должна опознаваться по MAC, а не заводиться
// в инвентаре повторно.
func TestMatchScannedFindsByMACAfterIPChange(t *testing.T) {
	app := newTestApp(t)
	res, _ := app.DB.Exec(`INSERT INTO devices (hostname, ip_address, mac_address, status)
		VALUES ('WS-1','192.168.1.10','AA:BB:CC:DD:EE:FF','online')`)
	id, _ := res.LastInsertId()

	got, ok := app.matchScanned(netscan.ScanResult{
		IP: "192.168.1.77", MAC: "aa:bb:cc:dd:ee:ff", Hostname: "WS-1",
	})
	if !ok {
		t.Fatal("устройство должно опознаваться по MAC при смене адреса")
	}
	if got.id != id {
		t.Fatalf("сопоставлено не то устройство: %d вместо %d", got.id, id)
	}
	if got.ip != "192.168.1.10" {
		t.Fatalf("прежний адрес должен возвращаться для истории, получено %q", got.ip)
	}
}

// Когда MAC узнать не удалось, опознаём по адресу.
func TestMatchScannedFallsBackToIP(t *testing.T) {
	app := newTestApp(t)
	res, _ := app.DB.Exec(`INSERT INTO devices (hostname, ip_address, mac_address, status)
		VALUES ('WS-2','192.168.1.20','','online')`)
	id, _ := res.LastInsertId()

	got, ok := app.matchScanned(netscan.ScanResult{IP: "192.168.1.20", MAC: "unknown"})
	if !ok || got.id != id {
		t.Fatalf("устройство должно опознаваться по адресу, получено %+v ok=%v", got, ok)
	}
}

// Значение «unknown» не должно склеивать разные машины.
func TestMatchScannedIgnoresUnknownMAC(t *testing.T) {
	app := newTestApp(t)
	app.DB.Exec(`INSERT INTO devices (hostname, ip_address, mac_address, status)
		VALUES ('WS-3','192.168.1.30','unknown','online')`)

	if _, ok := app.matchScanned(netscan.ScanResult{IP: "192.168.1.99", MAC: "unknown"}); ok {
		t.Fatal("по «unknown» устройства объединяться не должны")
	}
}

// Устройство, зарегистрированное агентом (без адреса), подхватывается сканом
// по имени — без этого оно дублировалось бы.
func TestMatchScannedPicksUpAgentEnrolledByHostname(t *testing.T) {
	app := newTestApp(t)
	res, _ := app.DB.Exec(`INSERT INTO devices (hostname, status, agent_token) VALUES ('ws-4','online','TOK')`)
	id, _ := res.LastInsertId()

	got, ok := app.matchScanned(netscan.ScanResult{
		IP: "192.168.1.40", MAC: "11:22:33:44:55:66", Hostname: "WS-4", // регистр иной
	})
	if !ok || got.id != id {
		t.Fatalf("устройство агента должно подхватываться по имени, получено %+v ok=%v", got, ok)
	}
}

// Совпадение по имени намеренно ограничено записями без адреса: два разных
// хоста могут отдать одинаковое имя, и объединять их нельзя.
func TestMatchScannedDoesNotMergeByHostnameWhenIPKnown(t *testing.T) {
	app := newTestApp(t)
	app.DB.Exec(`INSERT INTO devices (hostname, ip_address, mac_address, status)
		VALUES ('SHARED','192.168.1.50','11:11:11:11:11:11','online')`)

	if _, ok := app.matchScanned(netscan.ScanResult{
		IP: "192.168.1.51", MAC: "22:22:22:22:22:22", Hostname: "SHARED",
	}); ok {
		t.Fatal("устройства с разными MAC и IP не должны объединяться по имени")
	}
}

func TestMatchScannedNoMatch(t *testing.T) {
	app := newTestApp(t)
	if _, ok := app.matchScanned(netscan.ScanResult{IP: "10.0.0.1", MAC: "99:99:99:99:99:99", Hostname: "NEW"}); ok {
		t.Fatal("для неизвестного устройства совпадения быть не должно")
	}
}

func TestUsableMAC(t *testing.T) {
	for _, bad := range []string{"", "  ", "unknown", "UNKNOWN"} {
		if usableMAC(bad) != "" {
			t.Errorf("%q не должен годиться для сопоставления", bad)
		}
	}
	if usableMAC(" AA:BB:cc ") != "aa:bb:cc" {
		t.Errorf("MAC должен приводиться к нижнему регистру без пробелов, получено %q", usableMAC(" AA:BB:cc "))
	}
}
