package handlers

import "testing"

func TestValidUnicastMAC(t *testing.T) {
	for _, m := range []string{"", "ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00", "01:00:5e:00:00:fb", "33:33:00:00:00:01", "unknown"} {
		if validUnicastMAC(m) {
			t.Errorf("%q должен быть отсеян", m)
		}
	}
	if !validUnicastMAC("a4:bb:6d:11:22:33") {
		t.Error("нормальный unicast MAC должен пройти")
	}
}

// Интеграция: пассивное обнаружение читает реальный ARP-кэш машины и идемпотентно.
func TestDiscoverPassiveReal(t *testing.T) {
	app := newTestApp(t)
	app.DiscoverPassive()
	n := countRows(app, "SELECT COUNT(*) FROM discovery_queue")
	t.Logf("обнаружено хостов из ARP: %d", n)
	if n == 0 {
		t.Skip("ARP-кэш пуст в этом окружении — пропуск")
	}
	// повторный вызов не плодит дубли (mac UNIQUE + проверка существования)
	app.DiscoverPassive()
	if n2 := countRows(app, "SELECT COUNT(*) FROM discovery_queue"); n2 != n {
		t.Fatalf("повторный вызов изменил число записей: %d → %d", n, n2)
	}
	// нет записей с пустым MAC или статусом не 'new'
	if bad := countRows(app, "SELECT COUNT(*) FROM discovery_queue WHERE COALESCE(mac,'')='' OR status<>'new'"); bad != 0 {
		t.Fatalf("некорректные записи в очереди: %d", bad)
	}
}

// Известный MAC (уже в devices) не попадает в очередь обнаружения.
func TestDiscoverSkipsKnown(t *testing.T) {
	app := newTestApp(t)
	app.DiscoverPassive()
	var mac string
	if app.DB.QueryRow("SELECT mac FROM discovery_queue LIMIT 1").Scan(&mac) != nil || mac == "" {
		t.Skip("нет обнаруженных MAC для проверки")
	}
	// добавим этот MAC как известное устройство и уберём только его из очереди
	app.DB.Exec("INSERT INTO devices (hostname, mac_address, status) VALUES ('known', ?, 'online')", mac)
	app.DB.Exec("DELETE FROM discovery_queue WHERE mac=?", mac)
	app.DiscoverPassive()
	var cnt int
	app.DB.QueryRow("SELECT COUNT(*) FROM discovery_queue WHERE mac=?", mac).Scan(&cnt)
	if cnt != 0 {
		t.Fatalf("известный MAC не должен попадать в очередь, получено %d", cnt)
	}
}
