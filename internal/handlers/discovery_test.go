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

// queuedMACs — что лежит в очереди обнаружения.
func queuedMACs(t *testing.T, app *App) map[string]bool {
	t.Helper()
	rows, err := app.DB.Query("SELECT mac FROM discovery_queue")
	if err != nil {
		t.Fatalf("чтение очереди обнаружения: %v", err)
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var mac string
		if err := rows.Scan(&mac); err != nil {
			t.Fatalf("чтение очереди обнаружения: %v", err)
		}
		out[mac] = true
	}
	return out
}

// Интеграция: пассивное обнаружение читает реальный ARP-кэш машины. Повторный
// вызов не должен ни терять найденное, ни плодить дубли.
//
// Сравнивать при этом общее число записей нельзя, а раньше сравнивалось: кэш
// живой, между двумя вызовами в сети может появиться новый хост, и тест падал
// бы на исправном коде. Теперь проверяется то, что от кода и зависит, —
// найденное на первом проходе осталось на месте и в одном экземпляре, а
// очередь только росла.
//
// Тест стоит на пути выпуска: release.yml гоняет go test перед сборкой, и
// случайное падение здесь срывает релиз по тегу.
func TestDiscoverPassiveReal(t *testing.T) {
	app := newTestApp(t)
	app.DiscoverPassive()

	first := queuedMACs(t, app)
	t.Logf("обнаружено хостов из ARP: %d", len(first))
	if len(first) == 0 {
		t.Skip("ARP-кэш пуст в этом окружении — пропуск")
	}

	app.DiscoverPassive()

	for mac := range first {
		var n int
		if err := app.DB.QueryRow("SELECT COUNT(*) FROM discovery_queue WHERE mac=?", mac).Scan(&n); err != nil {
			t.Fatalf("подсчёт записей для %s: %v", mac, err)
		}
		if n != 1 {
			t.Errorf("после повторного вызова MAC %s встречается %d раз, ожидалась одна запись", mac, n)
		}
	}
	if n := countRows(app, "SELECT COUNT(*) FROM discovery_queue"); n < len(first) {
		t.Errorf("очередь уменьшилась: было %d, стало %d", len(first), n)
	}
	// нет записей с пустым MAC или статусом не «новый»
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
