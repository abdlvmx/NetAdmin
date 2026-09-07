package handlers

import (
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

// deviceWithHistory заводит устройство и всё, что к нему обычно привязано:
// историю метрик и события (на них есть внешние ключи), инвентарь, связь
// топологии и заявку.
func deviceWithHistory(t *testing.T, a *App, host string) int64 {
	t.Helper()
	res, err := a.DB.Exec(`INSERT INTO devices (hostname, ip_address, status)
		VALUES (?,?, 'online')`, host, "192.168.1.77")
	if err != nil {
		t.Fatalf("устройство: %v", err)
	}
	id, _ := res.LastInsertId()

	for _, q := range []string{
		`INSERT INTO metrics_history (device_id, cpu_usage) VALUES (?, 10)`,
		`INSERT INTO events (device_id, hostname, message) VALUES (?, 'x', 'y')`,
		`INSERT INTO software (device_id, name, version) VALUES (?, 'p', '1')`,
		`INSERT INTO device_changes (device_id, field, old_value, new_value) VALUES (?, 'os', 'a', 'b')`,
		`INSERT INTO services (device_id, name, display_name) VALUES (?, 's', 'Служба')`,
		`INSERT INTO autoruns (device_id, location, name, command) VALUES (?, 'HKLM', 'a', 'c')`,
		`INSERT INTO scheduled_tasks (device_id, name, path, action) VALUES (?, 't', '\', 'c')`,
		`INSERT INTO disks (device_id, model, serial) VALUES (?, 'm', 's')`,
		`INSERT INTO agent_tasks (device_id, kind, status) VALUES (?, 'k', 'pending')`,
		`INSERT INTO metrics_rollup (device_id, period, bucket, samples) VALUES (?, 'h', '2026-01-01', 1)`,
	} {
		if _, err := a.DB.Exec(q, id); err != nil {
			t.Fatalf("подготовка (%s): %v", strings.SplitN(q, " ", 4)[2], err)
		}
	}
	return id
}

// TestDeleteDeviceWithHistory — устройство с накопленной историей должно
// удаляться. На metrics_history и events стоят внешние ключи без каскада,
// поэтому «просто DELETE» на таком устройстве срывается, а сообщение об этом
// показывалось только при групповой операции: удаление по одному молча
// оставляло устройство на месте.
func TestDeleteDeviceWithHistory(t *testing.T) {
	a := newTestApp(t)
	admin := sessionFor(t, a, "admin", "admin")
	id := deviceWithHistory(t, a, "PC-HIST")

	r := httptest.NewRequest("POST", "/devices/"+strconv.FormatInt(id, 10)+"/delete", nil)
	r.SetPathValue("id", strconv.FormatInt(id, 10))
	r.AddCookie(admin)
	rec := httptest.NewRecorder()

	a.DeleteDevice(rec, r)

	if n := countRows(a, "SELECT COUNT(*) FROM devices WHERE id="+strconv.FormatInt(id, 10)); n != 0 {
		t.Errorf("устройство осталось в базе (перенаправление: %s)", rec.Header().Get("Location"))
	}
	for _, table := range []string{"metrics_history", "events", "software", "device_changes",
		"services", "autoruns", "scheduled_tasks", "disks", "agent_tasks", "metrics_rollup"} {
		if n := countRows(a, "SELECT COUNT(*) FROM "+table+" WHERE device_id="+strconv.FormatInt(id, 10)); n != 0 {
			t.Errorf("в %s осталось %d записей удалённого устройства", table, n)
		}
	}
}

// TestBulkDeleteWithHistory — то, на чём это и заметили: выбрать все и удалить.
func TestBulkDeleteWithHistory(t *testing.T) {
	a := newTestApp(t)
	admin := sessionFor(t, a, "admin", "admin")

	var ids []string
	for _, h := range []string{"PC-1", "PC-2", "PC-3"} {
		ids = append(ids, strconv.FormatInt(deviceWithHistory(t, a, h), 10))
	}

	form := url.Values{"action": {"delete"}, "device": ids}
	r := httptest.NewRequest("POST", "/devices/bulk", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(admin)
	rec := httptest.NewRecorder()

	a.BulkDevices(rec, r)

	loc := rec.Header().Get("Location")
	if strings.Contains(loc, "error=") {
		t.Fatalf("групповое удаление отклонено: %s", loc)
	}
	if n := countRows(a, "SELECT COUNT(*) FROM devices"); n != 0 {
		t.Errorf("после удаления осталось устройств: %d", n)
	}
}

// TestDeleteDeviceKeepsTickets — заявка написана человеком и к железу не
// сводится: удаление устройства не должно уносить её с собой.
func TestDeleteDeviceKeepsTickets(t *testing.T) {
	a := newTestApp(t)
	admin := sessionFor(t, a, "admin", "admin")
	id := deviceWithHistory(t, a, "PC-TICKET")

	if _, err := a.DB.Exec(`INSERT INTO tickets (code, title, device_id, status)
		VALUES ('AAA111','Не печатает', ?, 'new')`, id); err != nil {
		t.Fatalf("заявка: %v", err)
	}

	r := httptest.NewRequest("POST", "/devices/"+strconv.FormatInt(id, 10)+"/delete", nil)
	r.SetPathValue("id", strconv.FormatInt(id, 10))
	r.AddCookie(admin)
	a.DeleteDevice(httptest.NewRecorder(), r)

	if n := countRows(a, "SELECT COUNT(*) FROM tickets WHERE code='AAA111'"); n != 1 {
		t.Fatal("заявка исчезла вместе с устройством")
	}
	if n := countRows(a, "SELECT COUNT(*) FROM tickets WHERE code='AAA111' AND device_id IS NULL"); n != 1 {
		t.Error("у заявки осталась ссылка на удалённое устройство")
	}
}
