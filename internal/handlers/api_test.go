package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"netadmin/internal/auth"
	"netadmin/internal/tz"
	"netadmin/internal/web"
)

// metricSeries за 30 дней должен объединять свежее сырьё и старые агрегаты.
func TestMetricSeriesRawPlusRollup(t *testing.T) {
	app := newTestApp(t)
	app.DB.Exec(`INSERT INTO devices (id, hostname, status) VALUES (1,'d1','online')`)

	// свежая сырая точка (сегодня), cpu=50
	app.DB.Exec(`INSERT INTO metrics_history (device_id, cpu_usage, ram_usage, disk_usage, ts)
		VALUES (1, 50, 40, 30, datetime('now','-2 hours'))`)
	// суточный агрегат 20 дней назад, cpu_avg=30
	app.DB.Exec(`INSERT INTO metrics_rollup (device_id, period, bucket, cpu_min,cpu_avg,cpu_max, ram_min,ram_avg,ram_max, disk_min,disk_avg,disk_max, samples)
		VALUES (1, 'day', strftime('%Y-%m-%d 00:00:00', datetime('now','-20 days')), 20,30,40, 20,30,40, 20,30,40, 100)`)

	pts := app.metricSeries(0, 720, 86400) // окно 30 дней, суточные корзины
	if len(pts) < 2 {
		t.Fatalf("ожидалось >=2 точки (сырьё + агрегат), получено %d", len(pts))
	}
	var sawRaw, sawRoll bool
	for _, p := range pts {
		if p.CPU == 50 {
			sawRaw = true
		}
		if p.CPU == 30 {
			sawRoll = true
		}
	}
	if !sawRaw || !sawRoll {
		t.Fatalf("в ряду нет и сырья, и агрегата: raw=%v roll=%v (%+v)", sawRaw, sawRoll, pts)
	}

	// короткое окно (24ч) не должно тянуть старый агрегат — только свежее сырьё
	short := app.metricSeries(0, 24, 300)
	for _, p := range short {
		if p.CPU == 30 {
			t.Fatalf("агрегат 20-дневной давности попал в окно 24ч")
		}
	}
}

type deviceStatusSnapshot struct {
	Devices []struct {
		ID           int64  `json:"id"`
		Status       string `json:"status"`
		LastSeen     string `json:"last_seen"`
		LastSeenSort string `json:"last_seen_sort"`
		Alert        *bool  `json:"alert"`
		HasAgent     *bool  `json:"has_agent"`
	} `json:"devices"`
	Summary  map[string]int `json:"summary"`
	Revision string         `json:"issues_revision"`
}

func deviceStatusFor(t *testing.T, app *App, cookie *http.Cookie) deviceStatusSnapshot {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/devices/status", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	app.DevicesStatus(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d: %s", rec.Code, rec.Body.String())
	}
	var got deviceStatusSnapshot
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return got
}

// Фоновое обновление использует тот же признак проблемы, что начальный список,
// и передаёт false явно, чтобы снятая тревога исчезла из активного фильтра.
func TestDevicesStatusRefreshesAlertAndAgentFilters(t *testing.T) {
	app := newTestApp(t)
	cookie := sessionFor(t, app, "viewer", "viewer")
	_, err := app.DB.Exec(`INSERT INTO devices (id, hostname, status, cpu_usage, ram_usage, disk_usage, last_seen, agent_token)
		VALUES (1,'offline','offline',0,0,0,NULL,'token'),
		(2,'cpu','online',90,0,0,datetime('now'),'token'),
		(3,'ram','online',0,90,0,datetime('now'),NULL),
		(4,'disk','online',0,0,90,datetime('now'),''),
		(5,'stale','online',0,0,0,datetime('now','-11 minutes'),''),
		(6,'healthy','online',89,89,89,datetime('now','-9 minutes'),''),
		(7,'unknown','unknown',0,0,0,NULL,NULL)`)
	if err != nil {
		t.Fatal(err)
	}

	initial := deviceStatusFor(t, app, cookie)
	if len(initial.Devices) != 7 || initial.Summary["alerts"] != 5 || initial.Summary["unknown"] != 1 {
		t.Fatalf("неверная сводка: %+v", initial)
	}
	listAlerts := map[int64]bool{}
	for _, device := range app.listDevices() {
		listAlerts[device.ID] = device.Alert
	}
	for _, device := range initial.Devices {
		if device.Alert == nil || *device.Alert != listAlerts[device.ID] {
			t.Errorf("alert устройства %d не совпадает со списком: %+v", device.ID, device)
		}
		if device.HasAgent == nil || *device.HasAgent != (device.ID == 1 || device.ID == 2) {
			t.Errorf("has_agent устройства %d неверен: %+v", device.ID, device)
		}
		var raw string
		if err := app.DB.QueryRow(`SELECT COALESCE(last_seen,'') FROM devices WHERE id=?`, device.ID).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		if device.LastSeenSort != raw || device.LastSeen != tz.DateTime(raw) {
			t.Errorf("время устройства %d не сохраняет сортировку и отображение: %+v", device.ID, device)
		}
	}

	if _, err := app.DB.Exec(`UPDATE devices SET status='online', cpu_usage=0, ram_usage=0, disk_usage=0,
		last_seen=datetime('now'), agent_token=CASE WHEN id=3 THEN 'new-token' ELSE '' END`); err != nil {
		t.Fatal(err)
	}
	refreshed := deviceStatusFor(t, app, cookie)
	if refreshed.Summary["alerts"] != 0 || refreshed.Summary["online"] != 7 {
		t.Fatalf("сводка не обновилась: %+v", refreshed.Summary)
	}
	for _, device := range refreshed.Devices {
		if device.Alert == nil || *device.Alert {
			t.Errorf("снятая тревога устройства %d осталась активной", device.ID)
		}
		if device.HasAgent == nil || *device.HasAgent != (device.ID == 3) {
			t.Errorf("изменение агента устройства %d не обновилось", device.ID)
		}
	}
}

// Одинаковое количество проблем не означает одинаковый состав или описание.
func TestDevicesStatusIssueRevisionChangesWithSameCount(t *testing.T) {
	app := newTestApp(t)
	cookie := sessionFor(t, app, "viewer", "viewer")
	if _, err := app.DB.Exec(`INSERT INTO devices (id, hostname, status, last_seen)
		VALUES (1,'PC-1','offline',datetime('now')), (2,'PC-2','online',datetime('now'))`); err != nil {
		t.Fatal(err)
	}
	first := deviceStatusFor(t, app, cookie)
	if _, err := app.DB.Exec(`UPDATE devices SET status=CASE WHEN id=1 THEN 'online' ELSE 'offline' END`); err != nil {
		t.Fatal(err)
	}
	replaced := deviceStatusFor(t, app, cookie)
	if first.Summary["issues"] != 1 || replaced.Summary["issues"] != 1 || first.Revision == replaced.Revision {
		t.Fatalf("ревизия не заметила замену проблемы: first=%+v replaced=%+v", first, replaced)
	}
	if _, err := app.DB.Exec(`UPDATE devices SET hostname='Переименованный PC-2' WHERE id=2`); err != nil {
		t.Fatal(err)
	}
	renamed := deviceStatusFor(t, app, cookie)
	if renamed.Summary["issues"] != 1 || renamed.Revision == replaced.Revision {
		t.Fatal("ревизия не заметила изменение содержания проблемы")
	}
}

func TestDevicesStatusDatabaseErrorDoesNotReturnFreshSnapshot(t *testing.T) {
	app := newTestApp(t)
	cookie := sessionFor(t, app, "viewer", "viewer")
	if _, err := app.DB.Exec(`DROP TABLE devices`); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/devices/status", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	app.DevicesStatus(rec, req)
	if rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), `"devices"`) {
		t.Fatalf("ошибка базы вернула успешную сводку: status=%d body=%s", rec.Code, rec.Body.String())
	}
}

// Справочник сотрудников уезжает в data-атрибут и разбирается через JSON.parse.
// Раньше он вставлялся в тело скрипта через template.JS — экранирование там
// отключено, и защита держалась только на поведении json.Marshal.
func TestEmployeesJSONIsEscapedInAttribute(t *testing.T) {
	app := newTestApp(t)
	app.DB.Exec("INSERT INTO departments (name) VALUES ('Отдел')")
	app.DB.Exec(`INSERT INTO employees (full_name, position, department_id, is_active)
		VALUES (?, 'Тестер', 1, 1)`, `</script><script>alert(1)</script>`)

	rec := httptest.NewRecorder()
	web.RenderPage(rec, "employees", employeesData{
		User: &auth.User{ID: 1, Username: "admin", Role: "admin"}, Active: "employees",
		Employees:     app.listEmployeesFull(),
		EmployeesJSON: employeesJSON(t, app),
	})
	body := rec.Body.String()
	if strings.Contains(body, "template error") {
		t.Fatalf("ошибка шаблона: %s", body)
	}
	if strings.Contains(body, "<script>alert(1)</script>") {
		t.Fatal("разметка из имени сотрудника попала в страницу без экранирования")
	}
	if !strings.Contains(body, `id="emp-data"`) {
		t.Fatal("данные должны уезжать в data-атрибут")
	}
}

// employeesJSON повторяет то, что делает обработчик страницы.
func employeesJSON(t *testing.T, app *App) string {
	t.Helper()
	raw, err := json.Marshal(app.listEmployeesFull())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(raw)
}
