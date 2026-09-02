package handlers

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"netadmin/internal/auth"
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
