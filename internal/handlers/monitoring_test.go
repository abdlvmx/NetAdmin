package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Epic 6: проверка сервиса выполняется и пишет статус+историю.
func TestRunDueChecks(t *testing.T) {
	app := newTestApp(t)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer up.Close()

	app.DB.Exec("INSERT INTO service_checks (name, type, target, interval_sec, enabled) VALUES ('site','http',?,60,1)", up.URL)
	app.RunDueChecks()

	var status string
	app.DB.QueryRow("SELECT last_status FROM service_checks WHERE name='site'").Scan(&status)
	if status != "up" {
		t.Fatalf("ожидался статус up, получено %q", status)
	}
	if n := countRows(app, "SELECT COUNT(*) FROM service_check_history WHERE up=1"); n != 1 {
		t.Fatalf("ожидалась 1 запись истории up, получено %d", n)
	}
}

// Epic 8: прогноз заполнения по растущему ряду.
func TestForecastDays(t *testing.T) {
	// 50,55,60,65,70,75 — наклон 5/день, текущее 75 → до 95 ≈ 4 дня
	days, cur, ok := forecastDays([]float64{50, 55, 60, 65, 70, 75}, 95)
	if !ok {
		t.Fatal("растущий ряд должен давать прогноз")
	}
	if cur < 74 || cur > 76 {
		t.Fatalf("текущее значение ~75, получено %.1f", cur)
	}
	if days < 3 || days > 5 {
		t.Fatalf("ожидалось ~4 дня, получено %d", days)
	}
	// плоский ряд — прогноза нет
	if _, _, ok := forecastDays([]float64{60, 60, 60, 60}, 95); ok {
		t.Fatal("плоский ряд не должен давать прогноз")
	}
	// мало точек
	if _, _, ok := forecastDays([]float64{10, 20}, 95); ok {
		t.Fatal("при <3 точках прогноза быть не должно")
	}
}

// Epic 7: расчёт рейтинга SLA.
func TestSLARating(t *testing.T) {
	if slaRating(0, 0) != "nodata" {
		t.Fatal("без проверок — nodata")
	}
	if slaRating(99.95, 100) != "good" {
		t.Fatal("99.95% → good")
	}
	if slaRating(99.5, 100) != "medium" {
		t.Fatal("99.5% → medium")
	}
	if slaRating(95, 100) != "poor" {
		t.Fatal("95% → poor")
	}
}

// Epic 9: влияние сбоя — оффлайн-родитель и его зависимые.
func TestTopologyImpact(t *testing.T) {
	app := newTestApp(t)
	app.DB.Exec("INSERT INTO devices (id,hostname,status) VALUES (1,'sql','offline'),(2,'1c','online'),(3,'web','online')")
	app.DB.Exec("INSERT INTO topology_links (parent_device_id, child_device_id) VALUES (1,2),(1,3)")

	rows, _ := app.DB.Query(`SELECT c.hostname FROM topology_links t
		JOIN devices p ON p.id=t.parent_device_id
		JOIN devices c ON c.id=t.child_device_id
		WHERE p.status='offline'`)
	var deps []string
	for rows.Next() {
		var h string
		rows.Scan(&h)
		deps = append(deps, h)
	}
	rows.Close()
	if len(deps) != 2 {
		t.Fatalf("ожидалось 2 зависимых от оффлайн SQL, получено %d (%v)", len(deps), deps)
	}
}
