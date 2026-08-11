package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"netadmin/internal/ingest"
)

func TestHeartbeatTracksHardwareChanges(t *testing.T) {
	app := newTestApp(t)
	app.Ingest = ingest.New(app.DB, 90, 180, 365)
	const tok = "HBTOK123"
	app.DB.Exec(`INSERT INTO devices (hostname, status, agent_token, cpu_model, ram_total_gb, disk_total_gb, os_version)
		VALUES ('WS-1','online',?, 'Intel i5-2400', 8, 240, 'Microsoft Windows 10 Pro')`, tok)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/agent-heartbeat", app.AgentHeartbeat)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// апгрейд: CPU, RAM 8→16, диск 240→480, ОС Win10→Win11
	code := postJSON(t, srv, "/api/agent-heartbeat", tok, map[string]any{
		"hostname": "WS-1", "os": "Windows", "cpu": 10.0, "ram": 30.0, "disk": 40.0,
		"cpu_model": "Intel i7-12700", "ram_total_gb": 16, "disk_total_gb": 480,
		"os_version": "Microsoft Windows 11 Pro",
	})
	if code != 200 {
		t.Fatalf("ожидался 200, получено %d", code)
	}

	if n := countRows(app, "SELECT COUNT(*) FROM device_changes"); n != 4 {
		t.Fatalf("ожидалось 4 изменения (cpu/ram/disk/os), получено %d", n)
	}
	if n := countRows(app, "SELECT COUNT(*) FROM device_changes WHERE field='Оперативная память' AND old_value='8 ГБ' AND new_value='16 ГБ'"); n != 1 {
		t.Fatalf("нет корректной записи об апгрейде RAM, получено %d", n)
	}
	if n := countRows(app, "SELECT COUNT(*) FROM device_changes WHERE field='Операционная система' AND new_value='Microsoft Windows 11 Pro'"); n != 1 {
		t.Fatalf("нет записи о смене ОС, получено %d", n)
	}
	// характеристики в devices обновились
	var ram int
	app.DB.QueryRow("SELECT ram_total_gb FROM devices WHERE hostname='WS-1'").Scan(&ram)
	if ram != 16 {
		t.Fatalf("ram_total_gb должен стать 16, получено %d", ram)
	}

	// повторный heartbeat с теми же данными — новых изменений нет
	postJSON(t, srv, "/api/agent-heartbeat", tok, map[string]any{
		"hostname": "WS-1", "os": "Windows", "cpu": 11.0, "ram": 31.0, "disk": 41.0,
		"cpu_model": "Intel i7-12700", "ram_total_gb": 16, "disk_total_gb": 480,
		"os_version": "Microsoft Windows 11 Pro",
	})
	if n := countRows(app, "SELECT COUNT(*) FROM device_changes"); n != 4 {
		t.Fatalf("повтор не должен плодить изменения: %d", n)
	}
}

func TestHeartbeatFirstPopulationNoChange(t *testing.T) {
	app := newTestApp(t)
	app.Ingest = ingest.New(app.DB, 90, 180, 365)
	const tok = "HBTOK2"
	// устройство без характеристик (первый сбор)
	app.DB.Exec(`INSERT INTO devices (hostname, status, agent_token) VALUES ('WS-2','online',?)`, tok)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/agent-heartbeat", app.AgentHeartbeat)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	postJSON(t, srv, "/api/agent-heartbeat", tok, map[string]any{
		"hostname": "WS-2", "os": "Windows", "cpu": 5.0, "ram": 20.0, "disk": 30.0,
		"cpu_model": "AMD Ryzen 5", "ram_total_gb": 32, "disk_total_gb": 1000,
		"os_version": "Microsoft Windows 11 Pro",
	})
	// первое заполнение характеристик НЕ считается изменением
	if n := countRows(app, "SELECT COUNT(*) FROM device_changes"); n != 0 {
		t.Fatalf("первое заполнение не должно давать изменений, получено %d", n)
	}
	var cpu string
	app.DB.QueryRow("SELECT cpu_model FROM devices WHERE hostname='WS-2'").Scan(&cpu)
	if cpu != "AMD Ryzen 5" {
		t.Fatalf("cpu_model должен заполниться, получено %q", cpu)
	}
}
