package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAgentAutorunsSnapshotDiff(t *testing.T) {
	app := newTestApp(t)
	const tok = "ARTOK123"
	app.DB.Exec("INSERT INTO devices (hostname, status, agent_token) VALUES ('WS-1','online',?)", tok)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/agent-autoruns", app.AgentAutoruns)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ar := func(loc, name, cmd string) map[string]any {
		return map[string]any{"location": loc, "name": name, "command": cmd}
	}

	// первый снапшот — база, истории изменений быть не должно
	if code := postJSON(t, srv, "/api/agent-autoruns", tok, map[string]any{
		"hostname": "WS-1",
		"autoruns": []map[string]any{ar(`HKLM\Run`, "OneDrive", `C:\OneDrive.exe`)},
	}); code != 200 {
		t.Fatalf("snapshot1: ожидался 200, получено %d", code)
	}
	if n := countRows(app, "SELECT COUNT(*) FROM autoruns WHERE device_id=(SELECT id FROM devices WHERE hostname='WS-1')"); n != 1 {
		t.Fatalf("после snapshot1 ожидалась 1 запись, получено %d", n)
	}

	// второй снапшот: добавилась новая запись + у существующей сменилась команда
	postJSON(t, srv, "/api/agent-autoruns", tok, map[string]any{
		"hostname": "WS-1",
		"autoruns": []map[string]any{
			ar(`HKLM\Run`, "OneDrive", `C:\Temp\hijack.exe`), // подмена команды
			ar(`HKCU\Run`, "Updater", `C:\Users\u\evil.exe`), // новая запись
		},
	})
	if n := countRows(app, "SELECT COUNT(*) FROM autoruns WHERE device_id=(SELECT id FROM devices WHERE hostname='WS-1')"); n != 2 {
		t.Fatalf("после snapshot2 ожидалось 2 записи (полная замена), получено %d", n)
	}

	// в историю устройства попадают обе изменившиеся точки (новая + подмена команды)
	if got := countRows(app, "SELECT COUNT(*) FROM device_changes WHERE field='Автозагрузка добавлена'"); got != 2 {
		t.Fatalf("ожидалось 2 записи истории автозагрузки, получено %d", got)
	}
	if n := countRows(app, "SELECT COUNT(*) FROM device_changes WHERE field='Автозагрузка добавлена' AND new_value LIKE '%hijack%'"); n != 1 {
		t.Fatalf("подмена команды OneDrive должна попасть в историю, получено %d", n)
	}
}
