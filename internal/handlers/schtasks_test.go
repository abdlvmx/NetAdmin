package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAgentSchTasksSnapshotDiff(t *testing.T) {
	app := newTestApp(t)
	const tok = "TASKTOK123"
	app.DB.Exec("INSERT INTO devices (hostname, status, agent_token) VALUES ('WS-1','online',?)", tok)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/agent-schtasks", app.AgentSchTasks)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	task := func(path, name, action string) map[string]any {
		return map[string]any{"path": path, "name": name, "action": action, "state": "Ready"}
	}

	// первый снапшот — база, истории изменений быть не должно
	if code := postJSON(t, app, srv, "/api/agent-schtasks", tok, map[string]any{
		"hostname": "WS-1",
		"tasks":    []map[string]any{task(`\Microsoft\Windows\`, "GoogleUpdate", `C:\GoogleUpdate.exe`)},
	}); code != 200 {
		t.Fatalf("snapshot1: ожидался 200, получено %d", code)
	}
	if n := countRows(app, "SELECT COUNT(*) FROM scheduled_tasks WHERE device_id=(SELECT id FROM devices WHERE hostname='WS-1')"); n != 1 {
		t.Fatalf("после snapshot1 ожидалась 1 задача, получено %d", n)
	}

	// второй снапшот: новая задача + перенацеливание существующей
	postJSON(t, app, srv, "/api/agent-schtasks", tok, map[string]any{
		"hostname": "WS-1",
		"tasks": []map[string]any{
			task(`\Microsoft\Windows\`, "GoogleUpdate", `C:\Temp\malware.exe`), // перенацелено
			task(`\`, "Backdoor", `powershell -enc ZQ==`),                      // новая
		},
	})
	if n := countRows(app, "SELECT COUNT(*) FROM scheduled_tasks WHERE device_id=(SELECT id FROM devices WHERE hostname='WS-1')"); n != 2 {
		t.Fatalf("после snapshot2 ожидалось 2 задачи (полная замена), получено %d", n)
	}

	// обе изменившиеся задачи (новая + перенацеленная) попадают в историю устройства
	if got := countRows(app, "SELECT COUNT(*) FROM device_changes WHERE field='Задача планировщика добавлена'"); got != 2 {
		t.Fatalf("ожидалось 2 записи истории задач, получено %d", got)
	}
	if n := countRows(app, "SELECT COUNT(*) FROM device_changes WHERE field='Задача планировщика добавлена' AND new_value LIKE '%malware%'"); n != 1 {
		t.Fatalf("перенацеливание GoogleUpdate должно попасть в историю, получено %d", n)
	}
}
