package handlers

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"netadmin/internal/ingest"
)

func postJSON(t *testing.T, srv *httptest.Server, path, token string, payload map[string]any) int {
	t.Helper()
	payload["timestamp"] = time.Now().UTC().Unix()
	b, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", srv.URL+path, bytes.NewReader(b))
	req.Header.Set("X-Agent-Token", token)
	mac := hmac.New(sha256.New, []byte(token))
	mac.Write(b)
	req.Header.Set("X-Agent-Signature", hex.EncodeToString(mac.Sum(nil)))
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

// В инвентарной редакции новая служба пишется в историю устройства, но НЕ создаёт
// security-событие (это учёт конфигурации, не СОВ).
func TestServicesInventoryHistoryNoEvent(t *testing.T) {
	app := newTestApp(t) // редакция по умолчанию = inventory
	app.Ingest = ingest.New(app.DB, 90, 180, 365)
	const tok = "SVCINV"
	app.DB.Exec("INSERT INTO devices (hostname, status, agent_token) VALUES ('WS-1','online',?)", tok)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/agent-services", app.AgentServices)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	svc := func(name, disp, start, path string) map[string]any {
		return map[string]any{"name": name, "display_name": disp, "start_type": start, "path": path}
	}
	postJSON(t, srv, "/api/agent-services", tok, map[string]any{
		"hostname": "WS-1", "services": []map[string]any{svc("wuauserv", "Windows Update", "Auto", "")}})
	postJSON(t, srv, "/api/agent-services", tok, map[string]any{
		"hostname": "WS-1", "services": []map[string]any{
			svc("wuauserv", "Windows Update", "Auto", ""), svc("EvilSvc", "Backdoor", "Auto", `C:\evil.exe`)}})

	if n := countRows(app, "SELECT COUNT(*) FROM device_changes WHERE field='Служба добавлена'"); n != 1 {
		t.Fatalf("ожидалась 1 запись в истории устройства, получено %d", n)
	}
	if n := countRows(app, "SELECT COUNT(*) FROM events WHERE category='service'"); n != 0 {
		t.Fatalf("в инвентарной редакции security-события быть не должно, получено %d", n)
	}
}

func TestAgentServicesSnapshotDiff(t *testing.T) {
	app := newTestApp(t)
	const tok = "SVCTOK123"
	app.DB.Exec("INSERT INTO devices (hostname, status, agent_token) VALUES ('WS-1','online',?)", tok)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/agent-services", app.AgentServices)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	svc := func(name, disp, start, path string) map[string]any {
		return map[string]any{"name": name, "display_name": disp, "start_type": start, "path": path}
	}

	// первый снапшот — устанавливает базу, истории «новых» быть не должно
	if code := postJSON(t, srv, "/api/agent-services", tok, map[string]any{
		"hostname": "WS-1",
		"services": []map[string]any{svc("wuauserv", "Windows Update", "Auto", `C:\Windows\svchost.exe`),
			svc("Spooler", "Print Spooler", "Auto", `C:\Windows\spoolsv.exe`)},
	}); code != 200 {
		t.Fatalf("snapshot1: ожидался 200, получено %d", code)
	}
	if n := countRows(app, "SELECT COUNT(*) FROM services WHERE device_id=(SELECT id FROM devices WHERE hostname='WS-1')"); n != 2 {
		t.Fatalf("после snapshot1 ожидалось 2 службы, получено %d", n)
	}

	// второй снапшот — добавилась новая служба
	postJSON(t, srv, "/api/agent-services", tok, map[string]any{
		"hostname": "WS-1",
		"services": []map[string]any{svc("wuauserv", "Windows Update", "Auto", `C:\Windows\svchost.exe`),
			svc("Spooler", "Print Spooler", "Auto", `C:\Windows\spoolsv.exe`),
			svc("EvilSvc", "Backdoor", "Auto", `C:\Temp\evil.exe`)},
	})
	if n := countRows(app, "SELECT COUNT(*) FROM services WHERE device_id=(SELECT id FROM devices WHERE hostname='WS-1')"); n != 3 {
		t.Fatalf("после snapshot2 ожидалось 3 службы (полная замена), получено %d", n)
	}

	// только новая служба попадает в историю устройства (прежние — нет)
	if total := countRows(app, "SELECT COUNT(*) FROM device_changes WHERE field='Служба добавлена'"); total != 1 {
		t.Fatalf("ожидалась ровно 1 запись истории о новой службе, получено %d", total)
	}
	if n := countRows(app, "SELECT COUNT(*) FROM device_changes WHERE field='Служба добавлена' AND new_value LIKE '%Backdoor%'"); n != 1 {
		t.Fatalf("новая служба Backdoor должна попасть в историю, получено %d", n)
	}
}

func countRows(app *App, query string) int {
	var n int
	app.DB.QueryRow(query).Scan(&n)
	return n
}
