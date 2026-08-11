package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAssessDisk(t *testing.T) {
	cases := []struct {
		name string
		in   diskInfo
		sev  string
	}{
		{"healthy", diskInfo{Health: "Healthy", WearPct: 10, Temperature: 35}, ""},
		{"predict-fail", diskInfo{Health: "Healthy", PredictFail: true}, "critical"},
		{"unhealthy", diskInfo{Health: "Unhealthy"}, "critical"},
		{"ssd-worn-out", diskInfo{Health: "Healthy", WearPct: 95}, "critical"},
		{"warning-health", diskInfo{Health: "Warning"}, "warning"},
		{"ssd-high-wear", diskInfo{Health: "Healthy", WearPct: 85}, "warning"},
		{"hot", diskInfo{Health: "Healthy", Temperature: 62}, "warning"},
		{"read-errors", diskInfo{Health: "Healthy", ReadErrors: 3}, "warning"},
	}
	for _, c := range cases {
		if got := assessDisk(c.in).Severity; got != c.sev {
			t.Errorf("%s: ожидалось severity=%q, получено %q", c.name, c.sev, got)
		}
	}
}

func TestAgentDisksSnapshotAndAlert(t *testing.T) {
	app := newTestApp(t)
	const tok = "DISKTOK1"
	app.DB.Exec("INSERT INTO devices (hostname, status, agent_token) VALUES ('WS-9','online',?)", tok)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/agent-disks", app.AgentDisks)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	disk := func(model, serial, health string, wear int, predict bool) map[string]any {
		return map[string]any{"model": model, "serial": serial, "health": health,
			"wear_pct": wear, "predict_fail": predict, "size_gb": 500, "media_type": "SSD"}
	}

	// первый снимок: один исправный, один с предсказанным отказом
	postJSON(t, srv, "/api/agent-disks", tok, map[string]any{
		"hostname": "WS-9", "disks": []map[string]any{
			disk("Good SSD", "S-OK", "Healthy", 10, false),
			disk("Dying SSD", "S-BAD", "Healthy", 10, true)}})

	if n := countRows(app, "SELECT COUNT(*) FROM disks WHERE device_id=(SELECT id FROM devices WHERE hostname='WS-9')"); n != 2 {
		t.Fatalf("после snapshot1 ожидалось 2 диска, получено %d", n)
	}
	if n := countRows(app, "SELECT COUNT(*) FROM events WHERE category='disk_health'"); n != 1 {
		t.Fatalf("ожидался 1 алерт о новом отказе диска, получено %d", n)
	}

	// второй снимок: тот же отказавший диск всё ещё критичен — нового алерта быть НЕ должно
	postJSON(t, srv, "/api/agent-disks", tok, map[string]any{
		"hostname": "WS-9", "disks": []map[string]any{
			disk("Good SSD", "S-OK", "Healthy", 10, false),
			disk("Dying SSD", "S-BAD", "Healthy", 10, true)}})
	if n := countRows(app, "SELECT COUNT(*) FROM events WHERE category='disk_health'"); n != 1 {
		t.Fatalf("повторный критичный диск не должен давать новый алерт, получено всего %d", n)
	}

	// третий снимок: добавился ещё один отказавший диск — ровно 1 новый алерт
	postJSON(t, srv, "/api/agent-disks", tok, map[string]any{
		"hostname": "WS-9", "disks": []map[string]any{
			disk("Good SSD", "S-OK", "Healthy", 10, false),
			disk("Dying SSD", "S-BAD", "Healthy", 10, true),
			disk("Another Bad", "S-BAD2", "Unhealthy", 0, false)}})
	if n := countRows(app, "SELECT COUNT(*) FROM events WHERE category='disk_health'"); n != 2 {
		t.Fatalf("новый отказавший диск должен дать ещё 1 алерт (итого 2), получено %d", n)
	}
	if n := countRows(app, "SELECT COUNT(*) FROM disks WHERE device_id=(SELECT id FROM devices WHERE hostname='WS-9')"); n != 3 {
		t.Fatalf("после snapshot3 ожидалось 3 диска (полная замена), получено %d", n)
	}
}
