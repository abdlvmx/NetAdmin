package handlers

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// postHMAC выполняет подписанный POST агента и возвращает статус и тело ответа.
func postHMAC(t *testing.T, srv *httptest.Server, path, token string, payload map[string]any) (int, []byte) {
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
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, body
}

func TestAgentTaskQueueFlow(t *testing.T) {
	app := newTestApp(t)
	const tok = "TASKTOK1"
	res, _ := app.DB.Exec("INSERT INTO devices (hostname, status, agent_token) VALUES ('WS-5','online',?)", tok)
	did, _ := res.LastInsertId()

	if _, err := app.enqueueTask(did, "reboot", "", "Перезагрузка", 0); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/agent-tasks/poll", app.AgentTasksPoll)
	mux.HandleFunc("POST /api/agent-tasks/result", app.AgentTasksResult)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// первый опрос — задача выдаётся и помечается sent
	code, body := postHMAC(t, srv, "/api/agent-tasks/poll", tok, map[string]any{"hostname": "WS-5"})
	if code != 200 {
		t.Fatalf("poll код %d", code)
	}
	var r struct {
		Tasks []struct {
			ID   int64  `json:"id"`
			Kind string `json:"kind"`
		} `json:"tasks"`
	}
	json.Unmarshal(body, &r)
	if len(r.Tasks) != 1 || r.Tasks[0].Kind != "reboot" {
		t.Fatalf("ожидалась 1 задача reboot, получено %+v", r.Tasks)
	}
	if n := countRows(app, "SELECT COUNT(*) FROM agent_tasks WHERE status='sent'"); n != 1 {
		t.Fatalf("задача должна быть помечена sent, sent=%d", n)
	}

	// повторный опрос — ожидающих задач больше нет
	_, body2 := postHMAC(t, srv, "/api/agent-tasks/poll", tok, map[string]any{"hostname": "WS-5"})
	var r2 struct {
		Tasks []json.RawMessage `json:"tasks"`
	}
	json.Unmarshal(body2, &r2)
	if len(r2.Tasks) != 0 {
		t.Fatalf("повторный опрос не должен возвращать задачи, получено %d", len(r2.Tasks))
	}

	// результат от агента
	taskID := r.Tasks[0].ID
	postHMAC(t, srv, "/api/agent-tasks/result", tok, map[string]any{
		"id": taskID, "status": "done", "result": "запланировано", "exit_code": 0})
	var status, result string
	app.DB.QueryRow("SELECT status, COALESCE(result,'') FROM agent_tasks WHERE id=?", taskID).Scan(&status, &result)
	if status != "done" || result != "запланировано" {
		t.Fatalf("результат не сохранён: status=%q result=%q", status, result)
	}
}

func TestBuildMagicPacket(t *testing.T) {
	p, err := buildMagicPacket("AA:BB:CC:DD:EE:FF")
	if err != nil {
		t.Fatalf("buildMagicPacket: %v", err)
	}
	if len(p) != 102 {
		t.Fatalf("длина пакета %d, ожидалось 102", len(p))
	}
	for i := 0; i < 6; i++ {
		if p[i] != 0xFF {
			t.Fatalf("байт %d должен быть 0xFF", i)
		}
	}
	want := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}
	if !bytes.Equal(p[6:12], want) {
		t.Fatalf("первое повторение MAC неверно: %x", p[6:12])
	}
	if _, err := buildMagicPacket("не-mac"); err == nil {
		t.Fatal("некорректный MAC должен давать ошибку")
	}
}
