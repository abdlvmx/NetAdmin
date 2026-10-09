package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"

	"netadmin/internal/auth"
)

func taskServer(t *testing.T) (*App, *httptest.Server, int64, string) {
	t.Helper()
	a := newTestApp(t)
	const token = "task-delivery-test-key"
	res, err := a.DB.Exec(`INSERT INTO devices(hostname,status,agent_token) VALUES('TASK-PC','online',?)`, token)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := res.LastInsertId()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/agent-tasks/poll", a.AgentTasksPoll)
	mux.HandleFunc("POST /api/agent-tasks/start", a.AgentTaskStart)
	mux.HandleFunc("POST /api/agent-tasks/state", a.AgentTaskState)
	mux.HandleFunc("POST /api/agent-tasks/result", a.AgentTasksResult)
	s := httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return a, s, id, token
}

func taskIDs(t *testing.T, b []byte) []int64 {
	t.Helper()
	var reply struct {
		Tasks []struct {
			ID int64 `json:"id"`
		} `json:"tasks"`
	}
	if err := json.Unmarshal(b, &reply); err != nil {
		t.Fatalf("task reply: %v %s", err, b)
	}
	ids := []int64{}
	for _, task := range reply.Tasks {
		ids = append(ids, task.ID)
	}
	return ids
}

func TestTaskDeliveryRetriesUntilStartAndResultsAreImmutable(t *testing.T) {
	a, s, did, key := taskServer(t)
	id, err := a.enqueueTask(did, "command", "ipconfig", "Network", 0)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		code, b := agentPost(t, a, s, "/api/agent-tasks/poll", key, map[string]any{"hostname": "TASK-PC", "protocol": 2})
		ids := taskIDs(t, b)
		if code != 200 || len(ids) != 1 || ids[0] != id {
			t.Fatalf("redelivery: %d %s", code, b)
		}
	}
	const execution = "0123456789abcdef0123456789abcdef"
	for i := 0; i < 2; i++ {
		code, b := agentPost(t, a, s, "/api/agent-tasks/start", key, map[string]any{"id": id, "execution_key": execution})
		var reply struct {
			OK bool `json:"ok"`
		}
		if code != 200 || json.Unmarshal(b, &reply) != nil || !reply.OK {
			t.Fatalf("start: %d %s", code, b)
		}
	}
	code, b := agentPost(t, a, s, "/api/agent-tasks/start", key, map[string]any{"id": id, "execution_key": "abcdef0123456789abcdef0123456789"})
	var conflict struct {
		Conflict bool `json:"conflict"`
		OK       bool `json:"ok"`
	}
	if code != 200 || json.Unmarshal(b, &conflict) != nil || !conflict.Conflict || conflict.OK {
		t.Fatalf("second executor admitted: %d %s", code, b)
	}
	_, b = agentPost(t, a, s, "/api/agent-tasks/poll", key, map[string]any{"protocol": 2})
	if len(taskIDs(t, b)) != 0 {
		t.Fatal("running task redelivered")
	}
	payload := map[string]any{"id": id, "status": "failed", "result": "подробная ошибка", "exit_code": 17, "execution_key": execution}
	code, b = agentPost(t, a, s, "/api/agent-tasks/result", key, payload)
	if code != 200 {
		t.Fatalf("result: %d %s", code, b)
	}
	_, err = a.DB.Exec(`UPDATE agent_tasks SET done_at='2000-01-01 00:00:00' WHERE id=?`, id)
	if err != nil {
		t.Fatal(err)
	}
	delete(payload, "nonce")
	delete(payload, "timestamp")
	code, b = agentPost(t, a, s, "/api/agent-tasks/result", key, payload)
	if code != 200 {
		t.Fatalf("retry rejected: %d %s", code, b)
	}
	var stamp, result string
	if err = a.DB.QueryRow(`SELECT done_at,result FROM agent_tasks WHERE id=?`, id).Scan(&stamp, &result); err != nil {
		t.Fatal(err)
	}
	if stamp != "2000-01-01 00:00:00" || result != "подробная ошибка" {
		t.Fatal("retry changed confirmed result")
	}
	payload["result"] = "different"
	delete(payload, "nonce")
	delete(payload, "timestamp")
	code, _ = agentPost(t, a, s, "/api/agent-tasks/result", key, payload)
	if code != http.StatusConflict {
		t.Fatalf("conflicting result accepted: %d", code)
	}
}

func TestConcurrentLegacyPollsClaimEachTaskOnce(t *testing.T) {
	a, s, did, key := taskServer(t)
	for i := 0; i < 50; i++ {
		if _, err := a.enqueueTask(did, "command", "ipconfig", "test", 0); err != nil {
			t.Fatal(err)
		}
	}
	var mu sync.Mutex
	counts := map[int64]int{}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			code, b := agentPost(t, a, s, "/api/agent-tasks/poll", key, map[string]any{"hostname": "TASK-PC"})
			if code != 200 {
				t.Errorf("poll: %d %s", code, b)
				return
			}
			ids := taskIDs(t, b)
			mu.Lock()
			defer mu.Unlock()
			for _, id := range ids {
				counts[id]++
			}
		}()
	}
	wg.Wait()
	if len(counts) != 50 {
		t.Fatalf("lost tasks: %d", len(counts))
	}
	for id, n := range counts {
		if n != 1 {
			t.Fatalf("task %d issued %d times", id, n)
		}
	}
}

func cancelRequest(t *testing.T, a *App, id int64, role string) *httptest.ResponseRecorder {
	t.Helper()
	res, err := a.DB.Exec(`INSERT INTO users(username,role,password_hash) VALUES(?,?,?)`, fmt.Sprintf("cancel-%d-%s", id, role), role, "unused")
	if err != nil {
		t.Fatal(err)
	}
	uid, _ := res.LastInsertId()
	token, err := auth.CreateSession(a.DB, uid)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", fmt.Sprintf("/api/tasks/%d/cancel", id), nil)
	r.SetPathValue("id", strconv.FormatInt(id, 10))
	r.AddCookie(&http.Cookie{Name: "session", Value: token})
	w := httptest.NewRecorder()
	a.CancelTask(w, r)
	return w
}

func TestCancellationRequiresWriteRoleAndSignalsRunningTask(t *testing.T) {
	a, s, did, key := taskServer(t)
	id, _ := a.enqueueTask(did, "command", "ipconfig", "test", 0)
	if w := cancelRequest(t, a, id, "viewer"); w.Code != 403 {
		t.Fatalf("reader cancellation: %d", w.Code)
	}
	if w := cancelRequest(t, a, id, "admin"); w.Code != 200 {
		t.Fatalf("queued cancellation: %d %s", w.Code, w.Body.String())
	}
	_, b := agentPost(t, a, s, "/api/agent-tasks/poll", key, map[string]any{"protocol": 2})
	if len(taskIDs(t, b)) != 0 {
		t.Fatal("cancelled pending task was issued")
	}
	id, _ = a.enqueueTask(did, "command", "ipconfig", "test", 0)
	agentPost(t, a, s, "/api/agent-tasks/poll", key, map[string]any{"protocol": 2})
	const execution = "0123456789abcdef0123456789abcdef"
	agentPost(t, a, s, "/api/agent-tasks/start", key, map[string]any{"id": id, "execution_key": execution})
	if w := cancelRequest(t, a, id, "admin"); w.Code != 200 {
		t.Fatalf("running cancellation: %d %s", w.Code, w.Body.String())
	}
	code, b := agentPost(t, a, s, "/api/agent-tasks/state", key, map[string]any{"id": id, "execution_key": execution})
	var state struct {
		Cancel bool `json:"cancel_requested"`
	}
	if code != 200 || json.Unmarshal(b, &state) != nil || !state.Cancel {
		t.Fatalf("cancellation lost: %d %s", code, b)
	}
	code, _ = agentPost(t, a, s, "/api/agent-tasks/result", key, map[string]any{"id": id, "execution_key": execution, "status": "cancelled", "result": "stopped", "exit_code": 125})
	if code != 200 {
		t.Fatalf("cancelled result: %d", code)
	}
}
