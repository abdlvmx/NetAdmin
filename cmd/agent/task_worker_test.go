package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"netadmin/internal/taskrun"
)

func TestTaskPumpKeepsResultAcrossLostAcknowledgementAndRestart(t *testing.T) {
	const key = "task-pump-test-key"
	oldURL := serverURL
	oldKey, oldID := agentIdentity()
	t.Cleanup(func() { serverURL = oldURL; setAgentIdentity(oldKey, oldID) })
	var resultAttempts, runs atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var reply any
		switch r.URL.Path {
		case "/api/agent-tasks/poll":
			reply = map[string]any{"protocol": 2, "tasks": []taskrun.Task{{ID: 1, Kind: "command", Payload: "ipconfig"}}}
		case "/api/agent-tasks/start":
			reply = map[string]any{"ok": true}
		case "/api/agent-tasks/state":
			reply = map[string]any{"status": "running"}
		case "/api/agent-tasks/result":
			var result struct {
				Status, Result string
				ExitCode       int `json:"exit_code"`
			}
			if err := json.NewDecoder(r.Body).Decode(&result); err != nil {
				t.Error(err)
			}
			if result.Status != "failed" || result.Result != "ошибка с подробностями" || result.ExitCode != 17 {
				t.Errorf("result changed: %+v", result)
			}
			n := resultAttempts.Add(1)
			if n == 1 {
				http.Error(w, "temporary failure", 503)
				return
			}
			reply = map[string]any{"ok": true}
			if n == 2 {
				w.Header().Set(hdrSig, "lost-or-invalid-ack")
				w.Write([]byte(`{"ok":true}`))
				return
			}
		default:
			http.NotFound(w, r)
			return
		}
		b, _ := json.Marshal(reply)
		w.Header().Set(hdrSig, sign(key, b))
		w.Write(b)
	}))
	defer s.Close()
	serverURL = s.URL
	setAgentIdentity(key, 123)
	runner := func(context.Context, string, string) taskrun.Outcome {
		runs.Add(1)
		return taskrun.Outcome{Status: "failed", Output: "ошибка с подробностями", ExitCode: 17}
	}
	path := filepath.Join(t.TempDir(), "agent_task.json")
	e, err := taskrun.Open(path, runner)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { e.Close() }()
	deadline := time.Now().Add(2 * time.Second)
	for resultAttempts.Load() < 2 && time.Now().Before(deadline) {
		pumpTasks(context.Background(), e)
		time.Sleep(time.Millisecond)
	}
	if resultAttempts.Load() != 2 || e.Record == nil || e.Record.Phase != "finished" {
		t.Fatalf("result not retained: attempts=%d record=%+v", resultAttempts.Load(), e.Record)
	}
	e.Close()
	e, err = taskrun.Open(path, runner)
	if err != nil {
		t.Fatal(err)
	}
	pumpTasks(context.Background(), e)
	if e.Record != nil || runs.Load() != 1 || resultAttempts.Load() != 3 {
		t.Fatalf("retry replayed execution or lost acknowledgement: runs=%d attempts=%d record=%+v", runs.Load(), resultAttempts.Load(), e.Record)
	}
}
