package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAgentUpdateLeavesFollowingTasksPendingForTheNextProcess(t *testing.T) {
	app := newTestApp(t)
	const tok = "UPDATE-BARRIER-TOKEN"
	res, err := app.DB.Exec("INSERT INTO devices (hostname,status,agent_token) VALUES ('WS-UP','online',?)", tok)
	if err != nil {
		t.Fatal(err)
	}
	did, _ := res.LastInsertId()
	ids := []int64{}
	for _, kind := range []string{"check", "selfupdate", "command"} {
		id, err := app.enqueueTask(did, kind, "", kind, 0)
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/agent-tasks/poll", app.AgentTasksPoll)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	var response struct {
		Tasks []struct {
			ID int64 `json:"id"`
		} `json:"tasks"`
	}
	code, body := agentPost(t, app, srv, "/api/agent-tasks/poll", tok, map[string]any{"hostname": "WS-UP"})
	if code != http.StatusOK || json.Unmarshal(body, &response) != nil || len(response.Tasks) != 2 || response.Tasks[1].ID != ids[1] {
		t.Fatalf("unexpected update batch: HTTP %d %s", code, body)
	}
	var state string
	if err := app.DB.QueryRow("SELECT status FROM agent_tasks WHERE id=?", ids[2]).Scan(&state); err != nil || state != "pending" {
		t.Fatalf("following task lost: %q %v", state, err)
	}
	code, body = agentPost(t, app, srv, "/api/agent-tasks/poll", tok, map[string]any{"hostname": "WS-UP"})
	if code != http.StatusOK || json.Unmarshal(body, &response) != nil || len(response.Tasks) != 1 || response.Tasks[0].ID != ids[2] {
		t.Fatalf("new agent did not receive remaining task: HTTP %d %s", code, body)
	}
}
