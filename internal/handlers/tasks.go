package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"netadmin/internal/auth"
	"netadmin/internal/tz"
)

// enqueueTask ставит задачу устройству в очередь (pull-модель: агент заберёт сам).
func (a *App) enqueueTask(deviceID int64, kind, payload, label string, userID int64) (int64, error) {
	res, err := a.DB.Exec(`INSERT INTO agent_tasks (device_id, kind, payload, label, status, created_by)
		VALUES (?,?,?,?, 'pending', ?)`, deviceID, kind, payload, label, userID)
	if err != nil {
		return 0, err
	}
	id, _ := res.LastInsertId()
	return id, nil
}

// AgentTasksPoll — POST /api/agent-tasks/poll : агент забирает свои ожидающие задачи.
// Возвращает задачи и помечает их «sent» (выдача под токеном устройства).
func (a *App) AgentTasksPoll(w http.ResponseWriter, r *http.Request) {
	ag, ok := a.authAgentPost(w, r)
	if !ok {
		return
	}
	type task struct {
		ID      int64  `json:"id"`
		Kind    string `json:"kind"`
		Payload string `json:"payload"`
	}
	tasks := []task{}
	// до завершения enrollment у агента нет device_id — задач не выдаём
	if !ag.Enroll && ag.DeviceID > 0 {
		rows, err := a.DB.Query(`SELECT id, COALESCE(kind,''), COALESCE(payload,'')
			FROM agent_tasks WHERE device_id=? AND status='pending' ORDER BY id LIMIT 20`, ag.DeviceID)
		if err == nil {
			for rows.Next() {
				var t task
				if rows.Scan(&t.ID, &t.Kind, &t.Payload) == nil {
					tasks = append(tasks, t)
				}
			}
			rows.Close()
		}
		for _, t := range tasks {
			a.DB.Exec("UPDATE agent_tasks SET status='sent', sent_at=datetime('now') WHERE id=?", t.ID)
		}
	}
	writeAgentJSON(w, ag.Key, map[string]any{"tasks": tasks})
}

// AgentTasksResult — POST /api/agent-tasks/result : агент сообщает результат задачи.
func (a *App) AgentTasksResult(w http.ResponseWriter, r *http.Request) {
	ag, ok := a.authAgentPost(w, r)
	if !ok {
		return
	}
	var p struct {
		ID       int64  `json:"id"`
		Status   string `json:"status"` // done|failed
		Result   string `json:"result"`
		ExitCode int    `json:"exit_code"`
	}
	if err := json.Unmarshal(ag.Body, &p); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	status := "done"
	if p.Status == "failed" {
		status = "failed"
	}
	result := p.Result
	if len(result) > 8000 { // ограничиваем объём результата
		result = result[:8000] + "…"
	}
	// обновляем только задачу, принадлежащую этому устройству
	a.DB.Exec(`UPDATE agent_tasks SET status=?, result=?, exit_code=?, done_at=datetime('now')
		WHERE id=? AND device_id=?`, status, result, p.ExitCode, p.ID, ag.DeviceID)
	writeAgentJSON(w, ag.Key, map[string]any{"ok": true})
}

// DeviceTasks — GET /api/devices/{id}/tasks : история удалённых действий устройства.
func (a *App) DeviceTasks(w http.ResponseWriter, r *http.Request) {
	if auth.CurrentUser(a.DB, r) == nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	rows, err := a.DB.Query(`SELECT COALESCE(label,''), COALESCE(kind,''), COALESCE(status,''),
		exit_code, COALESCE(result,''), COALESCE(created_at,''), COALESCE(done_at,'')
		FROM agent_tasks WHERE device_id=? ORDER BY id DESC LIMIT 100`, id)
	type item struct {
		Label    string `json:"label"`
		Kind     string `json:"kind"`
		Status   string `json:"status"`
		ExitCode int    `json:"exit_code"`
		Result   string `json:"result"`
		Created  string `json:"created"`
		Done     string `json:"done"`
	}
	items := []item{}
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var it item
			var created, done string
			if rows.Scan(&it.Label, &it.Kind, &it.Status, &it.ExitCode, &it.Result, &created, &done) == nil {
				it.Created = tz.DateTime(created)
				it.Done = tz.DateTime(done)
				items = append(items, it)
			}
		}
	}
	writeJSON(w, map[string]any{"tasks": items})
}
