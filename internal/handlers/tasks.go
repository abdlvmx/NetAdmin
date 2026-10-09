package handlers

import (
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"sort"
	"strconv"

	"netadmin/internal/auth"
	"netadmin/internal/taskrun"
	"netadmin/internal/tz"
)

// enqueueTask ставит задачу устройству в очередь (pull-модель: агент заберёт сам).
func (a *App) enqueueTask(deviceID int64, kind, payload, label string, userID int64) (int64, error) {
	return a.enqueuePackageTask(deviceID, kind, payload, label, userID, 0)
}

// enqueuePackageTask ставит задачу, связанную с дистрибутивом.
//
// Идентификатор пакета хранится отдельной колонкой, а не только внутри payload:
// по нему проверяется право агента скачать файл. Разбирать ради этого JSON
// в SQL было бы хрупко.
func (a *App) enqueuePackageTask(deviceID int64, kind, payload, label string, userID, pkgID int64) (int64, error) {
	res, err := a.DB.Exec(`INSERT INTO agent_tasks (device_id, kind, payload, label, status, created_by, package_id)
		VALUES (?,?,?,?, 'pending', ?, ?)`, deviceID, kind, payload, label, userID, pkgID)
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
	var request struct {
		Protocol int `json:"protocol"`
	}
	if json.Unmarshal(ag.Body, &request) != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	// до завершения enrollment у агента нет device_id — задач не выдаём
	if !ag.Enroll && ag.DeviceID > 0 {
		// A single UPDATE is the claim. There is no SELECT/UPDATE race between
		// concurrent polls. Protocol 2 redelivers until the durable start ACK.
		query := `UPDATE agent_tasks SET status='sent', sent_at=COALESCE(sent_at,datetime('now')),task_protocol=1
			WHERE device_id=? AND status='pending' AND id IN (
			SELECT id FROM agent_tasks WHERE device_id=? AND status='pending'
			AND id<=COALESCE((SELECT MIN(id) FROM agent_tasks WHERE device_id=? AND status='pending' AND kind='selfupdate'),9223372036854775807)
			ORDER BY id LIMIT 20) RETURNING id,COALESCE(kind,''),COALESCE(payload,'')`
		args := []any{ag.DeviceID, ag.DeviceID, ag.DeviceID}
		if request.Protocol == 2 {
			query = `UPDATE agent_tasks SET status='sent', sent_at=COALESCE(sent_at,datetime('now')),task_protocol=2
			WHERE device_id=? AND id=(SELECT id FROM agent_tasks WHERE device_id=?
			AND (status='pending' OR (status='sent' AND task_protocol=2)) ORDER BY id LIMIT 1)
			AND (status='pending' OR (status='sent' AND task_protocol=2))
			RETURNING id,COALESCE(kind,''),COALESCE(payload,'')`
			args = []any{ag.DeviceID, ag.DeviceID}
		}
		rows, err := a.DB.QueryContext(r.Context(), query, args...)
		if err != nil {
			log.Printf("AgentTasksPoll: %v", err)
			http.Error(w, "queue unavailable", http.StatusServiceUnavailable)
			return
		}
		{
			for rows.Next() {
				var t task
				if err = rows.Scan(&t.ID, &t.Kind, &t.Payload); err != nil {
					break
				}
				tasks = append(tasks, t)
			}
			if err == nil {
				err = rows.Err()
			}
			rows.Close()
			if err != nil {
				log.Printf("AgentTasksPoll: %v", err)
				http.Error(w, "queue unavailable", http.StatusServiceUnavailable)
				return
			}
		}
		sort.Slice(tasks, func(i, j int) bool { return tasks[i].ID < tasks[j].ID })
	}
	protocol := 1
	if request.Protocol == 2 {
		protocol = 2
	}
	writeAgentJSON(w, ag.Key, map[string]any{"tasks": tasks, "protocol": protocol})
}

// AgentTasksResult — POST /api/agent-tasks/result : агент сообщает результат задачи.
func (a *App) AgentTasksResult(w http.ResponseWriter, r *http.Request) {
	ag, ok := a.authAgentPost(w, r)
	if !ok {
		return
	}
	var p struct {
		ID           int64  `json:"id"`
		Status       string `json:"status"` // done|failed
		Result       string `json:"result"`
		ExitCode     int    `json:"exit_code"`
		ExecutionKey string `json:"execution_key"`
	}
	if err := json.Unmarshal(ag.Body, &p); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	if ag.Enroll || ag.DeviceID <= 0 || p.ID <= 0 || (p.Status != "done" && p.Status != "failed" && p.Status != "cancelled") {
		http.Error(w, "invalid task result", http.StatusBadRequest)
		return
	}
	status, result := p.Status, taskrun.LimitOutput(p.Result)
	// обновляем только задачу, принадлежащую этому устройству
	res, err := a.DB.ExecContext(r.Context(), `UPDATE agent_tasks SET status=?, result=?, exit_code=?,done_at=datetime('now'),cancel_requested=0
		WHERE id=? AND device_id=? AND status IN ('sent','running')
		AND (task_protocol=1 OR execution_key=? OR execution_key='' OR (kind='selfupdate' AND ?=''))`, status, result, p.ExitCode, p.ID, ag.DeviceID, p.ExecutionKey, p.ExecutionKey)
	if err != nil {
		http.Error(w, "result not saved", http.StatusServiceUnavailable)
		return
	}
	n, err := res.RowsAffected()
	if err != nil {
		http.Error(w, "result not saved", http.StatusServiceUnavailable)
		return
	}
	if n == 0 {
		var oldStatus, oldResult, key, kind string
		var code, protocol int
		err = a.DB.QueryRowContext(r.Context(), `SELECT status,COALESCE(result,''),exit_code,task_protocol,COALESCE(execution_key,''),COALESCE(kind,'') FROM agent_tasks WHERE id=? AND device_id=?`, p.ID, ag.DeviceID).Scan(&oldStatus, &oldResult, &code, &protocol, &key, &kind)
		if errors.Is(err, sql.ErrNoRows) {
			http.Error(w, "task not found", http.StatusNotFound)
			return
		}
		if err != nil {
			http.Error(w, "result not saved", http.StatusServiceUnavailable)
			return
		}
		if oldStatus != status || oldResult != result || code != p.ExitCode || (protocol == 2 && key != "" && key != p.ExecutionKey && !(kind == "selfupdate" && p.ExecutionKey == "")) {
			http.Error(w, "result conflicts with saved state", http.StatusConflict)
			return
		}
	}
	writeAgentJSON(w, ag.Key, map[string]any{"ok": true})
}

// DeviceTasks — GET /api/devices/{id}/tasks : история удалённых действий устройства.
func (a *App) DeviceTasks(w http.ResponseWriter, r *http.Request) {
	user := auth.CurrentUser(a.DB, r)
	if user == nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	rows, err := a.DB.Query(`SELECT id,COALESCE(label,''), COALESCE(kind,''), COALESCE(status,''),
		exit_code, COALESCE(result,''), COALESCE(created_at,''), COALESCE(done_at,''),task_protocol,COALESCE(cancel_requested,0)
		FROM agent_tasks WHERE device_id=? ORDER BY id DESC LIMIT 100`, id)
	type item struct {
		ID              int64  `json:"id"`
		CanCancel       bool   `json:"can_cancel"`
		CancelRequested bool   `json:"cancel_requested"`
		Label           string `json:"label"`
		Kind            string `json:"kind"`
		Status          string `json:"status"`
		ExitCode        int    `json:"exit_code"`
		Result          string `json:"result"`
		Created         string `json:"created"`
		Done            string `json:"done"`
	}
	items := []item{}
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var it item
			var created, done string
			var protocol int
			if rows.Scan(&it.ID, &it.Label, &it.Kind, &it.Status, &it.ExitCode, &it.Result, &created, &done, &protocol, &it.CancelRequested) == nil {
				it.CanCancel = user.CanWrite() && (it.Status == "pending" || (protocol == 2 && (it.Status == "sent" || it.Status == "running")))
				it.Created = tz.DateTime(created)
				it.Done = tz.DateTime(done)
				items = append(items, it)
			}
		}
		if err := rows.Err(); err != nil {
			log.Printf("DeviceTasks: %v", err)
		}
	}
	writeJSON(w, map[string]any{"tasks": items})
}
