package handlers

import (
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"netadmin/internal/auth"
)

func (a *App) AgentTaskStart(w http.ResponseWriter, r *http.Request) {
	ag, ok := a.authAgentPost(w, r)
	if !ok {
		return
	}
	var p struct {
		ID           int64  `json:"id"`
		ExecutionKey string `json:"execution_key"`
	}
	parseErr := json.Unmarshal(ag.Body, &p)
	keyBytes, keyErr := hex.DecodeString(p.ExecutionKey)
	if ag.Enroll || parseErr != nil || p.ID <= 0 || keyErr != nil || len(keyBytes) != 16 {
		http.Error(w, "invalid start", http.StatusBadRequest)
		return
	}
	res, err := a.DB.ExecContext(r.Context(), `UPDATE agent_tasks SET status='running',execution_key=?,started_at=COALESCE(started_at,datetime('now'))
	WHERE id=? AND device_id=? AND task_protocol=2 AND cancel_requested=0
	AND (status='sent' OR (status='running' AND execution_key=?))`, p.ExecutionKey, p.ID, ag.DeviceID, p.ExecutionKey)
	if err != nil {
		http.Error(w, "start not saved", http.StatusServiceUnavailable)
		return
	}
	n, err := res.RowsAffected()
	if err != nil {
		http.Error(w, "start not saved", http.StatusServiceUnavailable)
		return
	}
	if n > 0 {
		writeAgentJSON(w, ag.Key, map[string]any{"ok": true})
		return
	}
	a.writeTaskState(w, r, ag.Key, ag.DeviceID, p.ID, p.ExecutionKey)
}

func (a *App) AgentTaskState(w http.ResponseWriter, r *http.Request) {
	ag, ok := a.authAgentPost(w, r)
	if !ok {
		return
	}
	var p struct {
		ID           int64  `json:"id"`
		ExecutionKey string `json:"execution_key"`
	}
	if ag.Enroll || json.Unmarshal(ag.Body, &p) != nil || p.ID <= 0 {
		http.Error(w, "invalid task", http.StatusBadRequest)
		return
	}
	a.writeTaskState(w, r, ag.Key, ag.DeviceID, p.ID, p.ExecutionKey)
}

func (a *App) writeTaskState(w http.ResponseWriter, r *http.Request, signingKey string, deviceID, id int64, executionKey string) {
	var status, key string
	var cancelled bool
	err := a.DB.QueryRowContext(r.Context(), `SELECT status,COALESCE(execution_key,''),COALESCE(cancel_requested,0) FROM agent_tasks WHERE id=? AND device_id=?`, id, deviceID).Scan(&status, &key, &cancelled)
	if errors.Is(err, sql.ErrNoRows) {
		http.Error(w, "task not found", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "task state unavailable", http.StatusServiceUnavailable)
		return
	}
	writeAgentJSON(w, signingKey, map[string]any{"ok": false, "status": status, "cancel_requested": cancelled || status == "cancelled", "conflict": key != "" && key != executionKey})
}

// CancelTask only cancels queued work or requests cooperative cancellation from
// a protocol-2 agent. Legacy sent tasks cannot be claimed to have stopped.
func (a *App) CancelTask(w http.ResponseWriter, r *http.Request) {
	u := auth.CurrentUser(a.DB, r)
	if !u.CanWrite() {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		http.Error(w, "invalid task", http.StatusBadRequest)
		return
	}
	res, err := a.DB.ExecContext(r.Context(), `UPDATE agent_tasks SET
	status=CASE WHEN status='pending' THEN 'cancelled' ELSE status END,
	result=CASE WHEN status='pending' THEN 'Отменено администратором до выдачи агенту.' ELSE result END,
	exit_code=CASE WHEN status='pending' THEN 125 ELSE exit_code END,
	done_at=CASE WHEN status='pending' THEN datetime('now') ELSE done_at END,
	cancel_requested=CASE WHEN status='pending' THEN 0 ELSE 1 END
	WHERE id=? AND (status='pending' OR (task_protocol=2 AND status IN ('sent','running')))`, id)
	if err != nil {
		http.Error(w, "cancellation not saved", http.StatusServiceUnavailable)
		return
	}
	n, err := res.RowsAffected()
	if err != nil {
		http.Error(w, "cancellation not saved", http.StatusServiceUnavailable)
		return
	}
	if n == 0 {
		http.Error(w, "task already finished or agent does not support cancellation", http.StatusConflict)
		return
	}
	auth.LogAction(a.DB, u.ID, "task_cancel", strconv.FormatInt(id, 10), "Запрошена отмена удалённой задачи")
	writeJSON(w, map[string]any{"ok": true})
}
