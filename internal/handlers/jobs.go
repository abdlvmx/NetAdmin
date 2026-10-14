package handlers

import (
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"netadmin/internal/auth"
	"netadmin/internal/tz"
	"netadmin/internal/web"
	"strconv"
	"strings"
)

type jobSummary struct {
	ID, ParentID                                                                                                               int64
	Kind, Label, Created, State, Badge                                                                                         string
	Total, Done, Failed, Cancelled, Pending, Sent, Running, CancelRequested, Cancellable, Retryable, Deleted, Waiting, Percent int
	CanCancel, CanRetry                                                                                                        bool
}
type jobTask struct {
	ID, DeviceID, RetryJobID                                                          int64
	Hostname, IP, DeviceStatus, Status, State, Badge, Preview, Created, Started, Done string
	ExitCode, Protocol                                                                int
	CancelRequested, CanRetry                                                         bool
}
type jobsData struct {
	User                                       *auth.User
	Active, Query, Status, Kind, CSRF, Message string
	Jobs                                       []jobSummary
	NextBefore                                 int64
	Job                                        jobSummary
	Tasks                                      []jobTask
	Result                                     string
	Task                                       jobTask
}

func taskState(status string, cancel bool) (string, string) {
	if cancel && (status == "sent" || status == "running") {
		return "Отмена запрошена", "badge-amber"
	}
	switch status {
	case "pending":
		return "Ожидает выдачи", "badge-gray"
	case "sent":
		return "Выдано агенту", "badge-accent"
	case "running":
		return "Выполняется", "badge-accent"
	case "done":
		return "Выполнено", "badge-green"
	case "failed":
		return "Ошибка", "badge-red"
	case "cancelled":
		return "Отменено", "badge-gray"
	}
	return "Неизвестное состояние", "badge-gray"
}
func (j *jobSummary) describe(u *auth.User) {
	complete := j.Done + j.Failed + j.Cancelled + j.Deleted
	if j.Total > 0 {
		j.Percent = complete * 100 / j.Total
	}
	j.CanCancel = u.CanWrite() && j.Cancellable > 0
	j.CanRetry = jobCanRepeat(u, j.Kind) && j.Retryable > 0
	switch {
	case j.Running > 0 || j.Sent > 0:
		j.State, j.Badge = "В работе", "badge-accent"
	case j.Pending > 0:
		j.State, j.Badge = "Ожидает выполнения", "badge-amber"
	case j.Failed > 0:
		j.State, j.Badge = "Завершено с ошибками", "badge-red"
	case j.Total > 0 && j.Cancelled == j.Total:
		j.State, j.Badge = "Отменено", "badge-gray"
	case j.Cancelled > 0 || j.Deleted > 0:
		j.State, j.Badge = "Завершено частично", "badge-gray"
	case j.Total > 0 && j.Done == j.Total:
		j.State, j.Badge = "Выполнено", "badge-green"
	case j.Total > 0:
		j.State, j.Badge = "Нет подтверждённого результата", "badge-gray"
	default:
		j.State, j.Badge = "Нет устройств", "badge-gray"
	}
}
func jobsAccount(a *App, w http.ResponseWriter, r *http.Request, write bool) *auth.User {
	u := auth.CurrentUser(a.DB, r)
	if u == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return nil
	}
	if write && !u.CanWrite() {
		http.Error(w, "forbidden", 403)
		return nil
	}
	w.Header().Set("Cache-Control", "no-store")
	return u
}

// Every aggregate sees the same filtered task set. Hidden devices never affect
// a restricted user's totals, search, pagination or controls.
func (a *App) jobsQuery(where, having string) string {
	visible := a.deviceScopeSQL("t.device_id")
	if a.scope != nil {
		visible += " AND EXISTS(SELECT 1 FROM devices WHERE devices.id=t.device_id)"
	}
	return `SELECT j.id,COALESCE(j.parent_id,0),j.kind,j.label,COALESCE(j.created_at,''),j.target_count,
	COUNT(t.id),COALESCE(SUM(t.status='done'),0),COALESCE(SUM(t.status='failed'),0),COALESCE(SUM(t.status='cancelled'),0),
	COALESCE(SUM(t.status='pending'),0),COALESCE(SUM(t.status='sent'),0),COALESCE(SUM(t.status='running'),0),
	COALESCE(SUM(t.cancel_requested=1 AND t.status IN ('sent','running')),0),
	COALESCE(SUM(t.status='pending' OR (t.task_protocol=2 AND t.status IN ('sent','running') AND t.cancel_requested=0)),0),
	COALESCE(SUM(t.status='failed' AND COALESCE(d.agent_token,'')<>'' AND NOT EXISTS(SELECT 1 FROM agent_tasks retried WHERE retried.retry_of=t.id)),0),
	COALESCE(SUM(t.status='pending' AND COALESCE(d.status,'offline')<>'online'),0)
	FROM agent_jobs j LEFT JOIN agent_tasks t ON t.job_id=j.id AND (` + visible + `)
	LEFT JOIN devices d ON d.id=t.device_id WHERE ` + where + ` GROUP BY j.id HAVING ` + having
}

type rowScanner interface{ Scan(...any) error }

func (a *App) scanJob(row rowScanner, u *auth.User) (jobSummary, error) {
	var j jobSummary
	var stored, total int
	err := row.Scan(&j.ID, &j.ParentID, &j.Kind, &j.Label, &j.Created, &stored, &total, &j.Done, &j.Failed, &j.Cancelled, &j.Pending, &j.Sent, &j.Running, &j.CancelRequested, &j.Cancellable, &j.Retryable, &j.Waiting)
	if err != nil {
		return j, err
	}
	j.Total = total
	if a.scope == nil && stored > total {
		j.Deleted = stored - total
		j.Total = stored
	}
	j.Created = tz.DateTime(j.Created)
	j.describe(u)
	return j, nil
}
func (a *App) jobByID(r *http.Request, u *auth.User, id int64) (jobSummary, error) {
	having := "1=1"
	if a.scope != nil {
		having = "COUNT(t.id)>0"
	}
	return a.scanJob(a.DB.QueryRowContext(r.Context(), a.jobsQuery("j.id=?", having), id), u)
}
func (a *App) JobsPage(w http.ResponseWriter, r *http.Request) {
	u := jobsAccount(a, w, r, false)
	if u == nil {
		return
	}
	q := r.URL.Query()
	data := jobsData{User: u, Active: "jobs", Query: strings.TrimSpace(q.Get("q")), Status: q.Get("status"), Kind: q.Get("kind")}
	if len(data.Query) > 200 {
		http.Error(w, "Слишком длинный поиск", 400)
		return
	}
	where, having := "1=1", "1=1"
	if a.scope != nil {
		having = "COUNT(t.id)>0"
	}
	args := []any{}
	if before := q.Get("before"); before != "" {
		id, err := strconv.ParseInt(before, 10, 64)
		if err != nil || id <= 0 {
			http.Error(w, "Некорректная страница", 400)
			return
		}
		where += " AND j.id<?"
		args = append(args, id)
	}
	if data.Query != "" {
		where += ` AND (j.label LIKE ? OR EXISTS(SELECT 1 FROM agent_tasks st JOIN devices sd ON sd.id=st.device_id WHERE st.job_id=j.id AND (` + a.deviceScopeSQL("st.device_id") + `) AND (sd.hostname LIKE ? OR sd.ip_address LIKE ?)))`
		pattern := "%" + data.Query + "%"
		args = append(args, pattern, pattern, pattern)
	}
	if data.Kind != "" {
		switch data.Kind {
		case "command", "check", "reboot", "shutdown", "logoff", "install", "selfupdate":
		default:
			http.Error(w, "Неизвестный тип задания", 400)
			return
		}
		where += " AND j.kind=?"
		args = append(args, data.Kind)
	}
	switch data.Status {
	case "":
	case "active":
		having += " AND COALESCE(SUM(t.status IN ('pending','sent','running')),0)>0"
	case "failed":
		having += " AND COALESCE(SUM(t.status='failed'),0)>0"
	case "finished":
		having += " AND COALESCE(SUM(t.status IN ('pending','sent','running')),0)=0"
	default:
		http.Error(w, "Неизвестное состояние", 400)
		return
	}
	rows, err := a.DB.QueryContext(r.Context(), a.jobsQuery(where, having)+" ORDER BY j.id DESC LIMIT 51", args...)
	if err != nil {
		http.Error(w, "Список заданий недоступен", 503)
		return
	}
	defer rows.Close()
	for rows.Next() {
		j, err := a.scanJob(rows, u)
		if err != nil {
			http.Error(w, "Список заданий недоступен", 503)
			return
		}
		data.Jobs = append(data.Jobs, j)
	}
	if rows.Err() != nil {
		http.Error(w, "Список заданий недоступен", 503)
		return
	}
	if len(data.Jobs) > 50 {
		data.Jobs = data.Jobs[:50]
		data.NextBefore = data.Jobs[49].ID
	}
	web.RenderPage(w, "jobs", data)
}
func (a *App) jobTasks(r *http.Request, u *auth.User, id int64) ([]jobTask, error) {
	rows, err := a.DB.QueryContext(r.Context(), `SELECT t.id,t.device_id,COALESCE(d.hostname,''),COALESCE(d.ip_address,''),COALESCE(d.status,'offline'),COALESCE(t.status,''),t.exit_code,t.task_protocol,t.cancel_requested,
	substr(COALESCE(t.result,''),1,200),COALESCE(t.created_at,''),COALESCE(t.started_at,''),COALESCE(t.done_at,''),
	COALESCE((SELECT job_id FROM agent_tasks retry WHERE retry.retry_of=t.id),0),COALESCE(d.agent_token,'')<>''
	FROM agent_tasks t LEFT JOIN devices d ON d.id=t.device_id WHERE t.job_id=? AND (`+a.deviceScopeSQL("t.device_id")+`) ORDER BY t.id LIMIT 5001`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []jobTask{}
	for rows.Next() {
		var t jobTask
		var hasAgent bool
		if err = rows.Scan(&t.ID, &t.DeviceID, &t.Hostname, &t.IP, &t.DeviceStatus, &t.Status, &t.ExitCode, &t.Protocol, &t.CancelRequested, &t.Preview, &t.Created, &t.Started, &t.Done, &t.RetryJobID, &hasAgent); err != nil {
			return nil, err
		}
		if t.Hostname == "" {
			t.Hostname = fmt.Sprintf("ПК #%d отсутствует", t.DeviceID)
		}
		t.State, t.Badge = taskState(t.Status, t.CancelRequested)
		if t.Status == "pending" && t.DeviceStatus != "online" {
			t.State = "Ожидает подключения ПК"
		}
		t.Created, t.Started, t.Done = tz.DateTime(t.Created), tz.DateTime(t.Started), tz.DateTime(t.Done)
		t.CanRetry = u.CanWrite() && t.Status == "failed" && t.RetryJobID == 0 && hasAgent
		items = append(items, t)
	}
	if len(items) > 5000 {
		return nil, errors.New("job exceeds device limit")
	}
	return items, rows.Err()
}
func (a *App) loadJob(w http.ResponseWriter, r *http.Request, u *auth.User) (jobSummary, []jobTask, bool) {
	id, err := pathID(r)
	if err != nil {
		http.NotFound(w, r)
		return jobSummary{}, nil, false
	}
	j, err := a.jobByID(r, u, id)
	if errors.Is(err, sql.ErrNoRows) {
		http.NotFound(w, r)
		return j, nil, false
	}
	if err != nil {
		http.Error(w, "Задание недоступно", 503)
		return j, nil, false
	}
	tasks, err := a.jobTasks(r, u, id)
	if err != nil {
		http.Error(w, "Результаты недоступны", 503)
		return j, nil, false
	}
	for i := range tasks {
		tasks[i].CanRetry = tasks[i].CanRetry && jobCanRepeat(u, j.Kind)
	}
	return j, tasks, true
}
func (a *App) JobPage(w http.ResponseWriter, r *http.Request) {
	u := jobsAccount(a, w, r, false)
	if u == nil {
		return
	}
	j, tasks, ok := a.loadJob(w, r, u)
	if !ok {
		return
	}
	web.RenderPage(w, "job_detail", jobsData{User: u, Active: "jobs", Job: j, Tasks: tasks, CSRF: csrfToken(r), Message: r.URL.Query().Get("result")})
}
func (a *App) JobStatus(w http.ResponseWriter, r *http.Request) {
	u := jobsAccount(a, w, r, false)
	if u == nil {
		return
	}
	j, tasks, ok := a.loadJob(w, r, u)
	if !ok {
		return
	}
	writeJSON(w, map[string]any{"job": j, "tasks": tasks})
}
func (a *App) JobTaskPage(w http.ResponseWriter, r *http.Request) {
	u := jobsAccount(a, w, r, false)
	if u == nil {
		return
	}
	j, tasks, ok := a.loadJob(w, r, u)
	if !ok {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("task"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	var task *jobTask
	for i := range tasks {
		if tasks[i].ID == id {
			task = &tasks[i]
			break
		}
	}
	if task == nil {
		http.NotFound(w, r)
		return
	}
	var result string
	if err = a.DB.QueryRowContext(r.Context(), "SELECT COALESCE(result,'') FROM agent_tasks t WHERE t.id=? AND t.job_id=? AND "+a.deviceScopeSQL("t.device_id"), id, j.ID).Scan(&result); err != nil {
		http.NotFound(w, r)
		return
	}
	web.RenderPage(w, "job_result", jobsData{User: u, Active: "jobs", Job: j, Task: *task, Result: result})
}
