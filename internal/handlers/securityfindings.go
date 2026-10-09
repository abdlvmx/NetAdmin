//go:build securityevents

package handlers

import (
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"netadmin/internal/auth"
	"netadmin/internal/securityevents"
	"netadmin/internal/web"
)

type findingRow struct {
	securityevents.Finding
	Hostname, StateLabel, SeverityLabel, AssigneeName string
}
type exceptionRow struct {
	securityevents.Exception
	Hostname, RuleTitle, ScopeLabel string
}
type findingAdmin struct {
	ID   int64
	Name string
}
type findingPageData struct {
	User     *auth.User
	Active   string
	Demo     bool
	Finding  findingRow
	Events   []eventsDisplayRow
	Comments []securityevents.FindingComment
	Admins   []findingAdmin
}

func (a *App) findingAdmins(r *http.Request) ([]findingAdmin, error) {
	rows, err := a.DB.QueryContext(r.Context(), `SELECT id,username FROM users WHERE role='admin' AND is_active=1 ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []findingAdmin
	for rows.Next() {
		var u findingAdmin
		if err = rows.Scan(&u.ID, &u.Name); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

func findingView(f securityevents.Finding, hostname, owner string) findingRow {
	if hostname == "" {
		hostname = fmt.Sprintf("Устройство #%d", f.DeviceID)
	}
	if owner == "" {
		if f.AssigneeID > 0 {
			owner = "Учётная запись недоступна"
		} else {
			owner = "Не назначен"
		}
	}
	return findingRow{Finding: f, Hostname: hostname, StateLabel: securityevents.FindingStateLabel(f.Status), SeverityLabel: securityevents.SeverityLabel(f.Severity), AssigneeName: owner}
}

func (a *App) loadFindingsPanel(r *http.Request, data *eventsPageData, names map[int64]string) error {
	data.FindingStatus = r.URL.Query().Get("finding_status")
	if data.FindingStatus == "" {
		data.FindingStatus = "active"
	}
	data.RuleFilter = r.URL.Query().Get("rule")
	rules, err := a.Events.Rules(r.Context())
	if err != nil {
		return err
	}
	data.Rules = rules
	admins, err := a.findingAdmins(r)
	if err != nil {
		return err
	}
	owners := map[int64]string{}
	for _, u := range admins {
		owners[u.ID] = u.Name
	}
	findings, err := a.Events.Findings(r.Context(), securityevents.FindingFilter{DeviceID: data.DeviceID, RuleID: data.RuleFilter, Status: data.FindingStatus, Limit: 100})
	if err != nil {
		return err
	}
	for _, f := range findings {
		data.Findings = append(data.Findings, findingView(f, names[f.DeviceID], owners[f.AssigneeID]))
	}
	return nil
}

func (a *App) loadRulesPanel(r *http.Request, data *eventsPageData, names map[int64]string) error {
	rules, err := a.Events.Rules(r.Context())
	if err != nil {
		return err
	}
	data.Rules = rules
	exceptions, err := a.Events.Exceptions(r.Context())
	if err != nil {
		return err
	}
	for _, e := range exceptions {
		row := exceptionRow{Exception: e, Hostname: names[e.DeviceID]}
		if e.DeviceID == 0 {
			row.Hostname = "Все ПК"
		} else if row.Hostname == "" {
			row.Hostname = fmt.Sprintf("Устройство #%d", e.DeviceID)
		}
		for _, rule := range rules {
			if rule.ID == e.RuleID {
				row.RuleTitle = rule.Title
			}
		}
		row.ScopeLabel = map[string]string{"account": "Учётная запись", "ip": "IP источника", "service": "Имя службы", "channel": "Канал"}[e.Scope]
		data.Exceptions = append(data.Exceptions, row)
	}
	return nil
}

func (a *App) findingAccess(w http.ResponseWriter, r *http.Request, write bool) (*auth.User, bool) {
	u := auth.CurrentUser(a.DB, r)
	if !u.IsAdmin() {
		http.Error(w, "Доступ разрешён только администратору", http.StatusForbidden)
		return nil, false
	}
	if a.Events == nil {
		http.Error(w, "Events недоступен", http.StatusServiceUnavailable)
		return nil, false
	}
	if write && a.Demo {
		http.Error(w, "Изменения Events недоступны в демо", http.StatusForbidden)
		return nil, false
	}
	return u, true
}
func findingError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, sql.ErrNoRows):
		http.Error(w, "Карточка или исключение не найдены", http.StatusNotFound)
	case errors.Is(err, securityevents.ErrFindingConflict):
		http.Error(w, "Карточка или правило изменились. Обновите страницу и повторите действие.", http.StatusConflict)
	case errors.Is(err, securityevents.ErrInvalid):
		http.Error(w, "Проверьте значения формы и допустимые пределы", http.StatusBadRequest)
	default:
		http.Error(w, "Изменение не сохранено; попробуйте позже", http.StatusServiceUnavailable)
	}
}
func findingID(r *http.Request) (int64, error) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		return 0, securityevents.ErrInvalid
	}
	return id, nil
}

// Check current registration before returning data from a retained device ID.
func (a *App) currentFinding(r *http.Request, id int64) (securityevents.FindingDetails, string, error) {
	f, err := a.Events.Finding(r.Context(), id)
	if err != nil {
		return f, "", err
	}
	d, err := a.eventsDevice(r, f.DeviceID)
	if errors.Is(err, sql.ErrNoRows) {
		return f, fmt.Sprintf("Удалённое устройство #%d", f.DeviceID), nil
	}
	if err != nil {
		return f, "", err
	}
	if _, err = a.Events.Policy(r.Context(), d.ID, d.Token); err != nil {
		return f, "", err
	}
	f, err = a.Events.Finding(r.Context(), id)
	return f, d.Hostname, err
}

func (a *App) SecurityFindingPage(w http.ResponseWriter, r *http.Request) {
	u, ok := a.findingAccess(w, r, false)
	if !ok {
		return
	}
	id, err := findingID(r)
	if err != nil {
		findingError(w, err)
		return
	}
	f, hostname, err := a.currentFinding(r, id)
	if err != nil {
		findingError(w, err)
		return
	}
	admins, err := a.findingAdmins(r)
	if err != nil {
		findingError(w, err)
		return
	}
	owner := ""
	for _, admin := range admins {
		if admin.ID == f.AssigneeID {
			owner = admin.Name
		}
	}
	data := findingPageData{User: u, Active: "securityevents", Demo: a.Demo, Finding: findingView(f.Finding, hostname, owner), Comments: f.Comments, Admins: admins}
	for _, e := range f.Evidence {
		data.Events = append(data.Events, eventsDisplayRow{StoredEvent: securityevents.StoredEvent{DeviceID: f.DeviceID, Event: e}, EventDescription: securityevents.DescribeEvent(e), Hostname: hostname})
	}
	w.Header().Set("Cache-Control", "no-store")
	web.RenderPage(w, "securityfinding", data)
}

func (a *App) UpdateSecurityFinding(w http.ResponseWriter, r *http.Request) {
	u, ok := a.findingAccess(w, r, true)
	if !ok {
		return
	}
	id, err := findingID(r)
	if err != nil {
		findingError(w, err)
		return
	}
	if _, _, err = a.currentFinding(r, id); err != nil {
		findingError(w, err)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
	if err = r.ParseForm(); err != nil {
		findingError(w, securityevents.ErrInvalid)
		return
	}
	revision, err := strconv.ParseInt(r.FormValue("revision"), 10, 64)
	if err != nil {
		findingError(w, securityevents.ErrInvalid)
		return
	}
	owner, err := strconv.ParseInt(r.FormValue("assignee"), 10, 64)
	if err != nil || owner < 0 {
		findingError(w, securityevents.ErrInvalid)
		return
	}
	if owner > 0 {
		var n int
		if err = a.DB.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM users WHERE id=? AND role='admin' AND is_active=1`, owner).Scan(&n); err != nil {
			findingError(w, err)
			return
		}
		if n != 1 {
			findingError(w, securityevents.ErrInvalid)
			return
		}
	}
	state := r.FormValue("status")
	if err = a.Events.UpdateFinding(r.Context(), id, revision, state, owner, r.FormValue("comment"), u.Username); err != nil {
		findingError(w, err)
		return
	}
	auth.LogAction(a.DB, u.ID, "events_finding", fmt.Sprintf("finding#%d", id), fmt.Sprintf("status=%s assignee_id=%d comment_added=%t", state, owner, r.FormValue("comment") != ""))
	http.Redirect(w, r, fmt.Sprintf("/events/findings/%d", id), http.StatusSeeOther)
}

func (a *App) UpdateSecurityRule(w http.ResponseWriter, r *http.Request) {
	u, ok := a.findingAccess(w, r, true)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
	if r.ParseForm() != nil {
		findingError(w, securityevents.ErrInvalid)
		return
	}
	revision, err := strconv.ParseInt(r.FormValue("revision"), 10, 64)
	if err != nil {
		findingError(w, securityevents.ErrInvalid)
		return
	}
	threshold, err := strconv.Atoi(r.FormValue("threshold"))
	if err != nil {
		findingError(w, securityevents.ErrInvalid)
		return
	}
	window, err := strconv.Atoi(r.FormValue("window"))
	if err != nil {
		findingError(w, securityevents.ErrInvalid)
		return
	}
	rule := securityevents.Rule{ID: r.PathValue("id"), Enabled: r.FormValue("enabled") == "1", Threshold: threshold, WindowMinutes: window, Revision: revision}
	if err = a.Events.SetRule(r.Context(), rule); err != nil {
		findingError(w, err)
		return
	}
	auth.LogAction(a.DB, u.ID, "events_rule", rule.ID, fmt.Sprintf("enabled=%t threshold=%d window_minutes=%d", rule.Enabled, threshold, window))
	http.Redirect(w, r, "/events?tab=rules#events-rules", http.StatusSeeOther)
}

func (a *App) AddSecurityException(w http.ResponseWriter, r *http.Request) {
	u, ok := a.findingAccess(w, r, true)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if r.ParseForm() != nil {
		findingError(w, securityevents.ErrInvalid)
		return
	}
	device, err := strconv.ParseInt(r.FormValue("device"), 10, 64)
	if err != nil || device < 0 {
		findingError(w, securityevents.ErrInvalid)
		return
	}
	if device > 0 {
		d, readErr := a.eventsDevice(r, device)
		if readErr != nil {
			findingError(w, readErr)
			return
		}
		if !d.isPC() || d.Token == "" {
			findingError(w, securityevents.ErrInvalid)
			return
		}
		if _, err = a.Events.Policy(r.Context(), device, d.Token); err != nil {
			findingError(w, err)
			return
		}
	}
	hours, err := strconv.Atoi(r.FormValue("hours"))
	if err != nil || hours < 1 || hours > 168 {
		findingError(w, securityevents.ErrInvalid)
		return
	}
	e := securityevents.Exception{DeviceID: device, RuleID: r.PathValue("id"), Scope: r.FormValue("scope"), Value: r.FormValue("value"), Reason: r.FormValue("reason"), ExpiresAt: time.Now().UTC().Add(time.Duration(hours) * time.Hour)}
	if err = a.Events.AddException(r.Context(), e); err != nil {
		findingError(w, err)
		return
	}
	auth.LogAction(a.DB, u.ID, "events_exception", e.RuleID, fmt.Sprintf("added device_id=%d scope=%s hours=%d", device, e.Scope, hours))
	http.Redirect(w, r, "/events?tab=rules#events-rules", http.StatusSeeOther)
}

func (a *App) DeleteSecurityException(w http.ResponseWriter, r *http.Request) {
	u, ok := a.findingAccess(w, r, true)
	if !ok {
		return
	}
	id, err := findingID(r)
	if err != nil {
		findingError(w, err)
		return
	}
	if err = a.Events.DeleteException(r.Context(), id); err != nil {
		findingError(w, err)
		return
	}
	auth.LogAction(a.DB, u.ID, "events_exception", fmt.Sprintf("exception#%d", id), "removed")
	http.Redirect(w, r, "/events?tab=rules#events-rules", http.StatusSeeOther)
}
