package handlers

import (
	"net/http"

	"netadmin/internal/auth"
	"netadmin/internal/tz"
	"netadmin/internal/web"
)

type auditRow struct {
	CreatedAt string
	Username  string
	Action    string
	Target    string
	Detail    string
}

type auditData struct {
	User   *auth.User
	Active string
	Logs   []auditRow
}

// AuditPage — GET /audit (admin).
func (a *App) AuditPage(w http.ResponseWriter, r *http.Request) {
	user := auth.CurrentUser(a.DB, r)
	if user == nil || user.Role != "admin" {
		http.Redirect(w, r, "/dashboard", http.StatusFound)
		return
	}
	rows, _ := a.DB.Query(`
		SELECT COALESCE(a.created_at,''), COALESCE(u.username,'система'),
		       a.action, COALESCE(a.target,''), COALESCE(a.detail,'')
		FROM audit_log a LEFT JOIN users u ON a.user_id=u.id
		ORDER BY a.created_at DESC LIMIT 200`)
	var logs []auditRow
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var l auditRow
			if rows.Scan(&l.CreatedAt, &l.Username, &l.Action, &l.Target, &l.Detail) == nil {
				l.CreatedAt = tz.DateTime(l.CreatedAt)
				logs = append(logs, l)
			}
		}
	}
	web.RenderPage(w, "audit", auditData{User: user, Active: "audit", Logs: logs})
}
