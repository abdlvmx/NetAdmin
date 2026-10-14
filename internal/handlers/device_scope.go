package handlers

import (
	"net/http"
	"netadmin/internal/auth"
	"strconv"
	"strings"
)

// Only trusted SQL column expressions and an authenticated numeric ID are used.
func (a *App) deviceScopeSQL(column string) string {
	if a.scope == nil {
		return "1=1"
	}
	actor := strconv.FormatInt(a.scope.ID, 10)
	if !strings.Contains(column, ".") {
		return "0=1"
	}
	return `(EXISTS(SELECT 1 FROM users scope_user WHERE scope_user.id=` + actor + ` AND scope_user.is_active=1) AND
        (EXISTS(SELECT 1 FROM user_device_access ua WHERE ua.user_id=` + actor + ` AND ua.mode='all') OR
		EXISTS(SELECT 1 FROM user_device_access ua JOIN user_device_groups ug ON ug.user_id=ua.user_id JOIN device_group_members gm ON gm.group_id=ug.group_id WHERE ua.user_id=` + actor + ` AND ua.mode='groups' AND gm.device_id=` + column + `)))`
}

func (a *App) scopedDeviceAllowed(id int64) bool {
	if id <= 0 {
		return false
	}
	var count int
	err := a.DB.QueryRow("SELECT COUNT(*) FROM devices WHERE id=? AND "+a.deviceScopeSQL("devices.id"), id).Scan(&count)
	return err == nil && count == 1
}

// Bind one receiver copy per scoped request, avoiding mutable shared app state
// or temporary SQL views that could leak between pooled database connections.
func (a *App) deviceScoped(handler func(*App, http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/agent-") || strings.HasPrefix(r.URL.Path, "/static/") {
			handler(a, w, r)
			return
		}
		user := auth.CurrentUser(a.DB, r)
		if user == nil || !user.DeviceRestricted {
			handler(a, w, r)
			return
		}
		scoped := *a
		scoped.scope = user
		if !scoped.allowScopedRoute(w, r) {
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		handler(&scoped, w, r)
	}
}

func (a *App) allowScopedRoute(w http.ResponseWriter, r *http.Request) bool {
	pattern := r.Pattern
	// Personal account operations and separately authorized public entry points.
	switch pattern {
	case "GET /{$}", "GET /login", "POST /login", "GET /login/mfa", "POST /login/mfa", "GET /setup", "POST /setup", "POST /logout",
		"GET /profile", "POST /profile/mfa/{operation}", "POST /settings/password",
		"GET /healthz", "GET /favicon.ico", "GET /enroll.ps1", "GET /agent.exe", "GET /help", "POST /help/submit", "GET /help/track", "POST /help/track/reply":
		return true
	case "GET /dashboard", "GET /devices", "GET /devices/export", "GET /commands", "POST /commands/run", "POST /devices/bulk",
		"GET /api/devices/status", "GET /api/metrics/fleet", "GET /api/search", "GET /disk-health", "GET /capacity", "GET /events":
		return true
	case "GET /jobs", "GET /jobs/{id}", "GET /jobs/{id}/tasks/{task}", "GET /api/jobs/{id}", "POST /jobs/{id}/cancel", "POST /jobs/{id}/retry":
		return true // Job readers and mutations filter tasks using the live scope.
	case "POST /api/ping":
		// Ping checks the resolved inventory address inside its handler.
		return true
	case "POST /api/tasks/{id}/cancel":
		taskID, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
		var device int64
		if a.DB.QueryRow("SELECT device_id FROM agent_tasks WHERE id=?", taskID).Scan(&device) == nil && a.scopedDeviceAllowed(device) {
			return true
		}
		http.NotFound(w, r)
		return false
	case "GET /events/findings/{id}", "POST /events/findings/{id}":
		return true // Checked against the finding's device before reading evidence.
	}
	if strings.HasPrefix(pattern, "GET /devices/{id}") || strings.HasPrefix(pattern, "POST /devices/{id}/") || strings.HasPrefix(pattern, "GET /api/devices/{id}/") {
		id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if a.scopedDeviceAllowed(id) {
			return true
		}
		http.NotFound(w, r)
		return false
	}
	// Organization-wide modules have independent objects (tickets, SNMP,
	// discovery, etc.). They are not silently exposed under a device-only scope.
	http.Error(w, "Этот раздел требует полного доступа к парку устройств.", http.StatusForbidden)
	return false
}

func (a *App) checkScopedTargets(w http.ResponseWriter, targets []int64) bool {
	if a.scope == nil {
		return true
	}
	for _, id := range targets {
		if !a.scopedDeviceAllowed(id) {
			http.Error(w, "Выборка содержит недоступные устройства. Ни одно действие не запущено.", http.StatusForbidden)
			return false
		}
	}
	return true
}
