package handlers

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"netadmin/internal/auth"
	"netadmin/internal/web"
	"strconv"
	"strings"
)

func (a *App) scopedEmployeeAllowed(value string) bool {
	if a.scope == nil || strings.TrimSpace(value) == "" {
		return true
	}
	id, err := strconv.ParseInt(value, 10, 64)
	if err != nil || id <= 0 {
		return false
	}
	var count int
	err = a.DB.QueryRow("SELECT COUNT(*) FROM employees e WHERE e.id=? AND "+a.employeeScopeSQL(), id).Scan(&count)
	return err == nil && count == 1
}

func (a *App) employeeScopeSQL() string {
	if a.scope == nil {
		return "1=1"
	}
	return "EXISTS(SELECT 1 FROM devices WHERE devices.employee_id=e.id AND " + a.deviceScopeSQL("devices.id") + ")"
}
func (a *App) ScopedDashboard(w http.ResponseWriter, r *http.Request, user *auth.User) {
	devices := a.listDevices()
	data := struct {
		User                  *auth.User
		Active                string
		Devices               []deviceRow
		Total, Online, Alerts int
	}{User: user, Active: "dashboard", Devices: devices, Total: len(devices)}
	for _, device := range devices {
		if device.Status == "online" {
			data.Online++
		}
		if device.Alert {
			data.Alerts++
		}
	}
	web.RenderPage(w, "scoped_dashboard", data)
}

func (a *App) scopedBulkExec(ctx context.Context, query string, args []any, ids []int64) (sql.Result, error) {
	if a.scope == nil {
		return a.DB.ExecContext(ctx, query, args...)
	}
	tx, err := a.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err = a.validateScopedTx(ctx, tx, ids); err != nil {
		return nil, err
	}
	result, err := tx.ExecContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return result, nil
}
func (a *App) validateScopedTx(ctx context.Context, tx *sql.Tx, ids []int64) error {
	for _, id := range ids {
		var count int
		if err := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM devices WHERE id=? AND "+a.deviceScopeSQL("devices.id"), id).Scan(&count); err != nil {
			return err
		}
		if count != 1 {
			return errors.New("device access revoked")
		}
	}
	return nil
}
