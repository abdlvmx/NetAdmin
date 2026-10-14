//go:build securityevents

package handlers

import (
	"errors"
	"net/http"
)

func (a *App) eventsScopeIDs(r *http.Request) ([]int64, error) {
	if a.scope == nil {
		return nil, nil
	}
	rows, err := a.DB.QueryContext(r.Context(), "SELECT id FROM devices WHERE "+a.deviceScopeSQL("devices.id"))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	devices := []int64{}
	for rows.Next() {
		var id int64
		if err = rows.Scan(&id); err != nil {
			return nil, err
		}
		devices = append(devices, id)
		if len(devices) > 20000 {
			return nil, errors.New("too many devices in Events access scope")
		}
	}
	return devices, rows.Err()
}
func (a *App) findingAssigneeAllowed(r *http.Request, actor, device int64) bool {
	var count int
	err := a.DB.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM users u WHERE u.id=? AND u.is_active=1 AND u.role IN ('admin','analyst') AND
        (u.role='admin' OR NOT EXISTS(SELECT 1 FROM user_device_access ua WHERE ua.user_id=u.id AND ua.mode='groups') OR
        EXISTS(SELECT 1 FROM device_group_members gm JOIN user_device_groups ug ON ug.group_id=gm.group_id WHERE ug.user_id=u.id AND gm.device_id=?))`, actor, device).Scan(&count)
	return err == nil && count == 1
}
