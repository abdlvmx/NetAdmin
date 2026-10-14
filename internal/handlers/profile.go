package handlers

import (
	"net/http"

	"netadmin/internal/auth"
)

type profileData struct {
	User              *auth.User
	Active            string
	Message           string
	Error             string
	MFA               auth.MFAStatus
	MFATransport      bool
	MFAUnavailable    bool
	RecoveryCodes     []string
	CSRF              string
	GroupNames        []string
	AccessUnavailable bool
}

func (a *App) profileAccess(r *http.Request, data *profileData) {
	if !data.User.DeviceRestricted {
		return
	}
	rows, err := a.DB.QueryContext(r.Context(), "SELECT g.name FROM device_groups g JOIN user_device_groups ug ON ug.group_id=g.id WHERE ug.user_id=? ORDER BY g.name,g.id", data.User.ID)
	if err != nil {
		data.AccessUnavailable = true
		return
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if err = rows.Scan(&name); err != nil {
			data.AccessUnavailable = true
			return
		}
		data.GroupNames = append(data.GroupNames, name)
	}
	data.AccessUnavailable = rows.Err() != nil
}

// ProfilePage — GET /profile : личная страница (смена пароля доступна всем).
func (a *App) ProfilePage(w http.ResponseWriter, r *http.Request) {
	user := auth.CurrentUser(a.DB, r)
	if user == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	data := profileData{
		User:    user,
		Active:  "profile",
		Message: r.URL.Query().Get("message"),
		Error:   r.URL.Query().Get("error"),
	}
	a.renderProfile(w, r, data)
}
