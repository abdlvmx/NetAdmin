package handlers

import (
	"net/http"

	"netadmin/internal/auth"
	"netadmin/internal/web"
)

type profileData struct {
	User    *auth.User
	Active  string
	Message string
	Error   string
}

// ProfilePage — GET /profile : личная страница (смена пароля доступна всем).
func (a *App) ProfilePage(w http.ResponseWriter, r *http.Request) {
	user := auth.CurrentUser(a.DB, r)
	if user == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	web.RenderPage(w, "profile", profileData{
		User:    user,
		Active:  "profile",
		Message: r.URL.Query().Get("message"),
		Error:   r.URL.Query().Get("error"),
	})
}
