package handlers

import (
	"fmt"
	"net/http"
	"strings"

	"netadmin/internal/auth"
	"netadmin/internal/config"
	"netadmin/internal/web"
)

// Root — / : направляет на setup/login/dashboard.
func (a *App) Root(w http.ResponseWriter, r *http.Request) {
	if !auth.HasUsers(a.DB) {
		http.Redirect(w, r, "/setup", http.StatusFound)
		return
	}
	if auth.CurrentUser(a.DB, r) == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	http.Redirect(w, r, "/dashboard", http.StatusFound)
}

// LoginPage — GET /login.
func (a *App) LoginPage(w http.ResponseWriter, r *http.Request) {
	if !auth.HasUsers(a.DB) {
		http.Redirect(w, r, "/setup", http.StatusFound)
		return
	}
	web.Render(w, "login.html", map[string]any{"Error": ""})
}

// Login — POST /login.
func (a *App) Login(w http.ResponseWriter, r *http.Request) {
	if !auth.HasUsers(a.DB) {
		http.Redirect(w, r, "/setup", http.StatusFound)
		return
	}
	ip := clientIP(r)
	_ = r.ParseForm()
	username := r.FormValue("username")
	password := r.FormValue("password")

	// блокировки: по IP и по учётной записи
	if d := loginLimiter.blockedFor(ip); d > 0 {
		web.Render(w, "login.html", map[string]any{
			"Error": fmt.Sprintf("Слишком много попыток входа. Повторите через %d мин.", int(d.Minutes())+1)})
		return
	}
	if d := userLockout.blockedFor(username); d > 0 {
		web.Render(w, "login.html", map[string]any{
			"Error": fmt.Sprintf("Учётная запись временно заблокирована. Повторите через %d мин.", int(d.Minutes())+1)})
		return
	}

	var id int64
	var hash string
	row := a.DB.QueryRow(
		"SELECT id, password_hash FROM users WHERE username=? AND is_active=1", username)
	if err := row.Scan(&id, &hash); err != nil || !auth.VerifyPassword(password, hash) {
		loginLimiter.fail(ip)
		userLockout.fail(username)
		auth.LogAction(a.DB, 0, "login_failed", username, ip)
		web.Render(w, "login.html", map[string]any{"Error": "Неверный логин или пароль"})
		return
	}
	loginLimiter.reset(ip)
	userLockout.reset(username)
	// защита от session fixation: гасим любую прежнюю сессию из cookie и выдаём новую
	if c, e := r.Cookie("session"); e == nil && c.Value != "" {
		auth.DeleteSession(a.DB, c.Value)
	}
	token, err := auth.CreateSession(a.DB, id)
	if err != nil {
		http.Error(w, "session error", http.StatusInternalServerError)
		return
	}
	auth.LogAction(a.DB, id, "login", "session", ip)
	setSessionCookie(w, token)
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

// SetupPage — GET /setup.
func (a *App) SetupPage(w http.ResponseWriter, r *http.Request) {
	if auth.HasUsers(a.DB) {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	web.Render(w, "setup.html", map[string]any{
		"Error":            "",
		"OrganizationName": config.Load().OrganizationName,
	})
}

// Setup — POST /setup: создаёт первого администратора.
func (a *App) Setup(w http.ResponseWriter, r *http.Request) {
	if auth.HasUsers(a.DB) {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	_ = r.ParseForm()
	orgName := strings.TrimSpace(r.FormValue("organization_name"))
	if orgName == "" {
		orgName = config.DefaultOrgName
	}
	username := strings.TrimSpace(r.FormValue("username"))
	fullName := strings.TrimSpace(r.FormValue("full_name"))
	password := r.FormValue("password")

	if len(username) < 3 || auth.WeakPassword(password) {
		web.Render(w, "setup.html", map[string]any{
			"Error":            "Логин — от 3 символов; пароль — от 8 символов, обязательно с буквами и цифрами.",
			"OrganizationName": orgName,
		})
		return
	}

	cfg := config.Load()
	cfg.OrganizationName = orgName
	_ = config.Save(cfg)

	hash, err := auth.HashPassword(password)
	if err != nil {
		http.Error(w, "hash error", http.StatusInternalServerError)
		return
	}
	res, err := a.DB.Exec(
		`INSERT INTO users (username, full_name, email, role, password_hash)
		 VALUES (?, ?, '', 'admin', ?)`, username, fullName, hash)
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	id, _ := res.LastInsertId()
	token, _ := auth.CreateSession(a.DB, id)
	auth.LogAction(a.DB, id, "initial_setup", orgName, "")
	setSessionCookie(w, token)
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

// Logout — GET /logout.
func (a *App) Logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie("session"); err == nil {
		auth.DeleteSession(a.DB, c.Value)
	}
	clearSessionCookie(w)
	http.Redirect(w, r, "/login", http.StatusFound)
}
