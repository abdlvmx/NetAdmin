package handlers

import (
	"log"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"

	"netadmin/internal/auth"
	"netadmin/internal/backup"
	"netadmin/internal/config"
	"netadmin/internal/notify"
	"netadmin/internal/web"
)

type settingsData struct {
	User              *auth.User
	Active            string
	OrgName           string
	AgentToken        string
	SMTPHost          string
	SMTPPort          int
	SMTPUser          string
	SMTPFrom          string
	SMTPTo            string
	ScanIntervalHours int
	HelpdeskEnabled   bool
	// Резервные копии
	BackupIntervalHours int
	BackupKeep          int
	BackupDir           string
	Backups             []backup.Info
	Message             string
	Error               string
}

// backupDir — каталог копий по текущим настройкам.
func backupDir(cfg config.Config) (string, error) {
	return backup.Dir(config.DataDir(), cfg.BackupDir)
}

// SettingsPage — GET /settings (admin).
func (a *App) SettingsPage(w http.ResponseWriter, r *http.Request) {
	user := auth.CurrentUser(a.DB, r)
	if user == nil || user.Role != "admin" {
		http.Redirect(w, r, "/dashboard", http.StatusFound)
		return
	}
	cfg := config.Load()
	var backups []backup.Info
	if dir, err := backupDir(cfg); err == nil {
		backups = backup.List(dir)
	} else {
		log.Printf("каталог резервных копий: %v", err)
	}
	web.RenderPage(w, "settings", settingsData{
		User:              user,
		Active:            "settings",
		OrgName:           cfg.OrganizationName,
		AgentToken:        cfg.AgentToken,
		SMTPHost:          cfg.SMTPHost,
		SMTPPort:          cfg.SMTPPort,
		SMTPUser:          cfg.SMTPUser,
		SMTPFrom:          cfg.SMTPFrom,
		SMTPTo:            cfg.SMTPTo,
		ScanIntervalHours: cfg.ScanIntervalHours,
		HelpdeskEnabled:   cfg.HelpdeskEnabled,

		BackupIntervalHours: cfg.BackupIntervalHours,
		BackupKeep:          cfg.BackupKeep,
		BackupDir:           cfg.BackupDir,
		Backups:             backups,

		Message: r.URL.Query().Get("message"),
		Error:   r.URL.Query().Get("error"),
	})
}

// UpdateBackup — POST /settings/backup (admin): расписание и хранение копий.
func (a *App) UpdateBackup(w http.ResponseWriter, r *http.Request) {
	user := auth.CurrentUser(a.DB, r)
	if user == nil || !user.IsAdmin() {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	_ = r.ParseForm()
	cfg := config.Load()
	cfg.BackupIntervalHours, _ = strconv.Atoi(strings.TrimSpace(r.FormValue("interval")))
	cfg.BackupKeep, _ = strconv.Atoi(strings.TrimSpace(r.FormValue("keep")))
	cfg.BackupDir = strings.TrimSpace(r.FormValue("dir"))
	if cfg.BackupIntervalHours < 0 {
		cfg.BackupIntervalHours = 0
	}
	if cfg.BackupKeep < 0 {
		cfg.BackupKeep = 0
	}
	if err := config.Save(cfg); err != nil {
		http.Redirect(w, r, "/settings?error=Не+удалось+сохранить+настройки", http.StatusSeeOther)
		return
	}
	auth.LogAction(a.DB, user.ID, "backup_settings", strconv.Itoa(cfg.BackupIntervalHours)+" ч",
		"хранить "+strconv.Itoa(cfg.BackupKeep))
	http.Redirect(w, r, "/settings?message=Настройки+копирования+сохранены", http.StatusSeeOther)
}

// BackupNow — POST /settings/backup/now (admin): снять копию немедленно.
func (a *App) BackupNow(w http.ResponseWriter, r *http.Request) {
	user := auth.CurrentUser(a.DB, r)
	if user == nil || !user.IsAdmin() {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	cfg := config.Load()
	dir, err := backupDir(cfg)
	if err != nil {
		http.Redirect(w, r, "/settings?error=Каталог+копий+недоступен", http.StatusSeeOther)
		return
	}
	path, err := backup.Create(a.DB, dir, cfg.BackupKeep)
	if err != nil {
		log.Printf("резервное копирование вручную: %v", err)
		http.Redirect(w, r, "/settings?error=Не+удалось+снять+копию", http.StatusSeeOther)
		return
	}
	auth.LogAction(a.DB, user.ID, "backup_now", filepath.Base(path), "")
	http.Redirect(w, r, "/settings?message=Копия+создана", http.StatusSeeOther)
}

// UpdateOrganization — POST /settings/organization (admin).
func (a *App) UpdateOrganization(w http.ResponseWriter, r *http.Request) {
	user := auth.CurrentUser(a.DB, r)
	if user == nil || user.Role != "admin" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	cfg := config.Load()
	name := strings.TrimSpace(r.FormValue("organization_name"))
	if name == "" {
		name = config.DefaultOrgName
	}
	cfg.OrganizationName = name
	_ = config.Save(cfg)
	auth.LogAction(a.DB, user.ID, "update_settings", "organization_name", name)
	http.Redirect(w, r, "/settings?message=organization_saved", http.StatusSeeOther)
}

// RotateAgentToken — POST /settings/agent-token/rotate (admin).
func (a *App) RotateAgentToken(w http.ResponseWriter, r *http.Request) {
	user := auth.CurrentUser(a.DB, r)
	if user == nil || user.Role != "admin" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	cfg := config.Load()
	cfg.AgentToken = config.GenerateToken()
	_ = config.Save(cfg)
	auth.LogAction(a.DB, user.ID, "rotate_agent_token", "settings", "")
	http.Redirect(w, r, "/settings?message=agent_token_rotated", http.StatusSeeOther)
}

// UpdateNotifications — POST /settings/notifications (admin).
func (a *App) UpdateNotifications(w http.ResponseWriter, r *http.Request) {
	user := auth.CurrentUser(a.DB, r)
	if user == nil || user.Role != "admin" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	cfg := config.Load()
	cfg.SMTPHost = strings.TrimSpace(r.FormValue("smtp_host"))
	cfg.SMTPPort, _ = strconv.Atoi(strings.TrimSpace(r.FormValue("smtp_port")))
	cfg.SMTPUser = strings.TrimSpace(r.FormValue("smtp_user"))
	if p := r.FormValue("smtp_pass"); p != "" { // пустое поле не затирает сохранённый пароль
		cfg.SMTPPass = p
	}
	cfg.SMTPFrom = strings.TrimSpace(r.FormValue("smtp_from"))
	cfg.SMTPTo = strings.TrimSpace(r.FormValue("smtp_to"))
	_ = config.Save(cfg)
	auth.LogAction(a.DB, user.ID, "update_settings", "notifications", "")
	http.Redirect(w, r, "/settings?message=notifications_saved", http.StatusSeeOther)
}

// TestNotification — POST /settings/notifications/test (admin).
func (a *App) TestNotification(w http.ResponseWriter, r *http.Request) {
	user := auth.CurrentUser(a.DB, r)
	if user == nil || user.Role != "admin" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if err := notify.SendTest(); err != nil {
		http.Redirect(w, r, "/settings?error=test_failed", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/settings?message=test_sent", http.StatusSeeOther)
}

// UpdateScan — POST /settings/scan : интервал автосканирования (admin).
func (a *App) UpdateScan(w http.ResponseWriter, r *http.Request) {
	user := auth.CurrentUser(a.DB, r)
	if user == nil || user.Role != "admin" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	h, _ := strconv.Atoi(strings.TrimSpace(r.FormValue("scan_interval_hours")))
	if h < 0 {
		h = 0
	}
	cfg := config.Load()
	cfg.ScanIntervalHours = h
	_ = config.Save(cfg)
	auth.LogAction(a.DB, user.ID, "update_settings", "scan_interval", strconv.Itoa(h))
	http.Redirect(w, r, "/settings?message=scan_saved", http.StatusSeeOther)
}

// UpdateHelpdesk — POST /settings/helpdesk : вкл/выкл портала заявок сотрудников (admin).
func (a *App) UpdateHelpdesk(w http.ResponseWriter, r *http.Request) {
	user := auth.CurrentUser(a.DB, r)
	if user == nil || user.Role != "admin" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	cfg := config.Load()
	cfg.HelpdeskEnabled = r.FormValue("helpdesk_enabled") != ""
	_ = config.Save(cfg)
	auth.LogAction(a.DB, user.ID, "update_settings", "helpdesk", strconv.FormatBool(cfg.HelpdeskEnabled))
	http.Redirect(w, r, "/settings?message=helpdesk_saved", http.StatusSeeOther)
}

// ChangePassword — POST /settings/password.
func (a *App) ChangePassword(w http.ResponseWriter, r *http.Request) {
	user := auth.CurrentUser(a.DB, r)
	if user == nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	_ = r.ParseForm()
	cur := r.FormValue("current_password")
	nw := r.FormValue("new_password")
	rep := r.FormValue("new_password_repeat")

	var hash string
	if a.DB.QueryRow("SELECT password_hash FROM users WHERE id=?", user.ID).Scan(&hash) != nil ||
		!auth.VerifyPassword(cur, hash) {
		http.Redirect(w, r, "/profile?error=bad_current_password", http.StatusSeeOther)
		return
	}
	if auth.WeakPassword(nw) {
		http.Redirect(w, r, "/profile?error=weak_password", http.StatusSeeOther)
		return
	}
	if nw != rep {
		http.Redirect(w, r, "/profile?error=password_mismatch", http.StatusSeeOther)
		return
	}
	newHash, err := auth.HashPassword(nw)
	if err != nil {
		http.Error(w, "hash error", http.StatusInternalServerError)
		return
	}
	a.DB.Exec("UPDATE users SET password_hash=? WHERE id=?", newHash, user.ID)
	// разлогинить остальные сессии
	curToken := ""
	if c, err := r.Cookie("session"); err == nil {
		curToken = c.Value
	}
	a.DB.Exec("DELETE FROM sessions WHERE user_id=? AND token != ?", user.ID, curToken)
	auth.LogAction(a.DB, user.ID, "change_password", user.Username, "")
	http.Redirect(w, r, "/profile?message=password_changed", http.StatusSeeOther)
}
