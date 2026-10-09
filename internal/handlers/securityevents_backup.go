//go:build securityevents

package handlers

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"path/filepath"
	"time"

	"netadmin/internal/auth"
	"netadmin/internal/config"
	"netadmin/internal/securityevents"
)

type eventsBackupPanel struct {
	Copies             []securityevents.BackupInfo
	TotalCopies        int
	Scheduled, Pending bool
	Interval, Keep     int
	Problem            string
}

func eventsBackupDirectory(dataDir string, cfg config.Config) string {
	dir := cfg.BackupDir
	if dir == "" {
		dir = filepath.Join(dataDir, "backups")
	}
	return filepath.Join(dir, "events")
}

func (a *App) eventsBackupPanel() eventsBackupPanel {
	cfg := config.Load()
	p := eventsBackupPanel{Scheduled: cfg.BackupIntervalHours > 0, Interval: cfg.BackupIntervalHours, Keep: cfg.BackupKeep, Pending: securityevents.PendingRestore(filepath.Join(config.DataDir(), "security-events.db"))}
	list, err := securityevents.ListBackups(eventsBackupDirectory(config.DataDir(), cfg))
	if err != nil {
		p.Problem = "Каталог копий Events недоступен. Проверьте путь и права службы."
		return p
	}
	p.TotalCopies = len(list)
	p.Copies = list[:min(len(list), 100)]
	if p.Scheduled && (len(list) == 0 || time.Since(list[0].Created) > time.Duration(p.Interval)*time.Hour+20*time.Minute) {
		p.Problem = "Нет свежей копии Events. Проверьте журнал сервера и свободное место; можно создать копию вручную."
	}
	return p
}

// Every operation is admin-only, disabled in demo and protected by route CSRF.
// Input selects a validated basename from the configured Events backup directory.
func (a *App) EventsBackupAction(w http.ResponseWriter, r *http.Request) {
	u, ok := a.findingAccess(w, r, true)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Неверная форма", 400)
		return
	}
	work, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	dir := eventsBackupDirectory(config.DataDir(), config.Load())
	name := r.FormValue("name")
	var err error
	message, action := "", ""
	switch r.PathValue("operation") {
	case "now":
		var info securityevents.BackupInfo
		info, err = a.Events.CreateBackup(work, dir, config.Load().BackupKeep)
		name = info.Name
		message = "Копия Events создана и проверена"
		action = "events_backup"
	case "verify":
		var path string
		path, err = securityevents.BackupPath(dir, name)
		if err == nil {
			err = securityevents.VerifyBackup(work, path)
		}
		message = "Целостность и формат копии Events проверены"
		action = "events_backup_verify"
	case "restore":
		if r.FormValue("confirm") != "1" {
			http.Error(w, "Подтвердите замену Events при перезапуске и выключение сбора", 400)
			return
		}
		err = a.Events.StageRestore(work, dir, name)
		message = "Восстановление Events подготовлено. Перезапустите сервер; затем включите сбор для нужных ПК заново"
		action = "events_restore_stage"
	case "cancel":
		err = a.Events.CancelRestore()
		message = "Восстановление Events отменено"
		action = "events_restore_cancel"
	default:
		http.NotFound(w, r)
		return
	}
	if err != nil {
		log.Printf("%s: %v", action, err)
		http.Error(w, "Операция с копией Events не выполнена. Проверьте файл, права и свободное место; подробности в журнале сервера.", http.StatusServiceUnavailable)
		return
	}
	auth.LogAction(a.DB, u.ID, action, name, "")
	http.Redirect(w, r, "/events?tab=backups&message="+url.QueryEscape(message)+"#events-backups", http.StatusSeeOther)
}

// This summary is included only for administrators, including the refresh API.
func (a *App) eventsIssueGroups(r *http.Request) []issueGroup {
	u := auth.CurrentUser(a.DB, r)
	if !u.IsAdmin() || a.Demo || a.Events == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	g := issueGroup{Cause: "Сбор и доставка Events", Crit: true, Href: "/events?tab=collection#events-delivery"}
	rows, err := a.DB.QueryContext(ctx, `SELECT id,hostname,COALESCE(agent_token,'') FROM devices WHERE COALESCE(agent_token,'')<>'' ORDER BY hostname,id`)
	if err != nil {
		return nil
	}
	type device struct {
		id          int64
		name, token string
	}
	var devices []device
	for rows.Next() {
		var d device
		if err = rows.Scan(&d.id, &d.name, &d.token); err != nil {
			break
		}
		devices = append(devices, d)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return nil
	}
	for _, d := range devices {
		p, e := a.Events.Policy(ctx, d.id, d.token)
		if e != nil {
			err = e
			break
		}
		if !p.Enabled {
			continue
		}
		s, e := a.Events.GetStatus(ctx, d.id)
		if e != nil {
			err = e
			break
		}
		h := securityevents.AssessDelivery(p, s, time.Now().UTC())
		if h.Level != "error" && h.Level != "warning" {
			continue
		}
		g.Total++
		if len(g.Items) < maxIssueItems {
			g.Items = append(g.Items, issueItem{Title: d.name, Detail: h.Title, Href: fmt.Sprintf("/events?tab=collection#events-device-%d", d.id)})
		}
	}
	if err != nil {
		g.Total++
		g.Items = append(g.Items, issueItem{Title: "Events", Detail: "Состояние доставки не удалось проверить", Href: "/events"})
	}
	g.More = max(0, g.Total-len(g.Items))
	var out []issueGroup
	if g.Total > 0 {
		out = append(out, g)
	}
	panel := a.eventsBackupPanel()
	if panel.Problem != "" {
		out = append(out, issueGroup{Cause: "Резервные копии Events", Total: 1, Href: "/events?tab=backups#events-backups", Items: []issueItem{{Title: "Events", Detail: panel.Problem, Href: "/events?tab=backups#events-backups"}}})
	}
	return out
}
