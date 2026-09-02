package handlers

import (
	"net/http"
	"strconv"
	"strings"

	"netadmin/internal/auth"
	"netadmin/internal/monitor"
	"netadmin/internal/notify"
	"netadmin/internal/tz"
	"netadmin/internal/web"
)

var checkTypes = map[string]bool{
	"http": true, "https": true, "tcp": true, "dns": true,
	"smtp": true, "imap": true, "rdp": true,
}

// RunDueChecks выполняет проверки сервисов, у которых истёк интервал. Вызывается фоново.
func (a *App) RunDueChecks() {
	type chk struct {
		id                       int64
		name, typ, target, prevS string
	}
	var due []chk
	rows, err := a.DB.Query(`SELECT id, COALESCE(name,''), COALESCE(type,''), COALESCE(target,''), COALESCE(last_status,'')
		FROM service_checks
		WHERE enabled=1 AND (last_check IS NULL OR last_check <= datetime('now', '-'||COALESCE(interval_sec,60)||' seconds'))`)
	if err == nil {
		for rows.Next() {
			var c chk
			if rows.Scan(&c.id, &c.name, &c.typ, &c.target, &c.prevS) == nil {
				due = append(due, c)
			}
		}
		rows.Close()
	}
	for _, c := range due {
		res := monitor.Check(c.typ, c.target)
		status := "down"
		if res.Up {
			status = "up"
		}
		a.DB.Exec("UPDATE service_checks SET last_status=?, last_latency_ms=?, last_check=datetime('now') WHERE id=?",
			status, res.LatencyMs, c.id)
		up := 0
		if res.Up {
			up = 1
		}
		a.DB.Exec("INSERT INTO service_check_history (check_id, up, latency_ms) VALUES (?,?,?)", c.id, up, res.LatencyMs)
		// уведомление о переходе up<->down
		if c.prevS != "" && c.prevS != status {
			if status == "down" {
				notify.Message("Сервис недоступен: " + c.name + " (" + c.target + ")")
			} else {
				notify.Message("Сервис восстановлен: " + c.name + " (" + c.target + ")")
			}
		}
	}
}

type checkRow struct {
	ID                 int64
	Name, Type, Target string
	Status, LastCheck  string
	Latency            int
	Enabled            bool
}

type serviceMonData struct {
	User            *auth.User
	Active          string
	Rows            []checkRow
	Up, Down, Total int
	Msg             string
}

// ServiceMonitorPage — GET /monitoring : список проверок сервисов.
func (a *App) ServiceMonitorPage(w http.ResponseWriter, r *http.Request) {
	user := auth.CurrentUser(a.DB, r)
	if user == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	data := serviceMonData{User: user, Active: "monitoring", Msg: r.URL.Query().Get("message")}
	rows, err := a.DB.Query(`SELECT id, COALESCE(name,''), COALESCE(type,''), COALESCE(target,''),
		COALESCE(last_status,''), COALESCE(last_latency_ms,0), COALESCE(last_check,''), COALESCE(enabled,1)
		FROM service_checks ORDER BY name`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var c checkRow
			var last string
			var en int
			if rows.Scan(&c.ID, &c.Name, &c.Type, &c.Target, &c.Status, &c.Latency, &last, &en) != nil {
				continue
			}
			c.LastCheck = tz.DateTime(last)
			c.Enabled = en == 1
			switch c.Status {
			case "up":
				data.Up++
			case "down":
				data.Down++
			}
			data.Total++
			data.Rows = append(data.Rows, c)
		}
	}
	web.RenderPage(w, "servicemon", data)
}

// AddServiceCheck — POST /monitoring/add (admin).
func (a *App) AddServiceCheck(w http.ResponseWriter, r *http.Request) {
	user := auth.CurrentUser(a.DB, r)
	if user == nil || !user.IsAdmin() {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	_ = r.ParseForm()
	name := strings.TrimSpace(r.FormValue("name"))
	typ := strings.ToLower(strings.TrimSpace(r.FormValue("type")))
	target := strings.TrimSpace(r.FormValue("target"))
	if name == "" || target == "" || !checkTypes[typ] {
		http.Redirect(w, r, "/monitoring?message=Заполните+поля", http.StatusSeeOther)
		return
	}
	interval, _ := strconv.Atoi(strings.TrimSpace(r.FormValue("interval_sec")))
	if interval < 10 {
		interval = 60
	}
	a.DB.Exec("INSERT INTO service_checks (name, type, target, interval_sec) VALUES (?,?,?,?)",
		name, typ, target, interval)
	auth.LogAction(a.DB, user.ID, "check_add", name, typ)
	http.Redirect(w, r, "/monitoring?message=Проверка+добавлена", http.StatusSeeOther)
}

// ToggleServiceCheck — POST /monitoring/{id}/toggle (admin).
func (a *App) ToggleServiceCheck(w http.ResponseWriter, r *http.Request) {
	user := auth.CurrentUser(a.DB, r)
	if user == nil || !user.IsAdmin() {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	a.DB.Exec("UPDATE service_checks SET enabled=1-enabled WHERE id=?", id)
	http.Redirect(w, r, "/monitoring", http.StatusSeeOther)
}

// DeleteServiceCheck — POST /monitoring/{id}/delete (admin).
func (a *App) DeleteServiceCheck(w http.ResponseWriter, r *http.Request) {
	user := auth.CurrentUser(a.DB, r)
	if user == nil || !user.IsAdmin() {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	a.DB.Exec("DELETE FROM service_checks WHERE id=?", id)
	a.DB.Exec("DELETE FROM service_check_history WHERE check_id=?", id)
	auth.LogAction(a.DB, user.ID, "check_delete", strconv.FormatInt(id, 10), "")
	http.Redirect(w, r, "/monitoring?message=Проверка+удалена", http.StatusSeeOther)
}
