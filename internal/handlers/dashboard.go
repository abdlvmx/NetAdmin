package handlers

import (
	"database/sql"
	"fmt"
	"html/template"
	"log"
	"math"
	"net/http"

	"netadmin/internal/auth"
	"netadmin/internal/config"
	"netadmin/internal/tz"
	"netadmin/internal/web"
)

type dashStats struct {
	UsersTotal, UsersActive                     int
	DevicesTotal, DevicesOnline, DevicesOffline int
	DevicesOnlinePct                            int
	EmployeesTotal                              int
	AlertsTotal                                 int
	// Покрытие агентами. Отфильтровать машины без агента страница устройств
	// умела и раньше, а ответить «сколько их всего и сколько осталось» —
	// только счётом строк глазами.
	DevicesWithAgent, DevicesNoAgent int
	AgentCoveragePct                 int
	// Найденные в сети хосты, ещё не заведённые устройствами: для раскатки
	// это такая же цель, но живут они на другой странице.
	DiscoveredNew int
}

type donutData struct {
	Online, Offline, Unknown          int
	OnlinePct, OfflinePct, UnknownPct int
	Gradient                          template.CSS
}

type deviceLoad struct {
	Hostname            string
	CPU, RAM, Disk, Max int
	Class               string
}

type dashData struct {
	User   *auth.User
	Active string
	// Onboarding — чек-лист первых шагов; nil, когда показывать нечего.
	Onboarding    *onboarding
	Stats         dashStats
	Donut         donutData
	TopDevices    []deviceLoad
	Issues        []issueGroup
	IssuesTotal   int
	Activity      []auditRow
	LastHeartbeat string
}

// Dashboard — GET /dashboard.
// dashboardStats считает сводку для плиток. Вынесено из обработчика, чтобы
// счёт проверялся тестом, а не только глазами на живой базе.
func (a *App) dashboardStats() dashStats {
	var s dashStats
	q := func(dest *int, query string) { _ = a.DB.QueryRow(query).Scan(dest) }
	q(&s.UsersTotal, "SELECT COUNT(*) FROM users")
	q(&s.UsersActive, "SELECT COUNT(*) FROM users WHERE is_active=1")
	q(&s.DevicesTotal, "SELECT COUNT(*) FROM devices")
	q(&s.DevicesOnline, "SELECT COUNT(*) FROM devices WHERE status='online'")
	q(&s.DevicesOffline, "SELECT COUNT(*) FROM devices WHERE status='offline'")
	q(&s.EmployeesTotal, "SELECT COUNT(*) FROM employees")
	q(&s.AlertsTotal, `SELECT COUNT(*) FROM devices
		WHERE status='offline' OR cpu_usage>=90 OR ram_usage>=90 OR disk_usage>=90
		   OR (last_seen IS NOT NULL AND last_seen < datetime('now','-10 minutes'))`)
	q(&s.DevicesWithAgent, "SELECT COUNT(*) FROM devices WHERE COALESCE(agent_token,'')<>''")
	q(&s.DiscoveredNew, "SELECT COUNT(*) FROM discovery_queue WHERE status='new'")
	s.DevicesNoAgent = s.DevicesTotal - s.DevicesWithAgent
	s.AgentCoveragePct = pct(s.DevicesWithAgent, s.DevicesTotal)
	return s
}

func (a *App) Dashboard(w http.ResponseWriter, r *http.Request) {
	user := auth.CurrentUser(a.DB, r)
	if user == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	s := a.dashboardStats()
	s.DevicesOnlinePct = pct(s.DevicesOnline, s.DevicesTotal)

	issues := a.issueGroups()
	data := dashData{
		User:          user,
		Active:        "dashboard",
		Onboarding:    a.onboardingFor(user, config.Load()),
		Stats:         s,
		Donut:         buildDonut(s.DevicesOnline, s.DevicesOffline, s.DevicesTotal),
		TopDevices:    a.topDevices(),
		Issues:        issues,
		IssuesTotal:   issuesTotal(issues),
		Activity:      a.recentActivity(),
		LastHeartbeat: a.lastHeartbeat(),
	}
	web.RenderPage(w, "dashboard", data)
}

func pct(part, total int) int {
	if total == 0 {
		return 0
	}
	return int(math.Round(float64(part) * 100 / float64(total)))
}

func buildDonut(online, offline, total int) donutData {
	d := donutData{Online: online, Offline: offline, Unknown: total - online - offline}
	d.OnlinePct, d.OfflinePct = pct(online, total), pct(offline, total)
	d.UnknownPct = pct(d.Unknown, total)
	if total == 0 {
		d.Gradient = template.CSS("var(--border)")
		return d
	}
	onPct := float64(online) / float64(total) * 100
	offPct := onPct + float64(offline)/float64(total)*100
	d.Gradient = template.CSS(fmt.Sprintf(
		"conic-gradient(#18a058 0 %.1f%%, #e5484d %.1f%% %.1f%%, #cdd6e4 %.1f%% 100%%)",
		onPct, onPct, offPct, offPct))
	return d
}

func (a *App) topDevices() []deviceLoad {
	rows, err := a.DB.Query(`
		SELECT hostname, cpu_usage, ram_usage, disk_usage
		FROM devices WHERE status='online'
		ORDER BY cpu_usage DESC LIMIT 5`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []deviceLoad
	for rows.Next() {
		var host string
		var cpu, ram, disk float64
		if rows.Scan(&host, &cpu, &ram, &disk) != nil {
			continue
		}
		d := deviceLoad{
			Hostname: host,
			CPU:      int(math.Round(cpu)),
			RAM:      int(math.Round(ram)),
			Disk:     int(math.Round(disk)),
		}
		d.Max = d.CPU
		switch {
		case d.CPU >= 90:
			d.Class = "crit"
		case d.CPU >= 70:
			d.Class = "warn"
		}
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		log.Printf("topDevices: %v", err)
	}
	return out
}

func (a *App) recentActivity() []auditRow {
	rows, err := a.DB.Query(`
		SELECT COALESCE(a.created_at,''), COALESCE(u.username,'система'),
		       a.action, COALESCE(a.target,''), COALESCE(a.detail,'')
		FROM audit_log a LEFT JOIN users u ON a.user_id=u.id
		ORDER BY a.created_at DESC LIMIT 5`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []auditRow
	for rows.Next() {
		var l auditRow
		if rows.Scan(&l.CreatedAt, &l.Username, &l.Action, &l.Target, &l.Detail) == nil {
			l.CreatedAt = tz.Time(l.CreatedAt)
			out = append(out, l)
		}
	}
	if err := rows.Err(); err != nil {
		log.Printf("recentActivity: %v", err)
	}
	return out
}

func (a *App) lastHeartbeat() string {
	var mins sql.NullInt64
	a.DB.QueryRow(`SELECT CAST((julianday('now')-julianday(MAX(last_seen)))*1440 AS INTEGER)
		FROM devices WHERE last_seen IS NOT NULL`).Scan(&mins)
	if !mins.Valid {
		return "нет данных"
	}
	m := mins.Int64
	switch {
	case m < 1:
		return "только что"
	case m < 60:
		return fmt.Sprintf("%d мин назад", m)
	case m < 1440:
		return fmt.Sprintf("%d ч назад", m/60)
	default:
		return fmt.Sprintf("%d дн назад", m/1440)
	}
}
