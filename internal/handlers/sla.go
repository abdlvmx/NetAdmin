package handlers

import (
	"net/http"

	"netadmin/internal/auth"
	"netadmin/internal/web"
)

type slaRow struct {
	Name, Type, Target, Rating string
	Uptime                     float64
	Checks                     int
}

type slaPageData struct {
	User        *auth.User
	Active      string
	Rows        []slaRow
	Period      string
	PeriodLabel string
	AvgUptime   float64
}

// SLAPage — GET /sla?period=week|month : доступность сервисов за период.
func (a *App) SLAPage(w http.ResponseWriter, r *http.Request) {
	user := auth.CurrentUser(a.DB, r)
	if user == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	period := r.URL.Query().Get("period")
	window, label := "-30 days", "30 дней"
	if period == "week" {
		window, label = "-7 days", "7 дней"
	}
	data := slaPageData{User: user, Active: "sla", Period: period, PeriodLabel: label}

	rows, err := a.DB.Query(`SELECT sc.name, sc.type, sc.target,
		COALESCE(SUM(h.up),0), COUNT(h.up)
		FROM service_checks sc
		LEFT JOIN service_check_history h ON h.check_id=sc.id AND h.ts >= datetime('now', ?)
		GROUP BY sc.id ORDER BY sc.name`, window)
	var sum float64
	var cnt int
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var sr slaRow
			var upSum, total int
			if rows.Scan(&sr.Name, &sr.Type, &sr.Target, &upSum, &total) != nil {
				continue
			}
			sr.Checks = total
			if total > 0 {
				sr.Uptime = float64(upSum) * 100 / float64(total)
				sum += sr.Uptime
				cnt++
			}
			sr.Rating = slaRating(sr.Uptime, total)
			data.Rows = append(data.Rows, sr)
		}
	}
	if cnt > 0 {
		data.AvgUptime = sum / float64(cnt)
	}
	web.RenderPage(w, "sla", data)
}

func slaRating(uptime float64, checks int) string {
	if checks == 0 {
		return "nodata"
	}
	switch {
	case uptime >= 99.9:
		return "good"
	case uptime >= 99:
		return "medium"
	default:
		return "poor"
	}
}
