package handlers

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"strconv"

	"netadmin/internal/auth"
	"netadmin/internal/tz"
)

// допустимые окна (часы)
func parseHours(r *http.Request) int {
	switch r.URL.Query().Get("hours") {
	case "1":
		return 1
	case "6":
		return 6
	case "168":
		return 168
	case "720": // 30 дней
		return 720
	case "2160": // 90 дней
		return 2160
	default:
		return 24
	}
}

func metricsBucketSeconds(hours int) int {
	switch {
	case hours <= 6:
		return 60
	case hours <= 24:
		return 300
	case hours <= 168:
		return 3600
	default:
		return 86400 // суточные корзины для длинных диапазонов
	}
}

type metricPoint struct {
	Ts   string  `json:"ts"`
	CPU  float64 `json:"cpu"`
	RAM  float64 `json:"ram"`
	Disk float64 `json:"disk"`
}

// metricSeries строит ряд точек CPU/RAM/Disk, объединяя сырые метрики (последние
// 7 дней) и агрегаты metrics_rollup (старше) — перекрытия нет, т.к. rollup удаляет
// сырьё. deviceID==0 → среднее по всему парку.
func (a *App) metricSeries(deviceID int64, hours, bucket int) []metricPoint {
	window := "-" + strconv.Itoa(hours) + " hours"
	rawFilter, rollFilter := "", ""
	args := []any{bucket, bucket, window}
	if deviceID > 0 {
		rawFilter = " AND device_id=?"
		args = append(args, deviceID)
	}
	args = append(args, window)
	if deviceID > 0 {
		rollFilter = " AND device_id=?"
		args = append(args, deviceID)
	}
	q := `SELECT bucket_ts, AVG(cpu), AVG(ram), AVG(disk) FROM (
		SELECT datetime((CAST(strftime('%s', ts) AS INTEGER)/?)*?, 'unixepoch') AS bucket_ts,
		       cpu_usage cpu, ram_usage ram, disk_usage disk
		FROM metrics_history WHERE ts >= datetime('now', ?)` + rawFilter + `
		UNION ALL
		SELECT bucket AS bucket_ts, cpu_avg cpu, ram_avg ram, disk_avg disk
		FROM metrics_rollup WHERE bucket >= datetime('now', ?)` + rollFilter + `
	) GROUP BY bucket_ts ORDER BY bucket_ts`

	rows, err := a.DB.Query(q, args...)
	points := []metricPoint{}
	if err != nil {
		return points
	}
	defer rows.Close()
	for rows.Next() {
		var p metricPoint
		var cpu, ram, disk sql.NullFloat64
		if rows.Scan(&p.Ts, &cpu, &ram, &disk) == nil {
			p.Ts = tz.Full(p.Ts)
			p.CPU, p.RAM, p.Disk = round1(cpu.Float64), round1(ram.Float64), round1(disk.Float64)
			points = append(points, p)
		}
	}
	if err := rows.Err(); err != nil {
		log.Printf("metricSeries: %v", err)
	}
	return points
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(v)
}

// FleetMetrics — GET /api/metrics/fleet?hours=N : средняя нагрузка по парку.
func (a *App) FleetMetrics(w http.ResponseWriter, r *http.Request) {
	if auth.CurrentUser(a.DB, r) == nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	hours := parseHours(r)
	points := a.metricSeries(0, hours, metricsBucketSeconds(hours))
	writeJSON(w, map[string]any{"hours": hours, "points": points})
}

// DevicesStatus — GET /api/devices/status : лёгкая сводка статусов для авто-обновления
// таблицы устройств и счётчиков дашборда (без перезагрузки страницы).
func (a *App) DevicesStatus(w http.ResponseWriter, r *http.Request) {
	if auth.CurrentUser(a.DB, r) == nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	rows, err := a.DB.Query(`SELECT id, status, COALESCE(last_seen,'') FROM devices`)
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	type devStatus struct {
		ID       int64  `json:"id"`
		Status   string `json:"status"`
		LastSeen string `json:"last_seen"`
	}
	list := []devStatus{}
	var total, online, offline int
	for rows.Next() {
		var d devStatus
		var ls string
		if rows.Scan(&d.ID, &d.Status, &ls) != nil {
			continue
		}
		d.LastSeen = tz.DateTime(ls)
		total++
		switch d.Status {
		case "online":
			online++
		case "offline":
			offline++
		}
		list = append(list, d)
	}
	if err := rows.Err(); err != nil {
		log.Printf("DevicesStatus: %v", err)
	}
	var alerts int
	a.DB.QueryRow(`SELECT COUNT(*) FROM devices
		WHERE status='offline' OR cpu_usage>=90 OR ram_usage>=90 OR disk_usage>=90
		   OR (last_seen IS NOT NULL AND last_seen < datetime('now','-10 minutes'))`).Scan(&alerts)
	// Число проблем в сводке — чтобы дашборд заметил, что список «Требует
	// внимания» устарел, и предложил обновить страницу. Перерисовать его сам он
	// не может: список собирается на сервере, а перезагружать страницу под
	// курсором у человека — последнее, чего от неё ждут.
	issues := issuesTotal(a.issueGroups())
	writeJSON(w, map[string]any{
		"devices": list,
		"summary": map[string]int{"total": total, "online": online, "offline": offline,
			"unknown": total - online - offline, "alerts": alerts, "issues": issues},
	})
}

func round1(v float64) float64 {
	return float64(int(v*10+0.5)) / 10
}
