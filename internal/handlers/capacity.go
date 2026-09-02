package handlers

import (
	"log"
	"net/http"
	"sort"

	"netadmin/internal/auth"
	"netadmin/internal/web"
)

const capacityThreshold = 95.0 // % заполнения, на который прогнозируем выход

type capacityRow struct {
	Hostname string
	Resource string // "Диск" | "ОЗУ"
	Current  float64
	Days     int
}

type capacityPageData struct {
	User   *auth.User
	Active string
	Rows   []capacityRow
}

// CapacityPage — GET /capacity : прогноз заполнения диска/ОЗУ (линейная регрессия).
func (a *App) CapacityPage(w http.ResponseWriter, r *http.Request) {
	user := auth.CurrentUser(a.DB, r)
	if user == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	data := capacityPageData{User: user, Active: "capacity"}

	// устройства с историей метрик
	type dev struct {
		id   int64
		host string
	}
	var devs []dev
	if rows, err := a.DB.Query(`SELECT id, hostname FROM devices
		WHERE id IN (SELECT DISTINCT device_id FROM metrics_history
		             UNION SELECT DISTINCT device_id FROM metrics_rollup) ORDER BY hostname`); err == nil {
		for rows.Next() {
			var d dev
			if rows.Scan(&d.id, &d.host) == nil {
				devs = append(devs, d)
			}
		}
		if err := rows.Err(); err != nil {
			log.Printf("CapacityPage: %v", err)
		}
		rows.Close()
	}

	for _, d := range devs {
		for _, res := range []struct{ col, name string }{{"disk", "Диск"}, {"ram", "ОЗУ"}} {
			ys := a.dailySeries(d.id, res.col)
			if days, cur, ok := forecastDays(ys, capacityThreshold); ok {
				data.Rows = append(data.Rows, capacityRow{Hostname: d.host, Resource: res.name, Current: cur, Days: days})
			}
		}
	}
	// ближайшие к заполнению — наверх
	sort.SliceStable(data.Rows, func(i, j int) bool { return data.Rows[i].Days < data.Rows[j].Days })
	web.RenderPage(w, "capacity", data)
}

// dailySeries возвращает суточные средние значения метрики (raw + rollup) по дням.
func (a *App) dailySeries(deviceID int64, col string) []float64 {
	rawCol := map[string]string{"disk": "disk_usage", "ram": "ram_usage", "cpu": "cpu_usage"}[col]
	rollCol := map[string]string{"disk": "disk_avg", "ram": "ram_avg", "cpu": "cpu_avg"}[col]
	q := `SELECT day, AVG(v) FROM (
		SELECT date(ts) day, ` + rawCol + ` v FROM metrics_history WHERE device_id=?
		UNION ALL
		SELECT date(bucket) day, ` + rollCol + ` v FROM metrics_rollup WHERE device_id=? AND period='day'
	) GROUP BY day ORDER BY day`
	rows, err := a.DB.Query(q, deviceID, deviceID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []float64
	for rows.Next() {
		var day string
		var v float64
		if rows.Scan(&day, &v) == nil {
			out = append(out, v)
		}
	}
	if err := rows.Err(); err != nil {
		log.Printf("dailySeries: %v", err)
	}
	return out
}

// forecastDays оценивает, через сколько дней значение достигнет порога (линейная
// регрессия по дневному ряду). Возвращает дни, текущее значение, успех.
func forecastDays(ys []float64, threshold float64) (int, float64, bool) {
	n := len(ys)
	if n < 3 {
		return 0, 0, false
	}
	var sx, sy, sxx, sxy float64
	for i, y := range ys {
		x := float64(i)
		sx += x
		sy += y
		sxx += x * x
		sxy += x * y
	}
	fn := float64(n)
	denom := fn*sxx - sx*sx
	if denom == 0 {
		return 0, 0, false
	}
	slope := (fn*sxy - sx*sy) / denom
	intercept := (sy - slope*sx) / fn
	cur := slope*float64(n-1) + intercept
	if slope <= 0.01 { // практически не растёт — прогноз не имеет смысла
		return 0, 0, false
	}
	if cur >= threshold {
		return 0, cur, true // уже за порогом
	}
	days := (threshold - cur) / slope
	if days < 0 || days > 3650 {
		return 0, 0, false
	}
	return int(days + 0.5), cur, true
}
