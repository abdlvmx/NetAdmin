package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"

	"netadmin/internal/auth"
	"netadmin/internal/notify"
	"netadmin/internal/tz"
	"netadmin/internal/web"
)

// diskInfo — состояние одного физического диска (снимок от агента / строка БД).
type diskInfo struct {
	Model        string `json:"model"`
	Serial       string `json:"serial"`
	SizeGB       int    `json:"size_gb"`
	MediaType    string `json:"media_type"`
	Health       string `json:"health"`
	Temperature  int    `json:"temperature"`
	PowerOnHours int    `json:"power_on_hours"`
	WearPct      int    `json:"wear_pct"`
	ReadErrors   int    `json:"read_errors"`
	PredictFail  bool   `json:"predict_fail"`
}

// diskVerdict — оценка состояния диска (для UI и алертов).
type diskVerdict struct {
	Severity string // "" | "warning" | "critical"
	Issue    string // человекочитаемая причина
}

// assessDisk оценивает здоровье диска по SMART-показателям. Чистая функция — тестируемая.
// Это мониторинг состояния оборудования, а не средство защиты информации.
func assessDisk(d diskInfo) diskVerdict {
	switch {
	case d.PredictFail:
		return diskVerdict{"critical", "SMART предсказывает отказ диска"}
	case d.Health == "Unhealthy":
		return diskVerdict{"critical", "Состояние диска: критическое"}
	case d.WearPct >= 90:
		return diskVerdict{"critical", fmt.Sprintf("Ресурс SSD почти исчерпан (износ %d%%)", d.WearPct)}
	case d.Health == "Warning":
		return diskVerdict{"warning", "Состояние диска: предупреждение"}
	case d.WearPct >= 80:
		return diskVerdict{"warning", fmt.Sprintf("Высокий износ SSD (%d%%)", d.WearPct)}
	case d.Temperature >= 60:
		return diskVerdict{"warning", fmt.Sprintf("Высокая температура диска (%d°C)", d.Temperature)}
	case d.ReadErrors > 0:
		return diskVerdict{"warning", fmt.Sprintf("Зафиксированы ошибки чтения (%d)", d.ReadErrors)}
	default:
		return diskVerdict{"", ""}
	}
}

// AgentDisks — POST /api/agent-disks : снимок здоровья дисков хоста (токен+HMAC+timestamp).
func (a *App) AgentDisks(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := a.resolveAgent(r); !ok {
		http.Error(w, "invalid agent token", http.StatusUnauthorized)
		return
	}
	body, ok := a.verifyAgentRequest(w, r)
	if !ok {
		return
	}
	var p struct {
		Hostname string     `json:"hostname"`
		Disks    []diskInfo `json:"disks"`
	}
	if err := json.Unmarshal(body, &p); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}

	var did int64
	var host string
	if a.DB.QueryRow("SELECT id, hostname FROM devices WHERE hostname=?", p.Hostname).Scan(&did, &host) != nil || did == 0 {
		writeJSON(w, map[string]any{"ok": true, "skipped": "unknown host"})
		return
	}

	// прежнее состояние по серийнику (для детекта новых отказов)
	prevBad := map[string]bool{}
	if rows, err := a.DB.Query(`SELECT COALESCE(serial,''), COALESCE(health,''), wear_pct, predict_fail
		FROM disks WHERE device_id=?`, did); err == nil {
		for rows.Next() {
			var serial, health string
			var wear, pf int
			if rows.Scan(&serial, &health, &wear, &pf) == nil {
				key := serial
				if key == "" {
					continue
				}
				prevBad[key] = assessDisk(diskInfo{Health: health, WearPct: wear, PredictFail: pf == 1}).Severity == "critical"
			}
		}
		rows.Close()
	}

	// полная замена снимка дисков устройства
	tx, err := a.DB.Begin()
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	tx.Exec("DELETE FROM disks WHERE device_id=?", did)
	for _, d := range p.Disks {
		pf := 0
		if d.PredictFail {
			pf = 1
		}
		tx.Exec(`INSERT INTO disks (device_id, model, serial, size_gb, media_type, health,
			temperature, power_on_hours, wear_pct, read_errors, predict_fail, updated_at)
			VALUES (?,?,?,?,?,?,?,?,?,?,?, datetime('now'))`,
			did, d.Model, d.Serial, d.SizeGB, d.MediaType, d.Health,
			d.Temperature, d.PowerOnHours, d.WearPct, d.ReadErrors, pf)
	}
	tx.Commit()

	// алерт при ПЕРЕХОДЕ диска в критическое состояние (новый отказ)
	for _, d := range p.Disks {
		v := assessDisk(d)
		if v.Severity != "critical" || prevBad[d.Serial] {
			continue
		}
		label := d.Model
		if d.Serial != "" {
			label += " (S/N " + d.Serial + ")"
		}
		msg := "Диск " + label + ": " + v.Issue
		a.DB.Exec(`INSERT INTO events (device_id, hostname, source, severity, category, message)
			VALUES (?,?,'monitor','critical','disk_health',?)`, did, host, msg)
		notify.CriticalEvent(host, msg+"\n\nРекомендуется заранее заменить накопитель и сделать резервную копию данных.")
	}

	writeJSON(w, map[string]any{"ok": true, "count": len(p.Disks)})
}

// DeviceDisks — GET /api/devices/{id}/disks : диски устройства с оценкой состояния.
func (a *App) DeviceDisks(w http.ResponseWriter, r *http.Request) {
	if auth.CurrentUser(a.DB, r) == nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	rows, err := a.DB.Query(`SELECT COALESCE(model,''), COALESCE(serial,''), size_gb,
		COALESCE(media_type,''), COALESCE(health,''), temperature, power_on_hours,
		wear_pct, read_errors, predict_fail FROM disks WHERE device_id=? ORDER BY model`, id)
	type item struct {
		diskInfo
		Severity string `json:"severity"`
		Issue    string `json:"issue"`
	}
	items := []item{}
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var it item
			var pf int
			if rows.Scan(&it.Model, &it.Serial, &it.SizeGB, &it.MediaType, &it.Health,
				&it.Temperature, &it.PowerOnHours, &it.WearPct, &it.ReadErrors, &pf) == nil {
				it.PredictFail = pf == 1
				v := assessDisk(it.diskInfo)
				it.Severity, it.Issue = v.Severity, v.Issue
				items = append(items, it)
			}
		}
	}
	writeJSON(w, map[string]any{"disks": items})
}

// diskHealthRow — строка таблицы парка дисков.
type diskHealthRow struct {
	Hostname     string
	DeviceID     int64
	Model        string
	Serial       string
	SizeGB       int
	MediaType    string
	Health       string
	Temperature  int
	PowerOnHours int
	WearPct      int
	Severity     string
	Issue        string
	Updated      string
}

type diskHealthData struct {
	User      *auth.User
	Active    string
	Rows      []diskHealthRow
	Total     int
	Warnings  int
	Criticals int
	Hosts     int
}

// DiskHealthPage — GET /disk-health : здоровье дисков по всему парку (проблемные сверху).
func (a *App) DiskHealthPage(w http.ResponseWriter, r *http.Request) {
	user := auth.CurrentUser(a.DB, r)
	if user == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	data := diskHealthData{User: user, Active: "disk_health"}

	rows, err := a.DB.Query(`SELECT d.device_id, COALESCE(v.hostname,''), COALESCE(d.model,''),
		COALESCE(d.serial,''), d.size_gb, COALESCE(d.media_type,''), COALESCE(d.health,''),
		d.temperature, d.power_on_hours, d.wear_pct, d.read_errors, d.predict_fail,
		COALESCE(d.updated_at,'')
		FROM disks d LEFT JOIN devices v ON v.id=d.device_id`)
	hosts := map[string]bool{}
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var row diskHealthRow
			var di diskInfo
			var pf int
			if rows.Scan(&row.DeviceID, &row.Hostname, &di.Model, &di.Serial, &di.SizeGB,
				&di.MediaType, &di.Health, &di.Temperature, &di.PowerOnHours, &di.WearPct,
				&di.ReadErrors, &pf, &row.Updated) != nil {
				continue
			}
			di.PredictFail = pf == 1
			v := assessDisk(di)
			row.Model, row.Serial, row.SizeGB = di.Model, di.Serial, di.SizeGB
			row.MediaType, row.Health, row.Temperature = di.MediaType, di.Health, di.Temperature
			row.PowerOnHours, row.WearPct = di.PowerOnHours, di.WearPct
			row.Severity, row.Issue = v.Severity, v.Issue
			row.Updated = tz.DateTime(row.Updated)
			data.Total++
			hosts[row.Hostname] = true
			switch v.Severity {
			case "critical":
				data.Criticals++
			case "warning":
				data.Warnings++
			}
			data.Rows = append(data.Rows, row)
		}
	}
	data.Hosts = len(hosts)
	// проблемные диски наверх: critical → warning → ok
	sevRank := map[string]int{"critical": 0, "warning": 1, "": 2}
	sort.SliceStable(data.Rows, func(i, j int) bool {
		return sevRank[data.Rows[i].Severity] < sevRank[data.Rows[j].Severity]
	})
	web.RenderPage(w, "disk_health", data)
}
