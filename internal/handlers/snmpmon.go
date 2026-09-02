package handlers

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"netadmin/internal/auth"
	"netadmin/internal/notify"
	"netadmin/internal/snmp"
	"netadmin/internal/tz"
	"netadmin/internal/web"
)

const snmpTimeout = 2 * time.Second

// Пороги состояния расходников и батарей. Вход и выход разные: заряд ИБП,
// зависший у самой границы, иначе слал бы письмо на каждом опросе.
const (
	supplyLowPct  = 15 // тонер/картридж ниже — тревога
	supplyOkPct   = 20 // и только выше этого она снимается
	batteryLowPct = 30 // заряд ИБП ниже — тревога
	batteryOkPct  = 35
)

// snmpKinds — допустимые типы устройств для опроса.
var snmpKinds = map[string]string{
	"auto": "Авто", "switch": "Коммутатор", "router": "Маршрутизатор",
	"ups": "ИБП", "printer": "Принтер", "server": "Сервер", "other": "Другое",
}

// snmpDetail — kind-специфичный снимок (сериализуется в столбец detail).
type snmpDetail struct {
	PortsUp    int          `json:"ports_up,omitempty"`
	PortsDown  int          `json:"ports_down,omitempty"`
	PortsTotal int          `json:"ports_total,omitempty"`
	BatteryPct int          `json:"battery_pct,omitempty"`
	RuntimeMin int          `json:"runtime_min,omitempty"`
	LoadPct    int          `json:"load_pct,omitempty"`
	OnBattery  bool         `json:"on_battery,omitempty"`
	BatStatus  string       `json:"bat_status,omitempty"`
	Supplies   []snmpSupply `json:"supplies,omitempty"`
}

type snmpSupply struct {
	Name  string `json:"name"`
	Pct   int    `json:"pct"`
	Known bool   `json:"known"`
}

// portSample — снимок одного порта свитча/роутера (сырые счётчики).
type portSample struct {
	Index, Name          string
	Oper, In, Out, Speed int64
}

// pollSNMP опрашивает устройство: идентификация+аптайм для всех, kind-специфика сверх того.
func pollSNMP(ip string, port uint16, community, kind string) (status, sysName, sysDescr string, uptimeSec int64, det snmpDetail, ports []portSample) {
	status = "down"
	sess, err := snmp.Dial(ip, port, community, snmpTimeout)
	if err != nil {
		return
	}
	defer sess.Close()

	base, err := sess.Get([]string{snmp.OIDSysDescr, snmp.OIDSysUptime, snmp.OIDSysName})
	if err != nil {
		return
	}
	if !snmp.Usable(base[snmp.OIDSysUptime]) {
		return // устройство по сути не ответило
	}
	status = "up"
	uptimeSec = snmp.Int(base[snmp.OIDSysUptime]) / 100 // TimeTicks (1/100 c) → секунды
	sysName = snmp.Str(base[snmp.OIDSysName])
	sysDescr = snmp.Str(base[snmp.OIDSysDescr])

	switch kind {
	case "switch", "router":
		descrs, _ := sess.Walk(snmp.OIDIfDescr)
		operMap := mustWalkMap(sess, snmp.OIDIfOperStatus)
		inMap := mustWalkMap(sess, snmp.OIDIfInOctets)
		outMap := mustWalkMap(sess, snmp.OIDIfOutOctets)
		spMap := mustWalkMap(sess, snmp.OIDIfSpeed)
		var statuses []int64
		for _, d := range descrs {
			idx := snmp.IndexOf(d.Name, snmp.OIDIfDescr)
			if idx == "" {
				continue
			}
			op := operMap[idx]
			statuses = append(statuses, op)
			ports = append(ports, portSample{
				Index: idx, Name: snmp.Str(d), Oper: op,
				In: inMap[idx], Out: outMap[idx], Speed: spMap[idx],
			})
		}
		det.PortsUp, det.PortsDown, det.PortsTotal = snmp.SummarizePorts(statuses)
	case "ups":
		ups, _ := sess.Get([]string{snmp.OIDUpsChargeRemain, snmp.OIDUpsMinutesRemain,
			snmp.OIDUpsBatteryStatus, snmp.OIDUpsOutputSource})
		det.BatteryPct = int(snmp.Int(ups[snmp.OIDUpsChargeRemain]))
		det.RuntimeMin = int(snmp.Int(ups[snmp.OIDUpsMinutesRemain]))
		det.BatStatus = snmp.BatteryStatusText(snmp.Int(ups[snmp.OIDUpsBatteryStatus]))
		det.OnBattery = snmp.OnBattery(snmp.Int(ups[snmp.OIDUpsOutputSource]))
		if load, e := sess.Walk(snmp.OIDUpsOutputLoadWalk); e == nil {
			for _, v := range load {
				if x := int(snmp.Int(v)); x > det.LoadPct {
					det.LoadPct = x
				}
			}
		}
	case "printer":
		descrs, _ := sess.Walk(snmp.OIDPrtSuppliesDescr)
		levels, _ := sess.Walk(snmp.OIDPrtSuppliesLevel)
		maxes, _ := sess.Walk(snmp.OIDPrtSuppliesMax)
		for i := range descrs {
			s := snmpSupply{Name: snmp.Str(descrs[i])}
			if i < len(levels) && i < len(maxes) {
				s.Pct, s.Known = snmp.SupplyPct(snmp.Int(levels[i]), snmp.Int(maxes[i]))
			}
			if s.Name != "" {
				det.Supplies = append(det.Supplies, s)
			}
		}
	}
	return
}

// mustWalkMap обходит поддерево OID и возвращает карту «индекс→значение» (пустую при ошибке).
func mustWalkMap(sess *snmp.Session, base string) map[string]int64 {
	vars, err := sess.Walk(base)
	if err != nil {
		return map[string]int64{}
	}
	return snmp.IndexMap(vars, base)
}

// portRate считает скорость в бит/с по дельте счётчика октетов. Учитывает обнуление
// счётчика (cur<prev → 0) и отсутствие интервала.
func portRate(cur, prev int64, seconds float64) int64 {
	if seconds <= 0 || cur < prev {
		return 0
	}
	return int64(float64(cur-prev) * 8 / seconds)
}

// persistPorts сохраняет снимок портов, рассчитывая скорость относительно прошлого опроса.
func (a *App) persistPorts(snmpID int64, ports []portSample) {
	type prev struct {
		in, out int64
		ts      time.Time
	}
	pm := map[string]prev{}
	if rows, err := a.DB.Query(`SELECT if_index, in_octets, out_octets, COALESCE(updated_at,'')
		FROM snmp_ports WHERE snmp_device_id=?`, snmpID); err == nil {
		for rows.Next() {
			var idx, ts string
			var in, out int64
			if rows.Scan(&idx, &in, &out, &ts) == nil {
				t, _ := time.Parse("2006-01-02 15:04:05", ts)
				pm[idx] = prev{in, out, t}
			}
		}
		if err := rows.Err(); err != nil {
			log.Printf("persistPorts: %v", err)
		}
		rows.Close()
	}
	now := time.Now().UTC()
	tx, err := a.DB.Begin()
	if err != nil {
		return
	}
	tx.Exec("DELETE FROM snmp_ports WHERE snmp_device_id=?", snmpID)
	for _, p := range ports {
		var inRate, outRate int64
		if pv, ok := pm[p.Index]; ok && !pv.ts.IsZero() {
			sec := now.Sub(pv.ts).Seconds()
			inRate = portRate(p.In, pv.in, sec)
			outRate = portRate(p.Out, pv.out, sec)
		}
		tx.Exec(`INSERT INTO snmp_ports (snmp_device_id, if_index, name, oper, in_octets, out_octets,
			in_rate_bps, out_rate_bps, speed, updated_at) VALUES (?,?,?,?,?,?,?,?,?, datetime('now'))`,
			snmpID, p.Index, p.Name, p.Oper, p.In, p.Out, inRate, outRate, p.Speed)
	}
	tx.Commit()
}

// pollAndSave опрашивает одно устройство, сохраняет результат и уведомляет о переходе up/down.
func (a *App) pollAndSave(id int64, ip string, port uint16, community, kind, prev, label string) string {
	status, sysName, sysDescr, uptime, det, ports := pollSNMP(ip, port, community, kind)
	detJSON, _ := json.Marshal(det)
	a.DB.Exec(`UPDATE snmp_devices SET last_status=?, last_poll=datetime('now'),
		sys_name=?, sys_descr=?, uptime_sec=?, detail=? WHERE id=?`,
		status, sysName, sysDescr, uptime, string(detJSON), id)
	if status == "up" && len(ports) > 0 {
		a.persistPorts(id, ports)
	}

	if prev != "" && prev != status {
		if status == "down" {
			a.DB.Exec(`INSERT INTO events (hostname, source, severity, category, message)
				VALUES (?,?, 'critical','snmp', ?)`, label, "monitor", "SNMP-устройство недоступно: "+label+" ("+ip+")")
			notify.Message("SNMP-устройство недоступно: " + label + " (" + ip + ")")
		} else {
			a.DB.Exec(`INSERT INTO events (hostname, source, severity, category, message)
				VALUES (?,?, 'info','snmp', ?)`, label, "monitor", "SNMP-устройство восстановлено: "+label+" ("+ip+")")
			notify.Message("SNMP-устройство восстановлено: " + label + " (" + ip + ")")
		}
	}
	if status == "up" {
		a.reportSupplyState(id, kind, ip, label, det)
	}
	return status
}

// reportSupplyState уведомляет о расходниках и батареях: письмо уходит один раз
// при переходе в проблемное состояние и один раз при возврате в норму, а не на
// каждом опросе. Признак текущей тревоги хранится в snmp_devices.supply_alert.
func (a *App) reportSupplyState(id int64, kind, ip, label string, det snmpDetail) {
	var was int
	a.DB.QueryRow("SELECT COALESCE(supply_alert,0) FROM snmp_devices WHERE id=?", id).Scan(&was)
	msgs := snmpAlerts(kind, det, was == 1)

	switch {
	case len(msgs) > 0 && was == 0:
		text := label + " (" + ip + "): " + strings.Join(msgs, ", ")
		a.DB.Exec(`INSERT INTO events (hostname, source, severity, category, message)
			VALUES (?,?, 'warning','snmp', ?)`, label, "monitor", text)
		notify.Message("NetAdmin: " + text)
		a.DB.Exec("UPDATE snmp_devices SET supply_alert=1 WHERE id=?", id)
	case len(msgs) == 0 && was == 1:
		text := label + " (" + ip + "): состояние в норме"
		a.DB.Exec(`INSERT INTO events (hostname, source, severity, category, message)
			VALUES (?,?, 'info','snmp', ?)`, label, "monitor", text)
		notify.Message("NetAdmin: " + text)
		a.DB.Exec("UPDATE snmp_devices SET supply_alert=0 WHERE id=?", id)
	}
}

// RunDueSNMP опрашивает SNMP-устройства, у которых истёк интервал. Вызывается фоново.
func (a *App) RunDueSNMP() {
	type dev struct {
		id                       int64
		name, ip, comm, kind, ps string
		port                     int
	}
	var due []dev
	rows, err := a.DB.Query(`SELECT id, COALESCE(name,''), COALESCE(ip,''), COALESCE(port,161),
		COALESCE(community,'public'), COALESCE(kind,'auto'), COALESCE(last_status,'')
		FROM snmp_devices WHERE enabled=1 AND COALESCE(ip,'')<>''
		AND (last_poll IS NULL OR last_poll <= datetime('now','-'||COALESCE(interval_sec,120)||' seconds'))`)
	if err == nil {
		for rows.Next() {
			var d dev
			if rows.Scan(&d.id, &d.name, &d.ip, &d.port, &d.comm, &d.kind, &d.ps) == nil {
				due = append(due, d)
			}
		}
		if err := rows.Err(); err != nil {
			log.Printf("RunDueSNMP: %v", err)
		}
		rows.Close()
	}
	for _, d := range due {
		label := d.name
		if label == "" {
			label = d.ip
		}
		a.pollAndSave(d.id, d.ip, uint16(d.port), d.comm, d.kind, d.ps, label)
	}
}

// ── Веб ─────────────────────────────────────────────────────────────────────

type snmpRow struct {
	ID       int64
	Name     string
	IP       string
	Kind     string
	KindRu   string
	Status   string
	SysName  string
	Uptime   string
	LastPoll string
	Summary  string
	Warn     bool
	Enabled  bool
}

type snmpData struct {
	User            *auth.User
	Active          string
	Rows            []snmpRow
	Up, Down, Total int
	Kinds           map[string]string
	Msg             string
}

// SNMPDevicesPage — GET /snmp : список SNMP-устройств и их состояние.
func (a *App) SNMPDevicesPage(w http.ResponseWriter, r *http.Request) {
	user := auth.CurrentUser(a.DB, r)
	if user == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	data := snmpData{User: user, Active: "snmp", Kinds: snmpKinds, Msg: r.URL.Query().Get("message")}
	rows, err := a.DB.Query(`SELECT id, COALESCE(name,''), COALESCE(ip,''), COALESCE(kind,'auto'),
		COALESCE(last_status,''), COALESCE(sys_name,''), uptime_sec, COALESCE(last_poll,''),
		COALESCE(detail,''), COALESCE(enabled,1) FROM snmp_devices ORDER BY name, ip`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var row snmpRow
			var uptime int64
			var detail, lastPoll string
			var en int
			if rows.Scan(&row.ID, &row.Name, &row.IP, &row.Kind, &row.Status, &row.SysName,
				&uptime, &lastPoll, &detail, &en) != nil {
				continue
			}
			row.KindRu = snmpKinds[row.Kind]
			row.Enabled = en == 1
			row.LastPoll = tz.DateTime(lastPoll)
			if row.Status == "up" {
				row.Uptime = humanUptime(uptime)
			}
			row.Summary, row.Warn = snmpSummary(row.Kind, detail)
			switch row.Status {
			case "up":
				data.Up++
			case "down":
				data.Down++
			}
			data.Total++
			data.Rows = append(data.Rows, row)
		}
		if err := rows.Err(); err != nil {
			log.Printf("SNMPDevicesPage: %v", err)
		}
	}
	web.RenderPage(w, "snmp", data)
}

// snmpAlerts перечисляет проблемы состояния устройства: заканчивающиеся
// расходники принтера, ИБП на батарее или с низким зарядом. Это не то же, что
// недоступность: устройство отвечает, но требует внимания.
//
// active — была ли тревога на прошлом опросе. Пока она активна, снимается
// только на заметно лучшем значении (см. пороги выше), иначе значение у самой
// границы дребезжало бы письмами.
//
// Пустой результат означает «всё в норме».
func snmpAlerts(kind string, d snmpDetail, active bool) []string {
	supplyLim, batLim := supplyLowPct, batteryLowPct
	if active {
		supplyLim, batLim = supplyOkPct, batteryOkPct
	}
	var msgs []string
	switch kind {
	case "ups":
		if d.OnBattery {
			msgs = append(msgs, "работает от батареи")
		}
		if d.BatteryPct > 0 && d.BatteryPct < batLim {
			msgs = append(msgs, fmt.Sprintf("заряд батареи %d%%", d.BatteryPct))
		}
	case "printer":
		for _, s := range d.Supplies {
			if s.Known && s.Pct < supplyLim {
				msgs = append(msgs, fmt.Sprintf("%s %d%%", s.Name, s.Pct))
			}
		}
	}
	return msgs
}

// snmpSummary строит краткое описание состояния для строки таблицы + флаг тревоги.
func snmpSummary(kind, detailJSON string) (string, bool) {
	if detailJSON == "" {
		return "", false
	}
	var d snmpDetail
	if json.Unmarshal([]byte(detailJSON), &d) != nil {
		return "", false
	}
	switch kind {
	case "switch", "router":
		if d.PortsTotal == 0 {
			return "", false
		}
		return fmt.Sprintf("Порты: %d из %d активны", d.PortsUp, d.PortsTotal), d.PortsDown > 0
	case "ups":
		parts := []string{}
		warn := len(snmpAlerts("ups", d, false)) > 0
		if d.OnBattery {
			parts = append(parts, "⚡ от батареи")
		}
		if d.BatteryPct > 0 {
			parts = append(parts, fmt.Sprintf("заряд %d%%", d.BatteryPct))
		}
		if d.RuntimeMin > 0 {
			parts = append(parts, fmt.Sprintf("~%d мин", d.RuntimeMin))
		}
		if d.LoadPct > 0 {
			parts = append(parts, fmt.Sprintf("нагрузка %d%%", d.LoadPct))
		}
		return strings.Join(parts, " · "), warn
	case "printer":
		if len(d.Supplies) == 0 {
			return "", false
		}
		parts := []string{}
		warn := len(snmpAlerts("printer", d, false)) > 0
		for _, s := range d.Supplies {
			if s.Known {
				parts = append(parts, fmt.Sprintf("%s %d%%", s.Name, s.Pct))
			}
		}
		return strings.Join(parts, " · "), warn
	}
	return "", false
}

// humanUptime переводит секунды аптайма в «Xд Yч» / «Yч Zм».
func humanUptime(sec int64) string {
	d := sec / 86400
	h := (sec % 86400) / 3600
	m := (sec % 3600) / 60
	if d > 0 {
		return fmt.Sprintf("%dд %dч", d, h)
	}
	if h > 0 {
		return fmt.Sprintf("%dч %dм", h, m)
	}
	return fmt.Sprintf("%dм", m)
}

// humanRate форматирует бит/с в Кбит/с / Мбит/с / Гбит/с.
func humanRate(bps int64) string {
	switch {
	case bps <= 0:
		return "0"
	case bps < 1000:
		return fmt.Sprintf("%d бит/с", bps)
	case bps < 1_000_000:
		return fmt.Sprintf("%.1f Кбит/с", float64(bps)/1000)
	case bps < 1_000_000_000:
		return fmt.Sprintf("%.1f Мбит/с", float64(bps)/1_000_000)
	default:
		return fmt.Sprintf("%.2f Гбит/с", float64(bps)/1_000_000_000)
	}
}

type portRow struct {
	Name    string
	Up      bool
	InRate  string
	OutRate string
	Speed   string
}

type snmpPortsData struct {
	User    *auth.User
	Active  string
	Device  string
	IP      string
	Rows    []portRow
	UpCount int
	Total   int
}

// SNMPPortsPage — GET /snmp/{id}/ports : статус и трафик портов устройства.
func (a *App) SNMPPortsPage(w http.ResponseWriter, r *http.Request) {
	user := auth.CurrentUser(a.DB, r)
	if user == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	data := snmpPortsData{User: user, Active: "snmp"}
	a.DB.QueryRow("SELECT COALESCE(name,''), COALESCE(ip,'') FROM snmp_devices WHERE id=?", id).Scan(&data.Device, &data.IP)
	if data.Device == "" {
		data.Device = data.IP
	}
	rows, err := a.DB.Query(`SELECT COALESCE(name,''), oper, in_rate_bps, out_rate_bps, speed
		FROM snmp_ports WHERE snmp_device_id=? ORDER BY CAST(if_index AS INTEGER)`, id)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var name string
			var oper, inR, outR, speed int64
			if rows.Scan(&name, &oper, &inR, &outR, &speed) != nil {
				continue
			}
			pr := portRow{Name: name, Up: oper == 1, InRate: humanRate(inR), OutRate: humanRate(outR), Speed: humanRate(speed)}
			data.Total++
			if pr.Up {
				data.UpCount++
			}
			data.Rows = append(data.Rows, pr)
		}
		if err := rows.Err(); err != nil {
			log.Printf("SNMPPortsPage: %v", err)
		}
	}
	web.RenderPage(w, "snmp_ports", data)
}

// AddSNMPDevice — POST /snmp/add (admin).
func (a *App) AddSNMPDevice(w http.ResponseWriter, r *http.Request) {
	user := auth.CurrentUser(a.DB, r)
	if user == nil || !user.IsAdmin() {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	_ = r.ParseForm()
	name := strings.TrimSpace(r.FormValue("name"))
	ip := strings.TrimSpace(r.FormValue("ip"))
	community := strings.TrimSpace(r.FormValue("community"))
	kind := strings.TrimSpace(r.FormValue("kind"))
	if _, ok := snmpKinds[kind]; !ok {
		kind = "auto"
	}
	if community == "" {
		community = "public"
	}
	if ip == "" {
		http.Redirect(w, r, "/snmp?message=Укажите+IP-адрес", http.StatusSeeOther)
		return
	}
	port, _ := strconv.Atoi(strings.TrimSpace(r.FormValue("port")))
	if port <= 0 || port > 65535 {
		port = 161
	}
	interval, _ := strconv.Atoi(strings.TrimSpace(r.FormValue("interval_sec")))
	if interval < 30 {
		interval = 120
	}
	a.DB.Exec(`INSERT INTO snmp_devices (name, ip, port, community, kind, interval_sec)
		VALUES (?,?,?,?,?,?)`, name, ip, port, community, kind, interval)
	auth.LogAction(a.DB, user.ID, "snmp_add", name, ip)
	http.Redirect(w, r, "/snmp?message=Устройство+добавлено", http.StatusSeeOther)
}

// ToggleSNMPDevice — POST /snmp/{id}/toggle (admin).
func (a *App) ToggleSNMPDevice(w http.ResponseWriter, r *http.Request) {
	user := auth.CurrentUser(a.DB, r)
	if user == nil || !user.IsAdmin() {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	a.DB.Exec("UPDATE snmp_devices SET enabled=1-enabled WHERE id=?", id)
	http.Redirect(w, r, "/snmp", http.StatusSeeOther)
}

// DeleteSNMPDevice — POST /snmp/{id}/delete (admin).
func (a *App) DeleteSNMPDevice(w http.ResponseWriter, r *http.Request) {
	user := auth.CurrentUser(a.DB, r)
	if user == nil || !user.IsAdmin() {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	a.DB.Exec("DELETE FROM snmp_devices WHERE id=?", id)
	a.DB.Exec("DELETE FROM snmp_ports WHERE snmp_device_id=?", id)
	auth.LogAction(a.DB, user.ID, "snmp_delete", strconv.FormatInt(id, 10), "")
	http.Redirect(w, r, "/snmp?message=Устройство+удалено", http.StatusSeeOther)
}

// PollSNMPNow — POST /snmp/{id}/poll : внеплановый опрос (CanWrite).
func (a *App) PollSNMPNow(w http.ResponseWriter, r *http.Request) {
	user := auth.CurrentUser(a.DB, r)
	if !user.CanWrite() {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	var name, ip, comm, kind, prev string
	var port int
	if a.DB.QueryRow(`SELECT COALESCE(name,''), COALESCE(ip,''), COALESCE(port,161),
		COALESCE(community,'public'), COALESCE(kind,'auto'), COALESCE(last_status,'')
		FROM snmp_devices WHERE id=?`, id).Scan(&name, &ip, &port, &comm, &kind, &prev) != nil || ip == "" {
		writeJSON(w, map[string]any{"ok": false, "error": "устройство не найдено"})
		return
	}
	label := name
	if label == "" {
		label = ip
	}
	status := a.pollAndSave(id, ip, uint16(port), comm, kind, prev, label)
	writeJSON(w, map[string]any{"ok": true, "status": status})
}
