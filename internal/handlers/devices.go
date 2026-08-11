package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"netadmin/internal/auth"
	"netadmin/internal/netscan"
	"netadmin/internal/tz"
	"netadmin/internal/web"
)

type deviceRow struct {
	ID           int64  `json:"id"`
	Hostname     string `json:"hostname"`
	IP           string `json:"ip_address"`
	MAC          string `json:"mac_address"`
	OSType       string `json:"os_type"`
	Status       string `json:"status"`
	LastSeen     string `json:"last_seen"`
	DeviceType   string `json:"device_type"`
	Manufacturer string `json:"manufacturer"`
	Model        string `json:"model"`
	SerialNumber string `json:"serial_number"`
	Location     string `json:"location"`
	Notes        string `json:"notes"`
	EmployeeID   int64  `json:"employee_id"`
	OwnerName    string `json:"-"`
	EmployeeName string `json:"-"`
	HasToken     bool   `json:"-"`
	OSGuess      string `json:"-"`
	OpenPorts    []int  `json:"-"`
	Critical     bool   `json:"critical"`
	Alert        bool   `json:"-"` // оффлайн / перегруз ресурсов / устаревший heartbeat
}

type employeeOpt struct {
	ID   int64
	Name string
	Dept string
}

type devicesData struct {
	User      *auth.User
	Active    string
	Devices   []deviceRow
	Employees []employeeOpt
}

// DevicesPage — GET /devices.
func (a *App) DevicesPage(w http.ResponseWriter, r *http.Request) {
	user := auth.CurrentUser(a.DB, r)
	if user == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	web.RenderPage(w, "devices", devicesData{
		User:      user,
		Active:    "devices",
		Devices:   a.listDevices(),
		Employees: a.listEmployees(),
	})
}

// deviceDetail — расширенные данные одного устройства для страницы /devices/{id}.
type deviceDetail struct {
	deviceRow
	CPUModel    string
	RAMTotalGB  int
	DiskTotalGB int
	OSVersion   string
}

type deviceDetailData struct {
	User      *auth.User
	Active    string
	Device    deviceDetail
	Employees []employeeOpt
	Commands  []cmdDef // готовая библиотека команд для запуска с карточки
}

// DeviceDetailPage — GET /devices/{id} : отдельная страница устройства с вкладками.
func (a *App) DeviceDetailPage(w http.ResponseWriter, r *http.Request) {
	user := auth.CurrentUser(a.DB, r)
	if user == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	d, ok := a.deviceDetailByID(id)
	if !ok {
		http.Redirect(w, r, "/devices?error=Устройство+не+найдено", http.StatusSeeOther)
		return
	}
	web.RenderPage(w, "device_detail", deviceDetailData{
		User:      user,
		Active:    "devices",
		Device:    d,
		Employees: a.listEmployees(),
		Commands:  commandLibrary,
	})
}

func (a *App) deviceDetailByID(id int64) (deviceDetail, bool) {
	var d deviceDetail
	var hasToken, critical int
	var openPorts string
	err := a.DB.QueryRow(`
		SELECT d.id, d.hostname, COALESCE(d.ip_address,''), COALESCE(d.mac_address,''),
		       COALESCE(d.os_type,''), d.status, COALESCE(d.last_seen,''),
		       COALESCE(d.device_type,''), COALESCE(d.manufacturer,''), COALESCE(d.model,''),
		       COALESCE(d.serial_number,''), COALESCE(d.location,''), COALESCE(d.notes,''),
		       COALESCE(d.employee_id,0), COALESCE(u.username,''), COALESCE(e.full_name,''),
		       (COALESCE(d.agent_token,'')<>''), COALESCE(d.os_guess,''), COALESCE(d.open_ports,''),
		       COALESCE(d.critical,0), COALESCE(d.cpu_model,''), COALESCE(d.ram_total_gb,0),
		       COALESCE(d.disk_total_gb,0), COALESCE(d.os_version,'')
		FROM devices d
		LEFT JOIN users u ON d.owner_id=u.id
		LEFT JOIN employees e ON d.employee_id=e.id
		WHERE d.id=?`, id).Scan(
		&d.ID, &d.Hostname, &d.IP, &d.MAC, &d.OSType, &d.Status, &d.LastSeen,
		&d.DeviceType, &d.Manufacturer, &d.Model, &d.SerialNumber, &d.Location, &d.Notes,
		&d.EmployeeID, &d.OwnerName, &d.EmployeeName, &hasToken, &d.OSGuess, &openPorts,
		&critical, &d.CPUModel, &d.RAMTotalGB, &d.DiskTotalGB, &d.OSVersion)
	if err != nil {
		return d, false
	}
	d.HasToken = hasToken == 1
	d.Critical = critical == 1
	for _, s := range strings.Split(openPorts, ",") {
		if n, e := strconv.Atoi(strings.TrimSpace(s)); e == nil {
			d.OpenPorts = append(d.OpenPorts, n)
		}
	}
	d.LastSeen = tz.DateTime(d.LastSeen)
	return d, true
}

func (a *App) listDevices() []deviceRow {
	rows, err := a.DB.Query(`
		SELECT d.id, d.hostname, COALESCE(d.ip_address,''), COALESCE(d.mac_address,''),
		       COALESCE(d.os_type,''), d.status, COALESCE(d.last_seen,''),
		       COALESCE(d.device_type,''), COALESCE(d.manufacturer,''), COALESCE(d.model,''),
		       COALESCE(d.serial_number,''), COALESCE(d.location,''), COALESCE(d.notes,''),
		       COALESCE(d.employee_id,0), COALESCE(u.username,''), COALESCE(e.full_name,''),
		       (COALESCE(d.agent_token,'')<>''), COALESCE(d.os_guess,''), COALESCE(d.open_ports,''),
		       COALESCE(d.critical,0),
		       (d.status='offline' OR d.cpu_usage>=90 OR d.ram_usage>=90 OR d.disk_usage>=90
		         OR (d.last_seen IS NOT NULL AND d.last_seen < datetime('now','-10 minutes')))
		FROM devices d
		LEFT JOIN users u ON d.owner_id=u.id
		LEFT JOIN employees e ON d.employee_id=e.id
		ORDER BY d.created_at DESC`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []deviceRow
	for rows.Next() {
		var d deviceRow
		var hasToken, critical, alert int
		var openPorts string
		if rows.Scan(&d.ID, &d.Hostname, &d.IP, &d.MAC, &d.OSType, &d.Status, &d.LastSeen,
			&d.DeviceType, &d.Manufacturer, &d.Model, &d.SerialNumber, &d.Location, &d.Notes,
			&d.EmployeeID, &d.OwnerName, &d.EmployeeName, &hasToken, &d.OSGuess, &openPorts, &critical, &alert) != nil {
			continue
		}
		d.HasToken = hasToken == 1
		d.Alert = alert == 1
		d.Critical = critical == 1
		for _, s := range strings.Split(openPorts, ",") {
			if n, e := strconv.Atoi(strings.TrimSpace(s)); e == nil {
				d.OpenPorts = append(d.OpenPorts, n)
			}
		}
		d.LastSeen = tz.DateTime(d.LastSeen)
		out = append(out, d)
	}
	return out
}

func (a *App) listEmployees() []employeeOpt {
	rows, err := a.DB.Query(`
		SELECT e.id, e.full_name, COALESCE(d.name,'')
		FROM employees e LEFT JOIN departments d ON e.department_id=d.id
		WHERE e.is_active=1 ORDER BY e.full_name`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []employeeOpt
	for rows.Next() {
		var e employeeOpt
		if rows.Scan(&e.ID, &e.Name, &e.Dept) == nil {
			out = append(out, e)
		}
	}
	return out
}

// boolParam: значение чекбокса формы → 0/1.
func boolParam(v string) int {
	if v != "" && v != "0" && v != "false" {
		return 1
	}
	return 0
}

// employeeParam возвращает значение для столбца employee_id (NULL если пусто).
func employeeParam(v string) any {
	if id, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil && id > 0 {
		return id
	}
	return nil
}

// CreateDevice — POST /devices/create.
func (a *App) CreateDevice(w http.ResponseWriter, r *http.Request) {
	user := auth.CurrentUser(a.DB, r)
	if user == nil || !user.CanWrite() {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	_ = r.ParseForm()
	f := r.FormValue
	_, err := a.DB.Exec(`
		INSERT INTO devices (hostname, ip_address, mac_address, os_type, employee_id, last_seen,
			device_type, manufacturer, model, serial_number, location, notes, critical)
		VALUES (?,?,?,?,?, datetime('now'), ?,?,?,?,?,?,?)`,
		strings.TrimSpace(f("hostname")), strings.TrimSpace(f("ip_address")),
		strings.TrimSpace(f("mac_address")), strings.TrimSpace(f("os_type")),
		employeeParam(f("employee_id")),
		strings.TrimSpace(f("device_type")), strings.TrimSpace(f("manufacturer")),
		strings.TrimSpace(f("model")), strings.TrimSpace(f("serial_number")),
		strings.TrimSpace(f("location")), strings.TrimSpace(f("notes")), boolParam(f("critical")))
	if err == nil {
		auth.LogAction(a.DB, user.ID, "create_device", f("hostname"), "")
	}
	http.Redirect(w, r, "/devices", http.StatusSeeOther)
}

// UpdateDevice — POST /devices/{id}/update.
func (a *App) UpdateDevice(w http.ResponseWriter, r *http.Request) {
	user := auth.CurrentUser(a.DB, r)
	if user == nil || !user.CanWrite() {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	_ = r.ParseForm()
	f := r.FormValue
	_, err := a.DB.Exec(`
		UPDATE devices SET hostname=?, ip_address=?, mac_address=?, os_type=?, employee_id=?,
			device_type=?, manufacturer=?, model=?, serial_number=?, location=?, notes=?, critical=?
		WHERE id=?`,
		strings.TrimSpace(f("hostname")), strings.TrimSpace(f("ip_address")),
		strings.TrimSpace(f("mac_address")), strings.TrimSpace(f("os_type")),
		employeeParam(f("employee_id")),
		strings.TrimSpace(f("device_type")), strings.TrimSpace(f("manufacturer")),
		strings.TrimSpace(f("model")), strings.TrimSpace(f("serial_number")),
		strings.TrimSpace(f("location")), strings.TrimSpace(f("notes")), boolParam(f("critical")), id)
	if err == nil {
		auth.LogAction(a.DB, user.ID, "update_device", f("hostname"), "")
	}
	http.Redirect(w, r, redirectAfter(r, "/devices"), http.StatusSeeOther)
}

// redirectAfter — куда вернуться после действия: безопасный локальный путь из поля
// формы `redirect` (например, обратно на страницу устройства), иначе значение по умолчанию.
func redirectAfter(r *http.Request, def string) string {
	t := r.FormValue("redirect")
	if strings.HasPrefix(t, "/") && !strings.HasPrefix(t, "//") {
		return t
	}
	return def
}

// DeleteDevice — POST /devices/{id}/delete (только admin).
func (a *App) DeleteDevice(w http.ResponseWriter, r *http.Request) {
	user := auth.CurrentUser(a.DB, r)
	if user == nil || user.Role != "admin" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	var host string
	_ = a.DB.QueryRow("SELECT hostname FROM devices WHERE id=?", id).Scan(&host)
	if _, err := a.DB.Exec("DELETE FROM devices WHERE id=?", id); err == nil {
		auth.LogAction(a.DB, user.ID, "delete_device", host, "")
	}
	http.Redirect(w, r, "/devices", http.StatusSeeOther)
}

// ScanPorts — POST /devices/{id}/scan-ports : скан критичных портов (user/admin).
func (a *App) ScanPorts(w http.ResponseWriter, r *http.Request) {
	user := auth.CurrentUser(a.DB, r)
	if user == nil || !user.CanWrite() {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	var ip, host string
	_ = a.DB.QueryRow("SELECT COALESCE(ip_address,''), hostname FROM devices WHERE id=?", id).Scan(&ip, &host)
	if ip == "" {
		writeJSON(w, map[string]any{"ok": false, "error": "у устройства нет IP"})
		return
	}
	ports := netscan.ScanPorts(ip)
	parts := make([]string, len(ports))
	for i, p := range ports {
		parts[i] = strconv.Itoa(p)
	}
	joined := strings.Join(parts, ",")
	a.DB.Exec("UPDATE devices SET open_ports=? WHERE id=?", joined, id)
	auth.LogAction(a.DB, user.ID, "scan_ports", host, joined)
	writeJSON(w, map[string]any{"ok": true, "ports": ports})
}

// RevokeAgentToken — POST /devices/{id}/agent-token/revoke (admin):
// сбрасывает персональный токен устройства; агент перерегистрируется
// (получит новый токен) при следующем heartbeat по enrollment-токену.
func (a *App) RevokeAgentToken(w http.ResponseWriter, r *http.Request) {
	user := auth.CurrentUser(a.DB, r)
	if user == nil || user.Role != "admin" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	var host string
	_ = a.DB.QueryRow("SELECT hostname FROM devices WHERE id=?", id).Scan(&host)
	a.DB.Exec("UPDATE devices SET agent_token=NULL WHERE id=?", id)
	auth.LogAction(a.DB, user.ID, "revoke_agent_token", host, "")
	http.Redirect(w, r, redirectAfter(r, "/devices"), http.StatusSeeOther)
}

// Ping — POST /api/ping {ip} : пингует и обновляет статус.
func (a *App) Ping(w http.ResponseWriter, r *http.Request) {
	if u := auth.CurrentUser(a.DB, r); u == nil || !u.CanWrite() {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	var body struct {
		IP string `json:"ip"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	status := "offline"
	if netscan.PingHost(body.IP) {
		status = "online"
	}
	_, _ = a.DB.Exec("UPDATE devices SET status=?, last_seen=datetime('now') WHERE ip_address=?",
		status, body.IP)
	writeJSON(w, map[string]any{"ip": body.IP, "status": status})
}

// DeviceMetrics — GET /api/devices/{id}/metrics?hours=N : история нагрузки устройства.
func (a *App) DeviceMetrics(w http.ResponseWriter, r *http.Request) {
	if auth.CurrentUser(a.DB, r) == nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	hours := parseHours(r)
	points := a.metricSeries(id, hours, metricsBucketSeconds(hours))
	writeJSON(w, map[string]any{"hours": hours, "points": points})
}
