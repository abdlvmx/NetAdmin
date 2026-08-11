package handlers

import (
	"net/http"
	"strings"

	"netadmin/internal/auth"
	"netadmin/internal/netscan"
	"netadmin/internal/tz"
	"netadmin/internal/web"
)

// NetworkMapPage — GET /network-map.
func (a *App) NetworkMapPage(w http.ResponseWriter, r *http.Request) {
	user := auth.CurrentUser(a.DB, r)
	if user == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	web.RenderPage(w, "network_map", map[string]any{"User": user, "Active": "network_map"})
}

// NetworkMapAPI — GET /api/network-map : узлы для карты (тип, статус, важность).
func (a *App) NetworkMapAPI(w http.ResponseWriter, r *http.Request) {
	if auth.CurrentUser(a.DB, r) == nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	type node struct {
		Hostname string `json:"hostname"`
		IP       string `json:"ip"`
		MAC      string `json:"mac"`
		Vendor   string `json:"vendor"`
		Status   string `json:"status"` // online | stale | offline | unknown
		Type     string `json:"type"`   // pc|server|phone|camera|ap|printer|network|other
		LastSeen string `json:"last_seen"`
		Critical bool   `json:"critical"`
		Subnet   string `json:"subnet"`
	}

	rows, err := a.DB.Query(`SELECT hostname, COALESCE(ip_address,''), COALESCE(mac_address,''),
		COALESCE(manufacturer,''), COALESCE(device_type,''), COALESCE(os_type,''), COALESCE(os_guess,''),
		COALESCE(open_ports,''), COALESCE(critical,0), COALESCE(last_seen,''),
		CASE
		  WHEN COALESCE(status,'')='offline' THEN 'offline'
		  WHEN COALESCE(status,'')='online' AND last_seen IS NOT NULL AND last_seen < datetime('now','-15 minutes') THEN 'stale'
		  WHEN COALESCE(status,'')='online' THEN 'online'
		  ELSE 'unknown'
		END
		FROM devices ORDER BY hostname`)
	nodes := []node{}
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var n node
			var dtype, osType, osGuess, ports, lastRaw string
			var crit int
			if rows.Scan(&n.Hostname, &n.IP, &n.MAC, &n.Vendor, &dtype, &osType, &osGuess,
				&ports, &crit, &lastRaw, &n.Status) != nil {
				continue
			}
			n.Type = inferDeviceType(dtype, osType+" "+osGuess, n.Vendor, n.Hostname, ports)
			n.Critical = crit == 1
			n.LastSeen = tz.DateTime(lastRaw)
			n.Subnet = subnetOf(n.IP)
			nodes = append(nodes, n)
		}
	}

	gateway := "Сеть"
	if ip, ok := netscan.LocalIPv4(); ok {
		if p := strings.Split(ip, "."); len(p) == 4 {
			gateway = p[0] + "." + p[1] + "." + p[2] + ".1"
		}
	}
	writeJSON(w, map[string]any{"gateway": gateway, "nodes": nodes})
}

func subnetOf(ip string) string {
	if p := strings.Split(ip, "."); len(p) == 4 {
		return p[0] + "." + p[1] + "." + p[2] + ".0/24"
	}
	return ""
}

func anyContains(s string, subs ...string) bool {
	for _, x := range subs {
		if strings.Contains(s, x) {
			return true
		}
	}
	return false
}

// inferDeviceType определяет тип устройства: сперва ручной device_type, затем
// эвристика по вендору/ОС/портам/имени. Возвращает канонический ключ типа.
func inferDeviceType(dtype, os, vendor, hostname, ports string) string {
	d := strings.ToLower(dtype)
	switch {
	case anyContains(d, "сервер", "server"):
		return "server"
	case anyContains(d, "коммут", "switch"):
		return "network"
	case anyContains(d, "точк", "wi-fi", "wifi", "access"):
		return "ap"
	case anyContains(d, "камер", "camera"):
		return "camera"
	case anyContains(d, "принтер", "printer", "мфу"):
		return "printer"
	case anyContains(d, "телефон", "phone", "смартфон"):
		return "phone"
	case anyContains(d, "ноут", "пк", "pc", "laptop", "desktop", "рабоч"):
		return "pc"
	}
	v := strings.ToLower(vendor)
	h := strings.ToLower(hostname)
	o := strings.ToLower(os)
	switch {
	case anyContains(v, "hewlett", "hp inc", "canon", "epson", "kyocera", "brother", "xerox", "ricoh", "pantum") ||
		anyContains(ports, "9100", "515", "631"):
		return "printer"
	case anyContains(v, "hikvision", "dahua", "hangzhou", "axis comm", "uniview", "ezviz") || anyContains(h, "cam", "camera", "dvr", "nvr"):
		return "camera"
	case anyContains(v, "cisco", "mikrotik", "tp-link", "ubiquiti", "zyxel", "d-link", "juniper", "aruba", "netgear", "keenetic", "eltex", "huawei tech"):
		return "network"
	case anyContains(v, "xiaomi", "samsung", "oneplus", "oppo", "vivo", "realme", "honor", "tecno"):
		return "phone"
	case anyContains(o, "server"):
		return "server"
	case anyContains(o, "windows", "linux", "macos", "ubuntu", "debian", "android"):
		if anyContains(o, "android") {
			return "phone"
		}
		return "pc"
	}
	return "other"
}
