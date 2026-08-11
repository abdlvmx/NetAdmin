package handlers

import (
	"database/sql"
	"net/http"
	"strings"

	"netadmin/internal/auth"
	"netadmin/internal/netscan"
)

// Scan — POST /api/scan : ручное сканирование локальной сети.
func (a *App) Scan(w http.ResponseWriter, r *http.Request) {
	user := auth.CurrentUser(a.DB, r)
	if user == nil || !user.CanWrite() {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	found, network := a.PerformScan()
	auth.LogAction(a.DB, user.ID, "network_scan", network, "")
	writeJSON(w, map[string]any{"found": found, "network": network})
}

// PerformScan сканирует сеть, обновляет инвентарь и пишет историю изменений
// сети (новые / исчезнувшие / изменившиеся устройства).
func (a *App) PerformScan() (int, string) {
	// был ли вообще инвентарь (чтобы не флудить историей сети на первом скане)
	existed := 0
	a.DB.QueryRow("SELECT COUNT(*) FROM devices").Scan(&existed)

	network, results := netscan.Scan()
	found := map[string]bool{}
	for _, d := range results {
		found[d.IP] = true
		var id int64
		var oldHost, oldMac string
		err := a.DB.QueryRow("SELECT id, COALESCE(hostname,''), COALESCE(mac_address,'') FROM devices WHERE ip_address=?",
			d.IP).Scan(&id, &oldHost, &oldMac)
		if err == sql.ErrNoRows {
			a.DB.Exec(`INSERT INTO devices (hostname, ip_address, mac_address, manufacturer, os_guess, status, last_seen)
				VALUES (?,?,?,?,?, 'online', datetime('now'))`, d.Hostname, d.IP, d.MAC, d.Vendor, d.OSGuess)
			// история сети: новое устройство (не на первом скане, чтобы не флудить базлайном)
			if existed > 0 {
				a.recordNetChange("new", d.IP, d.MAC, d.Hostname, d.Vendor, "")
			}
		} else if err == nil {
			a.DB.Exec(`UPDATE devices SET status='online', last_seen=datetime('now'),
				hostname=?, mac_address=?,
				manufacturer=CASE WHEN COALESCE(manufacturer,'')='' THEN ? ELSE manufacturer END,
				os_guess=CASE WHEN ?<>'' THEN ? ELSE os_guess END
				WHERE id=?`, d.Hostname, d.MAC, d.Vendor, d.OSGuess, d.OSGuess, id)
			// история сети: смена имени/MAC у известного IP
			var parts []string
			if d.Hostname != "" && oldHost != "" && d.Hostname != oldHost {
				parts = append(parts, "имя: "+oldHost+" → "+d.Hostname)
			}
			nm, om := strings.ToLower(d.MAC), strings.ToLower(oldMac)
			if nm != "" && nm != "unknown" && om != "" && om != "unknown" && nm != om {
				parts = append(parts, "MAC: "+oldMac+" → "+d.MAC)
			}
			if len(parts) > 0 {
				a.recordNetChange("changed", d.IP, d.MAC, d.Hostname, d.Vendor, strings.Join(parts, "; "))
			}
		}
	}

	// устройства, не ответившие на скан, помечаем оффлайн (и фиксируем «исчезло»)
	if rows, err := a.DB.Query("SELECT id, COALESCE(ip_address,''), COALESCE(hostname,''), COALESCE(mac_address,''), COALESCE(status,'') FROM devices"); err == nil {
		type off struct {
			id                  int64
			ip, host, mac, stat string
		}
		var toOffline []off
		for rows.Next() {
			var o off
			if rows.Scan(&o.id, &o.ip, &o.host, &o.mac, &o.stat) == nil && o.ip != "" && !found[o.ip] {
				toOffline = append(toOffline, o)
			}
		}
		rows.Close()
		for _, o := range toOffline {
			a.DB.Exec("UPDATE devices SET status='offline' WHERE id=?", o.id)
			// «исчезло» фиксируем только при переходе online→offline (не повторяем каждый скан)
			if o.stat == "online" {
				a.recordNetChange("gone", o.ip, o.mac, o.host, "", "")
			}
		}
	}
	return len(results), network
}

// FastPing (О-2 fast scan) — быстро пингует уже известные устройства с IP и
// обновляет их статус, не сканируя всю подсеть.
func (a *App) FastPing() {
	rows, err := a.DB.Query("SELECT id, ip_address FROM devices WHERE COALESCE(ip_address,'')<>''")
	if err != nil {
		return
	}
	type dev struct {
		id int64
		ip string
	}
	var list []dev
	for rows.Next() {
		var d dev
		if rows.Scan(&d.id, &d.ip) == nil {
			list = append(list, d)
		}
	}
	rows.Close()
	for _, d := range list {
		status := "offline"
		if netscan.PingHost(d.ip) {
			status = "online"
			a.DB.Exec("UPDATE devices SET status='online', last_seen=datetime('now') WHERE id=?", d.id)
		} else {
			a.DB.Exec("UPDATE devices SET status=? WHERE id=?", status, d.id)
		}
	}
}
