package handlers

import (
	"log"
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

// knownDevice — запись инвентаря, к которой отнесён результат сканирования.
type knownDevice struct {
	id            int64
	host, mac, ip string
}

// usableMAC возвращает MAC в сравнимом виде или пустую строку, если адрес
// непригоден для сопоставления. Сканер отдаёт «unknown», когда MAC узнать
// не удалось, и по такому значению нельзя объединять разные машины.
func usableMAC(mac string) string {
	m := strings.ToLower(strings.TrimSpace(mac))
	if m == "" || m == "unknown" {
		return ""
	}
	return m
}

// matchScanned подбирает запись инвентаря для найденного при сканировании
// устройства.
//
// Порядок проверок важен:
//
//  1. MAC — самый устойчивый признак. Раньше его не использовали вовсе, и
//     машина, сменившая адрес по DHCP, заводилась в инвентаре повторно.
//  2. IP — обычный случай, адрес не менялся.
//  3. Имя, и только у записей без адреса. Так подхватывается устройство,
//     которое сначала зарегистрировал агент (он IP не сообщает), а затем
//     обнаружил скан. Совпадение по имени намеренно ограничено записями без
//     IP: два разных хоста могут отдать одинаковое NetBIOS-имя, и объединить
//     их было бы хуже, чем оставить дубль. Регистр не учитываем — DNS и
//     NetBIOS возвращают имя не так, как его сообщает агент.
func (a *App) matchScanned(d netscan.ScanResult) (knownDevice, bool) {
	scan := func(query string, arg any) (knownDevice, bool) {
		var k knownDevice
		err := a.DB.QueryRow(query, arg).Scan(&k.id, &k.host, &k.mac, &k.ip)
		return k, err == nil
	}
	const cols = `SELECT id, COALESCE(hostname,''), COALESCE(mac_address,''), COALESCE(ip_address,'') FROM devices `

	if m := usableMAC(d.MAC); m != "" {
		if k, ok := scan(cols+`WHERE LOWER(COALESCE(mac_address,''))=?`, m); ok {
			return k, true
		}
	}
	if d.IP != "" {
		if k, ok := scan(cols+`WHERE ip_address=?`, d.IP); ok {
			return k, true
		}
	}
	if d.Hostname != "" {
		if k, ok := scan(cols+`WHERE COALESCE(ip_address,'')='' AND LOWER(COALESCE(hostname,''))=LOWER(?)`, d.Hostname); ok {
			return k, true
		}
	}
	return knownDevice{}, false
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
		prev, ok := a.matchScanned(d)
		if !ok {
			a.DB.Exec(`INSERT INTO devices (hostname, ip_address, mac_address, manufacturer, os_guess, status, last_seen)
				VALUES (?,?,?,?,?, 'online', datetime('now'))`, d.Hostname, d.IP, d.MAC, d.Vendor, d.OSGuess)
			// история сети: новое устройство (не на первом скане, чтобы не флудить базлайном)
			if existed > 0 {
				a.recordNetChange("new", d.IP, d.MAC, d.Hostname, d.Vendor, "")
			}
			continue
		}

		a.DB.Exec(`UPDATE devices SET status='online', last_seen=datetime('now'),
			hostname=?, ip_address=?, mac_address=?,
			manufacturer=CASE WHEN COALESCE(manufacturer,'')='' THEN ? ELSE manufacturer END,
			os_guess=CASE WHEN ?<>'' THEN ? ELSE os_guess END
			WHERE id=?`, d.Hostname, d.IP, d.MAC, d.Vendor, d.OSGuess, d.OSGuess, prev.id)

		// история сети: смена адреса/имени/MAC у известного устройства
		var parts []string
		if d.IP != "" && prev.ip != "" && d.IP != prev.ip {
			parts = append(parts, "адрес: "+prev.ip+" → "+d.IP)
		}
		if d.Hostname != "" && prev.host != "" && d.Hostname != prev.host {
			parts = append(parts, "имя: "+prev.host+" → "+d.Hostname)
		}
		if nm, om := usableMAC(d.MAC), usableMAC(prev.mac); nm != "" && om != "" && nm != om {
			parts = append(parts, "MAC: "+prev.mac+" → "+d.MAC)
		}
		if len(parts) > 0 {
			a.recordNetChange("changed", d.IP, d.MAC, d.Hostname, d.Vendor, strings.Join(parts, "; "))
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
		if err := rows.Err(); err != nil {
			log.Printf("PerformScan: %v", err)
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
	if err := rows.Err(); err != nil {
		log.Printf("FastPing: %v", err)
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
