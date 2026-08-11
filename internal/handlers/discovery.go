package handlers

import (
	"net/http"
	"strconv"
	"strings"
	"sync"

	"netadmin/internal/auth"
	"netadmin/internal/netscan"
	"netadmin/internal/tz"
	"netadmin/internal/web"
)

// DiscoverPassive читает ARP-кэш ОС (пассивно, без активного скана) и складывает
// ранее неизвестные MAC в очередь обнаружения. Вызывается фоново раз в минуту.
// Обратное разрешение имён для новых хостов идёт параллельно (пул), чтобы первый
// прогон с десятками хостов не блокировал фоновую горутину на минуты.
func (a *App) DiscoverPassive() {
	arp := netscan.ARPTable()
	if len(arp) == 0 {
		return
	}
	known := map[string]bool{}
	if rows, err := a.DB.Query("SELECT LOWER(COALESCE(mac_address,'')) FROM devices WHERE COALESCE(mac_address,'')<>''"); err == nil {
		for rows.Next() {
			var m string
			if rows.Scan(&m) == nil {
				known[m] = true
			}
		}
		rows.Close()
	}

	// собрать новые MAC; у уже известных в очереди обновить last_seen (быстро)
	type cand struct{ ip, mac, host string }
	var cands []cand
	for ip, mac := range arp {
		mac = strings.ToLower(mac)
		if !validUnicastMAC(mac) || known[mac] {
			continue
		}
		var id int64
		if a.DB.QueryRow("SELECT id FROM discovery_queue WHERE mac=?", mac).Scan(&id) == nil {
			a.DB.Exec("UPDATE discovery_queue SET last_seen=datetime('now'), ip=? WHERE id=?", ip, id)
			continue
		}
		cands = append(cands, cand{ip: ip, mac: mac})
	}
	if len(cands) == 0 {
		return
	}

	// параллельное обратное разрешение имён (пул 16)
	sem := make(chan struct{}, 16)
	var wg sync.WaitGroup
	for i := range cands {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			if h := netscan.ResolveHost(cands[i].ip); h != cands[i].ip {
				cands[i].host = h
			}
		}(i)
	}
	wg.Wait()

	for _, c := range cands {
		a.DB.Exec(`INSERT OR IGNORE INTO discovery_queue (ip, mac, hostname, vendor, method, status)
			VALUES (?,?,?,?, 'arp', 'new')`, c.ip, c.mac, c.host, netscan.VendorByMAC(c.mac))
	}
}

// validUnicastMAC отсекает широковещательные/мультикаст/нулевые MAC.
func validUnicastMAC(mac string) bool {
	if mac == "" || mac == "ff:ff:ff:ff:ff:ff" || mac == "00:00:00:00:00:00" || mac == "unknown" {
		return false
	}
	if strings.HasPrefix(mac, "01:00:5e") || strings.HasPrefix(mac, "33:33") {
		return false
	}
	return true
}

type discoveryRow struct {
	ID                                                             int64
	IP, MAC, Hostname, Vendor, Method, FirstSeen, LastSeen, Status string
}

type discoveryPageData struct {
	User       *auth.User
	Active     string
	Rows       []discoveryRow
	New, Total int
	Msg        string
}

// DiscoveryPage — GET /discovery : очередь обнаруженных устройств.
func (a *App) DiscoveryPage(w http.ResponseWriter, r *http.Request) {
	user := auth.CurrentUser(a.DB, r)
	if user == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	data := discoveryPageData{User: user, Active: "discovery", Msg: r.URL.Query().Get("message")}
	rows, err := a.DB.Query(`SELECT id, COALESCE(ip,''), COALESCE(mac,''), COALESCE(hostname,''),
		COALESCE(vendor,''), COALESCE(method,''), COALESCE(first_seen,''), COALESCE(last_seen,''), COALESCE(status,'new')
		FROM discovery_queue ORDER BY (status='new') DESC, last_seen DESC LIMIT 500`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var d discoveryRow
			var first, last string
			if rows.Scan(&d.ID, &d.IP, &d.MAC, &d.Hostname, &d.Vendor, &d.Method, &first, &last, &d.Status) != nil {
				continue
			}
			d.FirstSeen = tz.DateTime(first)
			d.LastSeen = tz.DateTime(last)
			if d.Status == "new" {
				data.New++
			}
			data.Total++
			data.Rows = append(data.Rows, d)
		}
	}
	web.RenderPage(w, "discovery", data)
}

// DiscoveryAction — POST /discovery/{id}/action : добавить/игнорировать/гость (user/admin).
func (a *App) DiscoveryAction(w http.ResponseWriter, r *http.Request) {
	user := auth.CurrentUser(a.DB, r)
	if user == nil || !user.CanWrite() {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	_ = r.ParseForm()
	action := r.FormValue("action")

	var ip, mac, host, vendor string
	if a.DB.QueryRow(`SELECT COALESCE(ip,''), COALESCE(mac,''), COALESCE(hostname,''), COALESCE(vendor,'')
		FROM discovery_queue WHERE id=?`, id).Scan(&ip, &mac, &host, &vendor) != nil {
		http.Redirect(w, r, "/discovery", http.StatusSeeOther)
		return
	}

	switch action {
	case "add":
		var exists int
		a.DB.QueryRow("SELECT 1 FROM devices WHERE LOWER(COALESCE(mac_address,''))=? LIMIT 1",
			strings.ToLower(mac)).Scan(&exists)
		if exists != 1 {
			hn := host
			if hn == "" {
				hn = ip
			}
			a.DB.Exec(`INSERT INTO devices (hostname, ip_address, mac_address, manufacturer, status, last_seen)
				VALUES (?,?,?,?, 'online', datetime('now'))`, hn, ip, mac, vendor)
		}
		a.DB.Exec("UPDATE discovery_queue SET status='added' WHERE id=?", id)
		auth.LogAction(a.DB, user.ID, "discovery_add", ip, mac)
	case "ignore":
		a.DB.Exec("UPDATE discovery_queue SET status='ignored' WHERE id=?", id)
	case "guest":
		a.DB.Exec("UPDATE discovery_queue SET status='guest' WHERE id=?", id)
	}
	http.Redirect(w, r, "/discovery?message=Готово", http.StatusSeeOther)
}
