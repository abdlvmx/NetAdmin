package handlers

import (
	"log"
	"net/http"

	"netadmin/internal/auth"
	"netadmin/internal/tz"
	"netadmin/internal/web"
)

// recordNetChange фиксирует изменение в сети (new|gone|changed) для истории.
func (a *App) recordNetChange(ctype, ip, mac, hostname, vendor, detail string) {
	a.DB.Exec(`INSERT INTO network_changes (change_type, ip, mac, hostname, vendor, detail)
		VALUES (?,?,?,?,?,?)`, ctype, ip, mac, hostname, vendor, detail)
}

type netChangeRow struct {
	Ts, Type, IP, MAC, Hostname, Vendor, Detail string
}

type netChangesPageData struct {
	User                    *auth.User
	Active                  string
	Rows                    []netChangeRow
	New, Gone, Changed, All int
}

// NetworkChangesPage — GET /network-changes : история изменений сети.
func (a *App) NetworkChangesPage(w http.ResponseWriter, r *http.Request) {
	user := auth.CurrentUser(a.DB, r)
	if user == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	data := netChangesPageData{User: user, Active: "network_changes"}

	rows, err := a.DB.Query(`SELECT ts, COALESCE(change_type,''), COALESCE(ip,''), COALESCE(mac,''),
		COALESCE(hostname,''), COALESCE(vendor,''), COALESCE(detail,'')
		FROM network_changes ORDER BY ts DESC LIMIT 500`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var c netChangeRow
			var ts string
			if rows.Scan(&ts, &c.Type, &c.IP, &c.MAC, &c.Hostname, &c.Vendor, &c.Detail) != nil {
				continue
			}
			c.Ts = tz.DateTime(ts)
			switch c.Type {
			case "new":
				data.New++
			case "gone":
				data.Gone++
			case "changed":
				data.Changed++
			}
			data.All++
			data.Rows = append(data.Rows, c)
		}
		if err := rows.Err(); err != nil {
			log.Printf("NetworkChangesPage: %v", err)
		}
	}
	web.RenderPage(w, "network_changes", data)
}
