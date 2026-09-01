package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"netadmin/internal/auth"
)

// AgentSoftware — POST /api/agent-software : инвентарь ПО хоста (токен+HMAC+timestamp).
func (a *App) AgentSoftware(w http.ResponseWriter, r *http.Request) {
	ag, ok := a.authAgentPost(w, r)
	if !ok {
		return
	}
	var p struct {
		Hostname string `json:"hostname"`
		Software []struct {
			Name        string `json:"name"`
			Version     string `json:"version"`
			InstallDate string `json:"install_date"`
		} `json:"software"`
	}
	if err := json.Unmarshal(ag.Body, &p); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}

	// устройство определяется подписью запроса, а не полем в теле: иначе агент
	// одной машины мог бы переписать инвентарь другой, назвавшись её именем
	did := ag.DeviceID
	if did == 0 {
		writeAgentJSON(w, ag.Key, map[string]any{"ok": true, "skipped": "not enrolled"})
		return
	}

	// прежний набор имён (для детекта нового ПО)
	prev := map[string]bool{}
	had := false
	if rows, err := a.DB.Query("SELECT name FROM software WHERE device_id=?", did); err == nil {
		for rows.Next() {
			var n string
			if rows.Scan(&n) == nil {
				prev[n] = true
				had = true
			}
		}
		rows.Close()
	}

	// полная замена списка ПО устройства
	tx, err := a.DB.Begin()
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	tx.Exec("DELETE FROM software WHERE device_id=?", did)
	for _, s := range p.Software {
		tx.Exec("INSERT INTO software (device_id, name, version, install_date) VALUES (?,?,?,?)",
			did, s.Name, s.Version, s.InstallDate)
	}
	tx.Commit()

	// Asset Change Tracking: установленное/удалённое ПО (только если инвентарь уже был).
	// История пишется всегда; security-событие — только в редакции security.
	if had {
		cur := map[string]bool{}
		for _, s := range p.Software {
			if s.Name != "" {
				cur[s.Name] = true
			}
		}
		for _, s := range p.Software {
			if s.Name == "" || prev[s.Name] {
				continue
			}
			a.recordDeviceChange(did, "ПО установлено", "", s.Name)
		}
		for name := range prev {
			if !cur[name] {
				a.recordDeviceChange(did, "ПО удалено", name, "")
			}
		}
	}

	writeAgentJSON(w, ag.Key, map[string]any{"ok": true, "count": len(p.Software)})
}

// DeviceSoftware — GET /api/devices/{id}/software : список ПО устройства.
func (a *App) DeviceSoftware(w http.ResponseWriter, r *http.Request) {
	if auth.CurrentUser(a.DB, r) == nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	rows, err := a.DB.Query(`SELECT COALESCE(name,''), COALESCE(version,''), COALESCE(install_date,'')
		FROM software WHERE device_id=? ORDER BY name`, id)
	type item struct {
		Name        string `json:"name"`
		Version     string `json:"version"`
		InstallDate string `json:"install_date"`
	}
	items := []item{}
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var it item
			if rows.Scan(&it.Name, &it.Version, &it.InstallDate) == nil {
				items = append(items, it)
			}
		}
	}
	writeJSON(w, map[string]any{"software": items})
}
