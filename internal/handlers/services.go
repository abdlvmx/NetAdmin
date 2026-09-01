package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"netadmin/internal/auth"
)

// AgentServices — POST /api/agent-services : снапшот служб хоста (токен+HMAC+timestamp).
// Полная замена списка служб устройства; новые службы (которых не было в прошлом
// снапшоте) фиксируются как warning-событие. Быстрый критический детект новой
// службы обеспечивает событие 7045 из журнала — это инвентарь-бэкстоп.
func (a *App) AgentServices(w http.ResponseWriter, r *http.Request) {
	ag, ok := a.authAgentPost(w, r)
	if !ok {
		return
	}
	var p struct {
		Hostname string `json:"hostname"`
		Services []struct {
			Name        string `json:"name"`
			DisplayName string `json:"display_name"`
			StartType   string `json:"start_type"`
			Path        string `json:"path"`
		} `json:"services"`
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

	// прежний набор имён служб (для детекта новых)
	prev := map[string]bool{}
	had := false
	if rows, err := a.DB.Query("SELECT name FROM services WHERE device_id=?", did); err == nil {
		for rows.Next() {
			var n string
			if rows.Scan(&n) == nil {
				prev[n] = true
				had = true
			}
		}
		rows.Close()
	}

	// полная замена снапшота служб устройства
	tx, err := a.DB.Begin()
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	tx.Exec("DELETE FROM services WHERE device_id=?", did)
	for _, s := range p.Services {
		tx.Exec("INSERT INTO services (device_id, name, display_name, start_type, path) VALUES (?,?,?,?,?)",
			did, s.Name, s.DisplayName, s.StartType, s.Path)
	}
	tx.Commit()

	// новые службы (если снапшот уже был): в историю изменений — всегда (инвентарь),
	// security-событие — только в редакции security.
	if had {
		for _, s := range p.Services {
			if s.Name == "" || prev[s.Name] {
				continue
			}
			name := s.DisplayName
			if name == "" {
				name = s.Name
			}
			label := name
			if s.Path != "" {
				label += " (" + s.Path + ")"
			}
			a.recordDeviceChange(did, "Служба добавлена", "", label)
		}
	}

	writeAgentJSON(w, ag.Key, map[string]any{"ok": true, "count": len(p.Services)})
}

// DeviceServices — GET /api/devices/{id}/services : список служб устройства.
func (a *App) DeviceServices(w http.ResponseWriter, r *http.Request) {
	if auth.CurrentUser(a.DB, r) == nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	rows, err := a.DB.Query(`SELECT COALESCE(display_name,''), COALESCE(name,''),
		COALESCE(start_type,''), COALESCE(path,'')
		FROM services WHERE device_id=? ORDER BY display_name, name`, id)
	type item struct {
		DisplayName string `json:"display_name"`
		Name        string `json:"name"`
		StartType   string `json:"start_type"`
		Path        string `json:"path"`
	}
	items := []item{}
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var it item
			if rows.Scan(&it.DisplayName, &it.Name, &it.StartType, &it.Path) == nil {
				items = append(items, it)
			}
		}
	}
	writeJSON(w, map[string]any{"services": items})
}
