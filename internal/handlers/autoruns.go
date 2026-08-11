package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"netadmin/internal/auth"
)

// AgentAutoruns — POST /api/agent-autoruns : снапшот точек автозапуска (токен+HMAC+timestamp).
// Полная замена снапшота; новые записи (location+name+command не встречались ранее)
// фиксируются как warning-событие — типичный способ закрепления вредоносного ПО.
func (a *App) AgentAutoruns(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := a.resolveAgent(r); !ok {
		http.Error(w, "invalid agent token", http.StatusUnauthorized)
		return
	}
	body, ok := a.verifyAgentRequest(w, r)
	if !ok {
		return
	}
	var p struct {
		Hostname string `json:"hostname"`
		Autoruns []struct {
			Location string `json:"location"`
			Name     string `json:"name"`
			Command  string `json:"command"`
		} `json:"autoruns"`
	}
	if err := json.Unmarshal(body, &p); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}

	var did int64
	if a.DB.QueryRow("SELECT id FROM devices WHERE hostname=?", p.Hostname).Scan(&did) != nil || did == 0 {
		writeJSON(w, map[string]any{"ok": true, "skipped": "unknown host"})
		return
	}

	// прежний набор (ключ = location|name|command — смена команды считается новой записью)
	prev := map[string]bool{}
	had, prevCorrupt := false, false
	if rows, err := a.DB.Query("SELECT location, name, command FROM autoruns WHERE device_id=?", did); err == nil {
		for rows.Next() {
			var loc, nm, cmd string
			if rows.Scan(&loc, &nm, &cmd) == nil {
				key := loc + "|" + nm + "|" + cmd
				prev[key] = true
				had = true
				if looksMojibake(key) {
					prevCorrupt = true
				}
			}
		}
		rows.Close()
	}

	// полная замена снапшота автозагрузки устройства
	tx, err := a.DB.Begin()
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	tx.Exec("DELETE FROM autoruns WHERE device_id=?", did)
	for _, e := range p.Autoruns {
		tx.Exec("INSERT INTO autoruns (device_id, location, name, command) VALUES (?,?,?,?)",
			did, e.Location, e.Name, e.Command)
	}
	tx.Commit()

	// новые записи (если снапшот был и не испорчен кодировкой): в историю — всегда
	// (инвентарь конфигурации), security-событие — только в редакции security.
	if had && !prevCorrupt {
		for _, e := range p.Autoruns {
			if prev[e.Location+"|"+e.Name+"|"+e.Command] {
				continue
			}
			label := e.Name + " → " + e.Command + " (" + e.Location + ")"
			a.recordDeviceChange(did, "Автозагрузка добавлена", "", label)
		}
	}

	writeJSON(w, map[string]any{"ok": true, "count": len(p.Autoruns)})
}

// DeviceAutoruns — GET /api/devices/{id}/autoruns : точки автозапуска устройства.
func (a *App) DeviceAutoruns(w http.ResponseWriter, r *http.Request) {
	if auth.CurrentUser(a.DB, r) == nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	rows, err := a.DB.Query(`SELECT COALESCE(location,''), COALESCE(name,''), COALESCE(command,'')
		FROM autoruns WHERE device_id=? ORDER BY location, name`, id)
	type item struct {
		Location string `json:"location"`
		Name     string `json:"name"`
		Command  string `json:"command"`
	}
	items := []item{}
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var it item
			if rows.Scan(&it.Location, &it.Name, &it.Command) == nil {
				items = append(items, it)
			}
		}
	}
	writeJSON(w, map[string]any{"autoruns": items})
}
