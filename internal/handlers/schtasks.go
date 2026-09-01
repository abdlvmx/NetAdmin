package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"netadmin/internal/auth"
)

// AgentSchTasks — POST /api/agent-schtasks : снапшот задач планировщика (токен+HMAC+timestamp).
// Полная замена снапшота; новые/изменённые задачи (path+name+action не встречались)
// фиксируются как warning-событие — способ закрепления вредоносного ПО.
func (a *App) AgentSchTasks(w http.ResponseWriter, r *http.Request) {
	ag, ok := a.authAgentPost(w, r)
	if !ok {
		return
	}
	var p struct {
		Hostname string `json:"hostname"`
		Tasks    []struct {
			Name   string `json:"name"`
			Path   string `json:"path"`
			Action string `json:"action"`
			State  string `json:"state"`
		} `json:"tasks"`
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

	// прежний набор (ключ = path|name|action — смена действия считается новой задачей)
	prev := map[string]bool{}
	had, prevCorrupt := false, false
	if rows, err := a.DB.Query("SELECT path, name, action FROM scheduled_tasks WHERE device_id=?", did); err == nil {
		for rows.Next() {
			var pth, nm, act string
			if rows.Scan(&pth, &nm, &act) == nil {
				key := pth + "|" + nm + "|" + act
				prev[key] = true
				had = true
				if looksMojibake(key) {
					prevCorrupt = true
				}
			}
		}
		rows.Close()
	}

	// полная замена снапшота задач устройства
	tx, err := a.DB.Begin()
	if err != nil {
		http.Error(w, "db error", http.StatusInternalServerError)
		return
	}
	tx.Exec("DELETE FROM scheduled_tasks WHERE device_id=?", did)
	for _, t := range p.Tasks {
		tx.Exec("INSERT INTO scheduled_tasks (device_id, name, path, action, state) VALUES (?,?,?,?,?)",
			did, t.Name, t.Path, t.Action, t.State)
	}
	tx.Commit()

	// новые/изменённые задачи (если снапшот был и не испорчен кодировкой): в историю —
	// всегда (инвентарь), security-событие — только в редакции security.
	if had && !prevCorrupt {
		for _, t := range p.Tasks {
			if prev[t.Path+"|"+t.Name+"|"+t.Action] {
				continue
			}
			label := t.Path + t.Name
			if act := strings.TrimSpace(t.Action); act != "" {
				label += " → " + act
			}
			a.recordDeviceChange(did, "Задача планировщика добавлена", "", label)
		}
	}

	writeAgentJSON(w, ag.Key, map[string]any{"ok": true, "count": len(p.Tasks)})
}

// looksMojibake сообщает, содержит ли строка символ-замену U+FFFD — признак
// данных, испорченных прежней OEM-кодировкой агента (до фикса UTF-8).
func looksMojibake(s string) bool { return strings.ContainsRune(s, '�') }

// DeviceSchTasks — GET /api/devices/{id}/schtasks : задачи планировщика устройства.
func (a *App) DeviceSchTasks(w http.ResponseWriter, r *http.Request) {
	if auth.CurrentUser(a.DB, r) == nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	rows, err := a.DB.Query(`SELECT COALESCE(path,''), COALESCE(name,''), COALESCE(action,''), COALESCE(state,'')
		FROM scheduled_tasks WHERE device_id=? ORDER BY path, name`, id)
	type item struct {
		Path   string `json:"path"`
		Name   string `json:"name"`
		Action string `json:"action"`
		State  string `json:"state"`
	}
	items := []item{}
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var it item
			if rows.Scan(&it.Path, &it.Name, &it.Action, &it.State) == nil {
				items = append(items, it)
			}
		}
	}
	writeJSON(w, map[string]any{"tasks": items})
}
