package handlers

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"netadmin/internal/config"
	"netadmin/internal/ingest"
)

const agentClockSkew = 60 // допустимое расхождение времени, сек

// resolveAgent определяет, чем авторизован агент:
//   - персональный токен устройства  -> (deviceID, enroll=false, ok=true)
//   - enrollment-токен из настроек    -> (0, enroll=true, ok=true)
//   - иначе                           -> ok=false
func (a *App) resolveAgent(r *http.Request) (deviceID int64, enroll, ok bool) {
	tok := r.Header.Get("X-Agent-Token")
	if tok == "" {
		return 0, false, false
	}
	var id int64
	if a.DB.QueryRow("SELECT id FROM devices WHERE agent_token=? AND COALESCE(agent_token,'')<>''",
		tok).Scan(&id) == nil {
		return id, false, true
	}
	enrollTok := config.Load().AgentToken
	if enrollTok != "" && subtle.ConstantTimeCompare([]byte(tok), []byte(enrollTok)) == 1 {
		return 0, true, true
	}
	return 0, false, false
}

// verifyAgentRequest читает тело и проверяет HMAC-подпись (ключ — токен агента)
// и свежесть timestamp (анти-replay). Возвращает тело и признак успеха.
func (a *App) verifyAgentRequest(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	tok := r.Header.Get("X-Agent-Token")
	body, _ := io.ReadAll(r.Body)

	sig := r.Header.Get("X-Agent-Signature")
	if sig == "" {
		a.rejectAgent(r, "нет подписи")
		http.Error(w, "signature required", http.StatusForbidden)
		return nil, false
	}
	mac := hmac.New(sha256.New, []byte(tok))
	mac.Write(body)
	want := hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(sig), []byte(want)) {
		a.rejectAgent(r, "неверная подпись")
		http.Error(w, "bad signature", http.StatusForbidden)
		return nil, false
	}

	var ts struct {
		Timestamp int64 `json:"timestamp"`
	}
	_ = json.Unmarshal(body, &ts)
	diff := time.Now().Unix() - ts.Timestamp
	if diff < 0 {
		diff = -diff
	}
	if ts.Timestamp == 0 || diff > agentClockSkew {
		a.rejectAgent(r, "просроченный/некорректный timestamp")
		http.Error(w, "stale request", http.StatusForbidden)
		return nil, false
	}
	return body, true
}

// rejectAgent фиксирует отклонённый запрос агента как событие безопасности.
func (a *App) rejectAgent(r *http.Request, reason string) {
	a.DB.Exec(`INSERT INTO events (hostname, source, event_id, severity, category, message)
		VALUES (?, 'security', 0, 'warning', 'replay', ?)`,
		clientIP(r), "Отклонён запрос агента: "+reason)
}

// AgentHeartbeat — POST /api/agent-heartbeat (токен + HMAC-подпись + timestamp).
func (a *App) AgentHeartbeat(w http.ResponseWriter, r *http.Request) {
	deviceID, enroll, ok := a.resolveAgent(r)
	if !ok {
		http.Error(w, "invalid agent token", http.StatusUnauthorized)
		return
	}
	body, ok := a.verifyAgentRequest(w, r)
	if !ok {
		return
	}
	var d struct {
		Hostname    string  `json:"hostname"`
		OS          string  `json:"os"`
		CPU         float64 `json:"cpu"`
		RAM         float64 `json:"ram"`
		Disk        float64 `json:"disk"`
		CPUModel    string  `json:"cpu_model"`
		RAMTotalGB  int     `json:"ram_total_gb"`
		DiskTotalGB int     `json:"disk_total_gb"`
		OSVersion   string  `json:"os_version"`
	}
	if err := json.Unmarshal(body, &d); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}

	issuedToken := ""
	if enroll {
		var id int64
		err := a.DB.QueryRow("SELECT id FROM devices WHERE hostname=?", d.Hostname).Scan(&id)
		if err == sql.ErrNoRows {
			res, e := a.DB.Exec(
				"INSERT INTO devices (hostname, status, last_seen) VALUES (?, 'online', datetime('now'))",
				d.Hostname)
			if e != nil {
				http.Error(w, "db error", http.StatusInternalServerError)
				return
			}
			id, _ = res.LastInsertId()
		} else if err != nil {
			http.Error(w, "db error", http.StatusInternalServerError)
			return
		}
		issuedToken = randToken()
		a.DB.Exec("UPDATE devices SET agent_token=? WHERE id=?", issuedToken, id)
		deviceID = id
	}

	// Asset Change Tracking: фиксируем изменения железа/ОС (до обновления)
	a.trackHardwareChanges(deviceID, d.CPUModel, d.OSVersion, d.RAMTotalGB, d.DiskTotalGB)

	// статус/последнее-онлайн + характеристики (пустые/нулевые поля не затирают прежние)
	a.DB.Exec(`UPDATE devices SET os_type=?, status='online', last_seen=datetime('now'),
		cpu_usage=?, ram_usage=?, disk_usage=?,
		cpu_model=CASE WHEN ?<>'' THEN ? ELSE cpu_model END,
		ram_total_gb=CASE WHEN ?>0 THEN ? ELSE ram_total_gb END,
		disk_total_gb=CASE WHEN ?>0 THEN ? ELSE disk_total_gb END,
		os_version=CASE WHEN ?<>'' THEN ? ELSE os_version END
		WHERE id=?`,
		d.OS, d.CPU, d.RAM, d.Disk,
		d.CPUModel, d.CPUModel, d.RAMTotalGB, d.RAMTotalGB,
		d.DiskTotalGB, d.DiskTotalGB, d.OSVersion, d.OSVersion, deviceID)
	// историю метрик пишем пачкой в фоне (батч + ретеншн в воркере)
	a.Ingest.Metric(ingest.MetricRow{DeviceID: deviceID, CPU: d.CPU, RAM: d.RAM, Disk: d.Disk})

	resp := map[string]any{"ok": true}
	if issuedToken != "" {
		resp["token"] = issuedToken
	}
	writeJSON(w, resp)
}
