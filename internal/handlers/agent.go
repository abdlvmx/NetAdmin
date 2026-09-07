package handlers

import (
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"

	"netadmin/internal/config"
	"netadmin/internal/ingest"
)

// Протокол обмена с агентом рассчитан на работу без шифрования канала.
// Токен устройства по сети НЕ передаётся: он служит только ключом HMAC-SHA256,
// а сервер выбирает ключ по идентификатору устройства из заголовка. Перехват
// трафика поэтому не выдаёт ключа. Ответы сервера подписываются тем же ключом —
// агент не выполнит задачу, пришедшую от постороннего.
const (
	hdrDevice = "X-Agent-Device"    // id устройства (обычный режим)
	hdrEnroll = "X-Agent-Enroll"    // «1» — режим первичной регистрации
	hdrSig    = "X-Agent-Signature" // hex(HMAC-SHA256(ключ, подписываемые данные))
)

const (
	agentClockSkew = 60 * time.Second // допустимое расхождение часов
	nonceTTL       = 3 * time.Minute  // сколько помним nonce (заведомо больше окна свежести)
	maxNonces      = 50000            // потолок кэша, чтобы память не росла без предела
)

// nonceCache — защита от повторного проигрывания запроса (replay). Одной проверки
// времени мало: внутри окна допустимого расхождения часов запрос можно повторить.
type nonceCache struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

var agentNonces = &nonceCache{seen: make(map[string]time.Time)}

// use регистрирует nonce и возвращает false, если такой уже встречался.
func (c *nonceCache) use(nonce string, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, dup := c.seen[nonce]; dup {
		return false
	}
	// подчищаем протухшие; при переполнении сбрасываем кэш целиком — старые
	// запросы всё равно отсекаются проверкой timestamp
	if len(c.seen) >= maxNonces {
		c.seen = make(map[string]time.Time, maxNonces/2)
	} else {
		for k, t := range c.seen {
			if now.Sub(t) > nonceTTL {
				delete(c.seen, k)
			}
		}
	}
	c.seen[nonce] = now
	return true
}

// agentReq — проверенный запрос агента.
type agentReq struct {
	DeviceID int64  // 0 при первичной регистрации
	Enroll   bool   // запрос пришёл с enrollment-токеном
	Key      string // ключ HMAC — им же подписывается ответ
	Body     []byte // тело запроса (для POST)
}

// agentEnvelope — служебные поля, которые агент обязан класть в каждый запрос.
type agentEnvelope struct {
	Timestamp int64  `json:"timestamp"`
	Nonce     string `json:"nonce"`
}

// agentKeys выбирает ключи HMAC, которыми может быть подписан запрос.
//
// У зарегистрированного устройства ключ ровно один — его персональный токен.
// При первичной регистрации подойти может любой действующий: постоянный токен
// из настроек (им пользуются install_agent.bat и скрипты раскатки) или
// одноразовый код. Сам ключ в запросе не передаётся, поэтому какой именно
// подошёл, выясняется проверкой подписи.
func (a *App) agentKeys(r *http.Request) (deviceID int64, enroll bool, keys []string, ok bool) {
	if r.Header.Get(hdrEnroll) != "" {
		if k := config.Load().AgentToken; k != "" {
			keys = append(keys, k)
		}
		keys = append(keys, a.activeEnrollKeys()...)
		if len(keys) == 0 {
			return 0, false, nil, false
		}
		return 0, true, keys, true
	}
	id, err := strconv.ParseInt(r.Header.Get(hdrDevice), 10, 64)
	if err != nil || id <= 0 {
		return 0, false, nil, false
	}
	var tok string
	if a.DB.QueryRow("SELECT COALESCE(agent_token,'') FROM devices WHERE id=?", id).Scan(&tok) != nil || tok == "" {
		return 0, false, nil, false
	}
	return id, false, []string{tok}, true
}

// checkSig сверяет подпись над signed и проверяет свежесть и неповторность
// запроса. Возвращает подошедший ключ: им же подписывается ответ, а по нему же
// видно, каким кодом регистрируется устройство.
func (a *App) checkSig(w http.ResponseWriter, r *http.Request, keys []string, signed []byte, env agentEnvelope) (string, bool) {
	sig := r.Header.Get(hdrSig)
	if sig == "" {
		a.rejectAgent(r, "нет подписи")
		http.Error(w, "signature required", http.StatusForbidden)
		return "", false
	}

	matched := ""
	for _, k := range keys {
		mac := hmac.New(sha256.New, []byte(k))
		mac.Write(signed)
		if hmac.Equal([]byte(sig), []byte(hex.EncodeToString(mac.Sum(nil)))) {
			matched = k
			break
		}
	}
	if matched == "" {
		a.rejectAgent(r, "неверная подпись")
		http.Error(w, "bad signature", http.StatusForbidden)
		return "", false
	}

	if env.Timestamp == 0 {
		a.rejectAgent(r, "нет timestamp")
		http.Error(w, "stale request", http.StatusForbidden)
		return "", false
	}
	now := time.Now()
	if d := now.Sub(time.Unix(env.Timestamp, 0)); d > agentClockSkew || d < -agentClockSkew {
		a.rejectAgent(r, "просроченный timestamp")
		http.Error(w, "stale request", http.StatusForbidden)
		return "", false
	}
	if env.Nonce == "" {
		a.rejectAgent(r, "нет nonce")
		http.Error(w, "nonce required", http.StatusForbidden)
		return "", false
	}
	if !agentNonces.use(env.Nonce, now) {
		a.rejectAgent(r, "повтор запроса (replay)")
		http.Error(w, "replayed request", http.StatusForbidden)
		return "", false
	}
	return matched, true
}

// touchDevice отмечает, что агент только что выходил на связь.
//
// Признак «на связи» намеренно опирается на ЛЮБОЙ запрос агента, а не только
// на heartbeat: heartbeat адаптивный и при стабильной нагрузке приходит редко,
// тогда как за задачами агент обращается каждые 15 секунд. Раньше учитывался
// только heartbeat, и спокойные машины регулярно уезжали в offline.
//
// Условие в WHERE делает запись самоограничивающейся: при опросе раз в 15
// секунд база обновляется не чаще раза в полминуты на устройство.
func (a *App) touchDevice(deviceID int64) {
	if deviceID <= 0 {
		return
	}
	a.DB.Exec(`UPDATE devices SET last_seen=datetime('now'), status='online'
		WHERE id=? AND (last_seen IS NULL OR last_seen < datetime('now','-30 seconds'))`, deviceID)
}

// authAgentPost проверяет POST-запрос агента: подпись над телом, свежесть, nonce.
func (a *App) authAgentPost(w http.ResponseWriter, r *http.Request) (agentReq, bool) {
	deviceID, enroll, keys, ok := a.agentKeys(r)
	if !ok {
		http.Error(w, "unknown agent", http.StatusUnauthorized)
		return agentReq{}, false
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return agentReq{}, false
	}
	var env agentEnvelope
	_ = json.Unmarshal(body, &env)
	key, ok := a.checkSig(w, r, keys, body, env)
	if !ok {
		return agentReq{}, false
	}
	a.touchDevice(deviceID)
	return agentReq{DeviceID: deviceID, Enroll: enroll, Key: key, Body: body}, true
}

// authAgentGet проверяет GET-запрос агента. Тела нет, поэтому подписывается
// метод и полный URI, а timestamp и nonce берутся из query-параметров.
func (a *App) authAgentGet(w http.ResponseWriter, r *http.Request) (agentReq, bool) {
	deviceID, enroll, keys, ok := a.agentKeys(r)
	if !ok {
		http.Error(w, "unknown agent", http.StatusUnauthorized)
		return agentReq{}, false
	}
	ts, _ := strconv.ParseInt(r.URL.Query().Get("ts"), 10, 64)
	env := agentEnvelope{Timestamp: ts, Nonce: r.URL.Query().Get("nonce")}
	key, ok := a.checkSig(w, r, keys, []byte(r.Method+"\n"+r.URL.RequestURI()), env)
	if !ok {
		return agentReq{}, false
	}
	a.touchDevice(deviceID)
	return agentReq{DeviceID: deviceID, Enroll: enroll, Key: key}, true
}

// writeAgentJSON отвечает агенту подписанным JSON. Подпись ответа не даёт
// постороннему навязать агенту задачу — например, установку своего пакета.
func writeAgentJSON(w http.ResponseWriter, key string, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		http.Error(w, "encode error", http.StatusInternalServerError)
		return
	}
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write(b)
	w.Header().Set(hdrSig, hex.EncodeToString(mac.Sum(nil)))
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(b)
}

// rejectAgent фиксирует отклонённый запрос агента как событие безопасности.
// logAgentEvent пишет заметное, но не тревожное событие про агента: оно должно
// остаться в истории устройства, чтобы «почему у машины сменился токен» имело
// ответ.
func (a *App) logAgentEvent(hostname, message string) {
	a.DB.Exec(`INSERT INTO events (hostname, source, event_id, severity, category, message)
		VALUES (?, 'agent', 0, 'info', 'enroll', ?)`, hostname, message)
}

func (a *App) rejectAgent(r *http.Request, reason string) {
	a.DB.Exec(`INSERT INTO events (hostname, source, event_id, severity, category, message)
		VALUES (?, 'security', 0, 'warning', 'replay', ?)`,
		clientIP(r), "Отклонён запрос агента: "+reason)
}

// AgentHeartbeat — POST /api/agent-heartbeat : метрики и, при первом обращении,
// выдача персонального токена устройства.
func (a *App) AgentHeartbeat(w http.ResponseWriter, r *http.Request) {
	ag, ok := a.authAgentPost(w, r)
	if !ok {
		return
	}
	var d struct {
		Hostname     string  `json:"hostname"`
		OS           string  `json:"os"`
		CPU          float64 `json:"cpu"`
		RAM          float64 `json:"ram"`
		Disk         float64 `json:"disk"`
		CPUModel     string  `json:"cpu_model"`
		RAMTotalGB   int     `json:"ram_total_gb"`
		DiskTotalGB  int     `json:"disk_total_gb"`
		OSVersion    string  `json:"os_version"`
		AgentVersion string  `json:"agent_version"`
	}
	if err := json.Unmarshal(ag.Body, &d); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}

	deviceID := ag.DeviceID
	issuedToken := ""
	if ag.Enroll {
		if d.Hostname == "" {
			http.Error(w, "hostname required", http.StatusBadRequest)
			return
		}
		var id int64
		var existing string
		err := a.DB.QueryRow("SELECT id, COALESCE(agent_token,'') FROM devices WHERE hostname=?",
			d.Hostname).Scan(&id, &existing)
		switch {
		case err == sql.ErrNoRows:
			res, e := a.DB.Exec(
				"INSERT INTO devices (hostname, status, last_seen) VALUES (?, 'online', datetime('now'))",
				d.Hostname)
			if e != nil {
				http.Error(w, "db error", http.StatusInternalServerError)
				return
			}
			id, _ = res.LastInsertId()
		case err != nil:
			http.Error(w, "db error", http.StatusInternalServerError)
			return
		case existing != "" && !a.isEnrollCode(ag.Key):
			// У устройства уже есть действующий токен. Перевыпуск по постоянному
			// токену позволил бы перехватить чужое устройство, назвавшись его
			// именем: этот токен есть у всех, кто когда-либо ставил агента.
			a.rejectAgent(r, "повторная регистрация занятого устройства: "+d.Hostname)
			http.Error(w, "device already enrolled", http.StatusConflict)
			return
		case existing != "":
			// А одноразовым кодом — можно: его выдал администратор считаные
			// минуты назад и на считаное число установок, то есть переустановку
			// он и подразумевает. Прежний токен при этом перестаёт работать.
			//
			// Без этого переустановленный агент так и не получал персонального
			// токена и продолжал подписываться кодом — до его истечения, после
			// чего машина уходила в оффлайн при работающем агенте.
			a.logAgentEvent(d.Hostname, "переустановка агента по одноразовому коду")
		}
		issuedToken = randToken()
		if _, e := a.DB.Exec("UPDATE devices SET agent_token=? WHERE id=?", issuedToken, id); e != nil {
			http.Error(w, "db error", http.StatusInternalServerError)
			return
		}
		deviceID = id
		// Установка засчитывается только здесь — по факту выданного токена.
		// Если запрос подписан постоянным токеном, строки с таким кодом нет
		// и обновление никого не трогает.
		a.useEnrollCode(ag.Key)
	}

	// Asset Change Tracking: фиксируем изменения железа/ОС (до обновления)
	a.trackHardwareChanges(deviceID, d.CPUModel, d.OSVersion, d.RAMTotalGB, d.DiskTotalGB)

	// статус/последнее-онлайн + характеристики (пустые/нулевые поля не затирают прежние)
	a.DB.Exec(`UPDATE devices SET os_type=?, status='online', last_seen=datetime('now'),
		cpu_usage=?, ram_usage=?, disk_usage=?,
		cpu_model=CASE WHEN ?<>'' THEN ? ELSE cpu_model END,
		ram_total_gb=CASE WHEN ?>0 THEN ? ELSE ram_total_gb END,
		disk_total_gb=CASE WHEN ?>0 THEN ? ELSE disk_total_gb END,
		os_version=CASE WHEN ?<>'' THEN ? ELSE os_version END,
		agent_version=CASE WHEN ?<>'' THEN ? ELSE agent_version END
		WHERE id=?`,
		d.OS, d.CPU, d.RAM, d.Disk,
		d.CPUModel, d.CPUModel, d.RAMTotalGB, d.RAMTotalGB,
		d.DiskTotalGB, d.DiskTotalGB, d.OSVersion, d.OSVersion,
		d.AgentVersion, d.AgentVersion, deviceID)
	// историю метрик пишем пачкой в фоне (батч + ретеншн в воркере)
	a.Ingest.Metric(ingest.MetricRow{DeviceID: deviceID, CPU: d.CPU, RAM: d.RAM, Disk: d.Disk})

	resp := map[string]any{"ok": true}
	if issuedToken != "" {
		resp["token"] = issuedToken
		resp["device_id"] = deviceID
	}
	writeAgentJSON(w, ag.Key, resp)
}
