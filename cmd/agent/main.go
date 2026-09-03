// Команда agent — NetAdmin агент: heartbeat (gopsutil) + инвентарь ПО/служб/
// автозагрузки/задач планировщика. Инвентарь конфигурации работает только на
// Windows. На прочих ОС агент шлёт только heartbeat.
package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/mem"
)

// agentVersion — версия сборки агента. Уходит в heartbeat, чтобы на сервере
// было видно, какие машины ещё не обновились.
const agentVersion = "1.1.0"

var (
	serverURL = normalizeServerURL(envOr("NETADMIN_SERVER_URL", "http://127.0.0.1:8765"))
	token     = os.Getenv("NETADMIN_AGENT_TOKEN") // enrollment-токен, только для первой регистрации
)

// normalizeServerURL достраивает адрес сервера до пригодного для запроса вида.
//
// Адрес вписывают руками в install_agent.bat на каждой машине, и «192.168.1.64»
// вместо «http://192.168.1.64:8765» — самая частая опечатка: агент запускается,
// но каждый запрос падает с «unsupported protocol scheme». Ошибка молчаливая и
// повторяется на всём парке, поэтому проще достроить адрес, чем ловить её.
//
// Схема по умолчанию http (TLS в продукте нет), порт по умолчанию 8765.
func normalizeServerURL(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimRight(s, "/") // иначе в пути получится двойной слеш
	if s == "" {
		return "http://127.0.0.1:8765"
	}
	if !strings.Contains(s, "://") {
		s = "http://" + s
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return s // не разобрали — оставляем как есть, ошибка вылезет при запросе
	}
	if u.Port() == "" {
		u.Host = net.JoinHostPort(u.Hostname(), "8765")
	}
	return u.String()
}

// Заголовки протокола. Токен по сети не передаётся — он лишь ключ HMAC,
// а сервер выбирает ключ по идентификатору устройства.
const (
	hdrDevice = "X-Agent-Device"
	hdrEnroll = "X-Agent-Enroll"
	hdrSig    = "X-Agent-Signature"
)

// maxRespBytes — потолок ответа сервера, чтобы подставной сервер не выел память.
const maxRespBytes = 4 << 20

// HTTP-клиент для связи с сервером. Только локальная сеть, обычный HTTP:
// подлинность и целостность обмена обеспечивает HMAC-подпись, не транспорт.
var httpClient = &http.Client{
	Timeout: 10 * time.Second,
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func statePath() string {
	dir, err := os.Executable()
	if err != nil {
		return "agent_state.json"
	}
	return filepath.Join(filepath.Dir(dir), "agent_state.json")
}

type agentState struct {
	DeviceID     int64  `json:"device_id"`     // идентификатор устройства на сервере
	DeviceToken  string `json:"device_token"`  // персональный токен, выданный сервером
	LastSoftware string `json:"last_software"` // когда последний раз слали инвентарь ПО
	LastServices string `json:"last_services"` // когда последний раз слали список служб
	LastAutoruns string `json:"last_autoruns"` // когда последний раз слали автозагрузку
	LastSchTasks string `json:"last_schtasks"` // когда последний раз слали задачи планировщика
	LastDisks    string `json:"last_disks"`    // когда последний раз слали здоровье дисков (SMART)
}

// deviceToken/deviceID — реквизиты, выданные сервером при регистрации.
var (
	deviceToken string
	deviceID    int64
)

// authKey возвращает ключ HMAC и заголовок, по которому сервер этот ключ найдёт.
// Пока устройство не зарегистрировано, работаем по enrollment-токену.
func authKey() (key, hdrName, hdrValue string) {
	if deviceToken != "" && deviceID > 0 {
		return deviceToken, hdrDevice, strconv.FormatInt(deviceID, 10)
	}
	return token, hdrEnroll, "1"
}

// sign — HMAC-SHA256 в hex; им подписывается запрос и проверяется ответ.
func sign(key string, data []byte) string {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write(data)
	return hex.EncodeToString(mac.Sum(nil))
}

// newNonce — одноразовая метка запроса: вместе с timestamp не даёт повторно
// проиграть перехваченный запрос.
func newNonce() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 16)
	}
	return hex.EncodeToString(b)
}

func loadState() agentState {
	var s agentState
	if b, err := os.ReadFile(statePath()); err == nil {
		_ = json.Unmarshal(b, &s)
	}
	return s
}

func saveState(s agentState) {
	if b, err := json.Marshal(s); err == nil {
		// в файле лежит токен устройства (на Windows — под DPAPI)
		_ = os.WriteFile(statePath(), b, 0o600)
	}
}

func osName() string {
	switch runtime.GOOS {
	case "windows":
		return "Windows"
	case "darwin":
		return "macOS"
	default:
		return "Linux"
	}
}

func diskPath() string {
	if runtime.GOOS == "windows" {
		return envOr("SystemDrive", "C:") + "\\"
	}
	return "/"
}

func collectMetrics() map[string]any {
	host, _ := os.Hostname()
	cpuPct := 0.0
	if v, err := cpu.Percent(0, false); err == nil && len(v) > 0 {
		cpuPct = v[0]
	}
	ramPct := 0.0
	if vm, err := mem.VirtualMemory(); err == nil {
		ramPct = vm.UsedPercent
	}
	diskPct := 0.0
	if du, err := disk.Usage(diskPath()); err == nil {
		diskPct = du.UsedPercent
	}
	m := map[string]any{
		"hostname":      host,
		"os":            osName(),
		"cpu":           round1(cpuPct),
		"ram":           round1(ramPct),
		"disk":          round1(diskPct),
		"agent_version": agentVersion,
	}
	for k, v := range hardwareInfo() {
		m[k] = v
	}
	return m
}

// hwCache — характеристики железа кешируются (меняются редко; обновятся при перезапуске агента).
var hwCache map[string]any

// hardwareInfo собирает статичные характеристики: модель CPU, объём RAM/диска, версия ОС.
func hardwareInfo() map[string]any {
	if hwCache != nil {
		return hwCache
	}
	hw := map[string]any{}
	if ci, err := cpu.Info(); err == nil && len(ci) > 0 {
		hw["cpu_model"] = strings.TrimSpace(ci[0].ModelName)
	}
	if vm, err := mem.VirtualMemory(); err == nil && vm.Total > 0 {
		hw["ram_total_gb"] = int((vm.Total + (1<<30)/2) / (1 << 30)) // округление до ГБ
	}
	if du, err := disk.Usage(diskPath()); err == nil && du.Total > 0 {
		hw["disk_total_gb"] = int(du.Total / (1 << 30))
	}
	if hi, err := host.Info(); err == nil {
		osv := strings.TrimSpace(hi.Platform)
		if osv == "" {
			osv = hi.OS
		}
		hw["os_version"] = osv
	}
	hwCache = hw
	return hw
}

func round1(v float64) float64 { return float64(int(v*10+0.5)) / 10 }

// psUTF8 заставляет PowerShell выводить UTF-8. Без этого на русской Windows вывод
// идёт в OEM-кодировке (cp866) и кириллица ломается при чтении как UTF-8 (→ «�»).
const psUTF8 = "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8;"

// runPS выполняет PowerShell-скрипт и возвращает stdout в UTF-8 (BOM убран).
func runPS(script string) ([]byte, bool) {
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", psUTF8+script)
	hideWindow(cmd) // без видимого окна PowerShell
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return nil, false
	}
	return bytes.TrimPrefix(out.Bytes(), []byte{0xEF, 0xBB, 0xBF}), true
}

func post(path string, payload map[string]any) (int, []byte, error) {
	payload["timestamp"] = time.Now().UTC().Unix()
	payload["nonce"] = newNonce()
	b, _ := json.Marshal(payload)
	req, err := http.NewRequest("POST", serverURL+path, bytes.NewReader(b))
	if err != nil {
		return 0, nil, err
	}
	key, hName, hValue := authKey()
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(hName, hValue)
	req.Header.Set(hdrSig, sign(key, b))

	resp, err := httpClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxRespBytes))
	// Ответ сервера тоже подписан. Без этой проверки любой, кто ответит за
	// сервер, смог бы выдать агенту задачу на установку своего пакета.
	if resp.StatusCode == http.StatusOK &&
		!hmac.Equal([]byte(resp.Header.Get(hdrSig)), []byte(sign(key, body))) {
		return resp.StatusCode, nil, errors.New("неверная подпись ответа сервера")
	}
	return resp.StatusCode, body, nil
}

const (
	// pollInterval — шаг основного цикла: сбор метрик и опрос очереди задач.
	// Заодно это и частота, с которой сервер видит агента на связи, — признак
	// «онлайн» опирается на любой запрос, а не только на heartbeat.
	pollInterval = 15 * time.Second
	// maxHeartbeat — максимум без heartbeat при стабильной нагрузке. Управляет
	// только частотой записи метрик: на определение online/offline не влияет.
	maxHeartbeat = 300 * time.Second
)

// bigChange — заметное изменение нагрузки (>=15 п.п. по любому из CPU/RAM/Disk или >=80%).
func bigChange(cur, prev map[string]any) bool {
	if prev == nil {
		return true
	}
	for _, k := range []string{"cpu", "ram", "disk"} {
		c, _ := cur[k].(float64)
		p, _ := prev[k].(float64)
		if c >= 80 {
			return true
		}
		if d := c - p; d >= 15 || d <= -15 {
			return true
		}
	}
	return false
}

// inventoryRetry — через сколько повторить часть инвентаря, которую сервер не
// принял. Сбор идёт через PowerShell и стоит секунд процессорного времени,
// поэтому долбиться каждые 15 секунд нельзя.
const inventoryRetry = 15 * time.Minute

// sendInventory отправляет часть инвентаря и говорит, принял ли её сервер.
//
// Раньше успехом считалось отсутствие ошибки связи: отказ сервера (например,
// «устройство уже зарегистрировано» или временная 5xx при перезапуске) выглядел
// как успешная отправка. Агент писал в журнал «отправлено», помечал инвентарь
// сданным и молчал до суток, хотя на сервере не появлялось ничего.
func sendInventory(path, label string, payload map[string]any, n int) bool {
	code, body, err := post(path, payload)
	switch {
	case err != nil:
		log.Printf("%s — ошибка связи: %v", label, err)
		return false
	case code < 200 || code >= 300:
		log.Printf("%s — сервер отверг (HTTP %d): %s", label, code,
			strings.TrimSpace(string(body)))
		return false
	}
	log.Printf("%s: %d", label, n)
	return true
}

// attemptStamp возвращает отметку времени для состояния агента: при успехе —
// текущее время (следующая отправка через полный интервал), при неудаче —
// сдвинутое так, чтобы повтор пришёлся через inventoryRetry.
//
// Время пишется в UTC, потому что due*-проверки читают его через time.Parse без
// зоны, то есть как UTC. Раньше здесь писалось локальное время, и на любом поясе
// кроме UTC все интервалы инвентаря уезжали на величину смещения: в Москве
// (UTC+3) агент отправлял инвентарь на три часа позже положенного.
func attemptStamp(ok bool, interval time.Duration) string {
	if ok {
		return time.Now().UTC().Format(stateTimeLayout)
	}
	return time.Now().UTC().Add(-interval + inventoryRetry).Format(stateTimeLayout)
}

// stateTimeLayout — формат отметок в agent_state.json (UTC, без зоны).
const stateTimeLayout = "2006-01-02 15:04:05"

// dueSoftware — пора ли слать инвентарь ПО (раз в сутки).
func dueSoftware(last string) bool {
	if last == "" {
		return true
	}
	t, err := time.Parse(stateTimeLayout, last)
	return err != nil || time.Since(t) >= 24*time.Hour
}

// dueServices — пора ли слать список служб (раз в 6 часов).
func dueServices(last string) bool {
	if last == "" {
		return true
	}
	t, err := time.Parse(stateTimeLayout, last)
	return err != nil || time.Since(t) >= 6*time.Hour
}

// dueAutoruns — пора ли слать точки автозапуска (раз в час; чтение реестра дешёвое,
// а новая запись автозагрузки — сигнал закрепления вредоноса).
func dueAutoruns(last string) bool {
	if last == "" {
		return true
	}
	t, err := time.Parse(stateTimeLayout, last)
	return err != nil || time.Since(t) >= time.Hour
}

// dueSchTasks — пора ли слать задачи планировщика (раз в 6 часов; снапшот + диф
// ловит новые и перенацеленные задачи — классический способ закрепления).
func dueSchTasks(last string) bool {
	if last == "" {
		return true
	}
	t, err := time.Parse(stateTimeLayout, last)
	return err != nil || time.Since(t) >= 6*time.Hour
}

// dueDisks — пора ли слать здоровье дисков SMART (раз в 6 часов).
func dueDisks(last string) bool {
	if last == "" {
		return true
	}
	t, err := time.Parse(stateTimeLayout, last)
	return err != nil || time.Since(t) >= 6*time.Hour
}

func main() {
	// Флаг версии используется механизмом самообновления: скачанная сборка
	// запускается с ним как проверка, что файл рабочий, — только после этого
	// агент подменяет себя.
	if len(os.Args) > 1 && (os.Args[1] == "-version" || os.Args[1] == "--version") {
		fmt.Println(agentVersion)
		return
	}

	log.Printf("NetAdmin agent %s → %s", agentVersion, serverURL)
	cleanupOldBinary() // остаток прошлого самообновления
	st := loadState()
	deviceToken, deviceID = unprotectString(st.DeviceToken), st.DeviceID
	if deviceToken == "" && token == "" {
		log.Fatal("не задан NETADMIN_AGENT_TOKEN — enrollment-токен обязателен для первой регистрации")
	}
	var lastSent map[string]any
	var lastHB time.Time

	for {
		metrics := collectMetrics()
		// адаптивный heartbeat: шлём при заметном изменении или не реже maxHeartbeat
		if lastSent == nil || time.Since(lastHB) >= maxHeartbeat || bigChange(metrics, lastSent) {
			status, body, err := post("/api/agent-heartbeat", metrics)
			switch {
			case err != nil:
				log.Println("heartbeat error:", err)
			case status == 401:
				if deviceToken != "" {
					log.Println("токен отозван — перерегистрация по enrollment-токену")
					deviceToken, deviceID = "", 0
					st.DeviceToken, st.DeviceID = "", 0
					saveState(st)
				} else {
					log.Println("heartbeat: 401 (неверный enrollment-токен)")
				}
			case status == 409:
				log.Println("устройство уже зарегистрировано: отзовите токен на сервере перед переустановкой агента")
			case status == 200:
				var resp struct {
					Token    string `json:"token"`
					DeviceID int64  `json:"device_id"`
				}
				_ = json.Unmarshal(body, &resp)
				if resp.Token != "" && resp.Token != deviceToken {
					deviceToken, deviceID = resp.Token, resp.DeviceID
					st.DeviceToken = protectString(resp.Token) // DPAPI на Windows
					st.DeviceID = resp.DeviceID
					saveState(st)
					log.Println("получен персональный токен устройства")
				}
				lastSent = metrics
				lastHB = time.Now()
				log.Println("heartbeat:", metrics["hostname"], metrics["cpu"], metrics["ram"], metrics["disk"])
			}
		}

		if runtime.GOOS == "windows" {
			// инвентарь ПО — раз в сутки
			if dueSoftware(st.LastSoftware) {
				ok := true
				if sw := collectSoftware(); len(sw) > 0 {
					host, _ := os.Hostname()
					ok = sendInventory("/api/agent-software", "отправлено ПО",
						map[string]any{"hostname": host, "software": sw}, len(sw))
				}
				st.LastSoftware = attemptStamp(ok, 24*time.Hour)
				saveState(st)
			}

			// инвентарь конфигурации хоста: службы / автозагрузка / задачи.
			// Изменения уходят в историю устройства.
			if dueServices(st.LastServices) {
				ok := true
				if sv := collectServices(); len(sv) > 0 {
					host, _ := os.Hostname()
					ok = sendInventory("/api/agent-services", "отправлено служб",
						map[string]any{"hostname": host, "services": sv}, len(sv))
				}
				st.LastServices = attemptStamp(ok, 6*time.Hour)
				saveState(st)
			}
			if dueAutoruns(st.LastAutoruns) {
				ok := true
				if ar := collectAutoruns(); len(ar) > 0 {
					host, _ := os.Hostname()
					ok = sendInventory("/api/agent-autoruns", "отправлено точек автозагрузки",
						map[string]any{"hostname": host, "autoruns": ar}, len(ar))
				}
				st.LastAutoruns = attemptStamp(ok, time.Hour)
				saveState(st)
			}
			if dueSchTasks(st.LastSchTasks) {
				ok := true
				if ts := collectScheduledTasks(); len(ts) > 0 {
					host, _ := os.Hostname()
					ok = sendInventory("/api/agent-schtasks", "отправлено задач планировщика",
						map[string]any{"hostname": host, "tasks": ts}, len(ts))
				}
				st.LastSchTasks = attemptStamp(ok, 6*time.Hour)
				saveState(st)
			}
			// здоровье дисков (SMART) — раз в 6 часов
			if dueDisks(st.LastDisks) {
				ok := true
				if dk := collectDisks(); len(dk) > 0 {
					host, _ := os.Hostname()
					ok = sendInventory("/api/agent-disks", "отправлено дисков",
						map[string]any{"hostname": host, "disks": dk}, len(dk))
				}
				st.LastDisks = attemptStamp(ok, 6*time.Hour)
				saveState(st)
			}
		}

		// удалённые задачи (RMM): забираем и выполняем (только после регистрации)
		if deviceToken != "" && deviceID > 0 {
			pollTasks()
		}

		time.Sleep(pollInterval)
	}
}

// pollTasks забирает ожидающие задачи устройства, выполняет их и рапортует результат.
func pollTasks() {
	host, _ := os.Hostname()
	_, body, err := post("/api/agent-tasks/poll", map[string]any{"hostname": host})
	if err != nil {
		return
	}
	var resp struct {
		Tasks []struct {
			ID      int64  `json:"id"`
			Kind    string `json:"kind"`
			Payload string `json:"payload"`
		} `json:"tasks"`
	}
	if json.Unmarshal(body, &resp) != nil {
		return
	}
	for _, t := range resp.Tasks {
		status, output, code := runTask(t.Kind, t.Payload)
		log.Printf("задача #%d (%s): %s", t.ID, t.Kind, status)
		_, _, _ = post("/api/agent-tasks/result", map[string]any{
			"id": t.ID, "status": status, "result": output, "exit_code": code,
		})
		// Самообновление завершается перезапуском, и только после отправки
		// результата: иначе сервер не узнал бы, чем закончилась задача.
		if restartPending {
			restartIntoNewBinary()
			return
		}
	}
}
