// Команда agent — NetAdmin агент: heartbeat (gopsutil) + инвентарь ПО/служб/
// автозагрузки/задач планировщика. Инвентарь конфигурации работает только на
// Windows. На прочих ОС агент шлёт только heartbeat.
package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/mem"
)

var (
	serverURL = envOr("NETADMIN_SERVER_URL", "http://0.0.0.0:8765")
	token     = envOr("NETADMIN_AGENT_TOKEN", "YOUR_TOKEN_HERE")
)

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
	DeviceToken  string `json:"device_token"`  // персональный токен, выданный сервером
	LastSoftware string `json:"last_software"` // когда последний раз слали инвентарь ПО
	LastServices string `json:"last_services"` // когда последний раз слали список служб
	LastAutoruns string `json:"last_autoruns"` // когда последний раз слали автозагрузку
	LastSchTasks string `json:"last_schtasks"` // когда последний раз слали задачи планировщика
	LastDisks    string `json:"last_disks"`    // когда последний раз слали здоровье дисков (SMART)
}

// deviceToken — текущий персональный токен (если выдан); иначе используется enrollment.
var deviceToken string

func authToken() string {
	if deviceToken != "" {
		return deviceToken
	}
	return token
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
		_ = os.WriteFile(statePath(), b, 0o644)
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
		"hostname": host,
		"os":       osName(),
		"cpu":      round1(cpuPct),
		"ram":      round1(ramPct),
		"disk":     round1(diskPct),
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
	payload["timestamp"] = time.Now().UTC().Unix() // защита от replay
	b, _ := json.Marshal(payload)
	req, err := http.NewRequest("POST", serverURL+path, bytes.NewReader(b))
	if err != nil {
		return 0, nil, err
	}
	tok := authToken()
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-Token", tok)
	// HMAC-SHA256 тела на токене агента (целостность + анти-replay)
	mac := hmac.New(sha256.New, []byte(tok))
	mac.Write(b)
	req.Header.Set("X-Agent-Signature", hex.EncodeToString(mac.Sum(nil)))
	resp, err := httpClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, body, nil
}

const (
	pollInterval = 15 * time.Second  // как часто опрашиваем метрики/события
	maxHeartbeat = 300 * time.Second // максимум без heartbeat при стабильной нагрузке
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

// dueSoftware — пора ли слать инвентарь ПО (раз в сутки).
func dueSoftware(last string) bool {
	if last == "" {
		return true
	}
	t, err := time.Parse("2006-01-02 15:04:05", last)
	return err != nil || time.Since(t) >= 24*time.Hour
}

// dueServices — пора ли слать список служб (раз в 6 часов).
func dueServices(last string) bool {
	if last == "" {
		return true
	}
	t, err := time.Parse("2006-01-02 15:04:05", last)
	return err != nil || time.Since(t) >= 6*time.Hour
}

// dueAutoruns — пора ли слать точки автозапуска (раз в час; чтение реестра дешёвое,
// а новая запись автозагрузки — сигнал закрепления вредоноса).
func dueAutoruns(last string) bool {
	if last == "" {
		return true
	}
	t, err := time.Parse("2006-01-02 15:04:05", last)
	return err != nil || time.Since(t) >= time.Hour
}

// dueSchTasks — пора ли слать задачи планировщика (раз в 6 часов; снапшот + диф
// ловит новые и перенацеленные задачи — классический способ закрепления).
func dueSchTasks(last string) bool {
	if last == "" {
		return true
	}
	t, err := time.Parse("2006-01-02 15:04:05", last)
	return err != nil || time.Since(t) >= 6*time.Hour
}

// dueDisks — пора ли слать здоровье дисков SMART (раз в 6 часов).
func dueDisks(last string) bool {
	if last == "" {
		return true
	}
	t, err := time.Parse("2006-01-02 15:04:05", last)
	return err != nil || time.Since(t) >= 6*time.Hour
}

func main() {
	log.Printf("NetAdmin agent → %s", serverURL)
	st := loadState()
	deviceToken = unprotectString(st.DeviceToken)
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
					deviceToken, st.DeviceToken = "", ""
					saveState(st)
				} else {
					log.Println("heartbeat: 401 (неверный enrollment-токен)")
				}
			case status == 200:
				var resp struct {
					Token string `json:"token"`
				}
				_ = json.Unmarshal(body, &resp)
				if resp.Token != "" && resp.Token != deviceToken {
					deviceToken = resp.Token
					st.DeviceToken = protectString(resp.Token) // DPAPI на Windows
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
				if sw := collectSoftware(); len(sw) > 0 {
					host, _ := os.Hostname()
					if _, _, e := post("/api/agent-software", map[string]any{"hostname": host, "software": sw}); e == nil {
						log.Printf("отправлено ПО: %d", len(sw))
					}
				}
				st.LastSoftware = time.Now().Format("2006-01-02 15:04:05")
				saveState(st)
			}

			// инвентарь конфигурации хоста: службы / автозагрузка / задачи.
			// Изменения уходят в историю устройства.
			if dueServices(st.LastServices) {
				if sv := collectServices(); len(sv) > 0 {
					host, _ := os.Hostname()
					if _, _, e := post("/api/agent-services", map[string]any{"hostname": host, "services": sv}); e == nil {
						log.Printf("отправлено служб: %d", len(sv))
					}
				}
				st.LastServices = time.Now().Format("2006-01-02 15:04:05")
				saveState(st)
			}
			if dueAutoruns(st.LastAutoruns) {
				if ar := collectAutoruns(); len(ar) > 0 {
					host, _ := os.Hostname()
					if _, _, e := post("/api/agent-autoruns", map[string]any{"hostname": host, "autoruns": ar}); e == nil {
						log.Printf("отправлено точек автозагрузки: %d", len(ar))
					}
				}
				st.LastAutoruns = time.Now().Format("2006-01-02 15:04:05")
				saveState(st)
			}
			if dueSchTasks(st.LastSchTasks) {
				if ts := collectScheduledTasks(); len(ts) > 0 {
					host, _ := os.Hostname()
					if _, _, e := post("/api/agent-schtasks", map[string]any{"hostname": host, "tasks": ts}); e == nil {
						log.Printf("отправлено задач планировщика: %d", len(ts))
					}
				}
				st.LastSchTasks = time.Now().Format("2006-01-02 15:04:05")
				saveState(st)
			}
			// здоровье дисков (SMART) — раз в 6 часов
			if dueDisks(st.LastDisks) {
				if dk := collectDisks(); len(dk) > 0 {
					host, _ := os.Hostname()
					if _, _, e := post("/api/agent-disks", map[string]any{"hostname": host, "disks": dk}); e == nil {
						log.Printf("отправлено дисков: %d", len(dk))
					}
				}
				st.LastDisks = time.Now().Format("2006-01-02 15:04:05")
				saveState(st)
			}
		}

		// удалённые задачи (RMM): забираем и выполняем (только после enrollment)
		if deviceToken != "" {
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
	}
}
