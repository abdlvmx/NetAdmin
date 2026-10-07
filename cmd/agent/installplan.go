package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"netadmin/internal/installtxn"
)

type agentInstallPlan struct {
	Config      agentConfig
	Files       []installtxn.File
	ArchivePath string
}

// installServerURL validates and canonicalizes the address before touching the
// working installation. Host aliases intentionally remain different: an IP
// change cannot tell us whether the administrator chose a different server.
func installServerURL(raw string) (string, error) {
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("не указан адрес сервера: agent.exe -install -server=http://192.168.1.10:8765 -token=…")
	}
	u, err := url.Parse(normalizeServerURL(raw))
	if err != nil || u.Hostname() == "" {
		return "", fmt.Errorf("неверный адрес сервера: нужен http://адрес:порт или https://адрес:порт")
	}
	if u.Scheme != "http" && u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("неверный адрес сервера: используйте HTTP(S) без логина, параметров и фрагмента")
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 {
		return "", fmt.Errorf("неверный порт сервера: допустимы значения 1–65535")
	}
	u.Host = net.JoinHostPort(strings.ToLower(u.Hostname()), strconv.Itoa(port))
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawPath = ""
	return u.String(), nil
}

func readInstallJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("чтение %s: %w", path, err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		return fmt.Errorf("повреждён %s: %w; восстановите файл перед установкой", path, err)
	}
	return nil
}

func readInstallIdentity(dir string) (agentConfig, agentState, error) {
	var cfg agentConfig
	var st agentState
	if err := readInstallJSON(configPathIn(dir), &cfg); err != nil {
		return cfg, st, err
	}
	if err := readInstallJSON(filepath.Join(dir, "agent_state.json"), &st); err != nil {
		return cfg, st, err
	}
	return cfg, st, nil
}

// planAgentInstall is side-effect free. Ordinary reinstall preserves personal
// credentials; transfer requires an explicit, fresh code and archives the old
// registration within the same file transaction as the replacement settings.
func planAgentInstall(dir, source, server, tok string, transfer, keepRegistration bool, now time.Time) (agentInstallPlan, error) {
	var plan agentInstallPlan
	if err := checkInstallUpdatePending(dir); err != nil {
		return plan, err
	}
	if transfer && keepRegistration {
		return plan, fmt.Errorf("-transfer и -keep-registration нельзя использовать одновременно")
	}
	existing, state, err := readInstallIdentity(dir)
	if err != nil {
		return plan, err
	}
	if server == "" {
		server = existing.ServerURL
	}
	server, err = installServerURL(server)
	if err != nil {
		return plan, err
	}
	registered := state.DeviceID != 0 || state.DeviceToken != ""
	if !transfer && (state.DeviceID < 0 || (state.DeviceID > 0) != (state.DeviceToken != "")) {
		return plan, fmt.Errorf("неполная регистрация в agent_state.json: восстановите файл или явно перенесите агента с -transfer и новым кодом регистрации")
	}
	if registered && !transfer {
		previous, err := installServerURL(existing.ServerURL)
		if err != nil || previous != server {
			if !keepRegistration {
				return plan, fmt.Errorf("у агента уже есть регистрация на %s, новый адрес: %s.\n"+
					"Если изменился только адрес прежнего сервера, повторите с -keep-registration.\n"+
					"Для другого сервера используйте -transfer и -token=НОВЫЙ_КОД; прежняя регистрация будет сохранена в копии", existing.ServerURL, server)
			}
		}
	}
	if transfer && strings.TrimSpace(tok) == "" {
		return plan, fmt.Errorf("для переноса нужен новый код регистрации целевого сервера: -transfer -server=… -token=НОВЫЙ_КОД")
	}
	if tok == "" && !transfer {
		previous, err := installServerURL(existing.ServerURL)
		if err == nil && previous == server {
			tok = existing.EnrollToken
		}
	}
	if !registered && strings.TrimSpace(tok) == "" {
		return plan, fmt.Errorf("не указан код регистрации: agent.exe -install -server=… -token=КОД\nкод показывает страница «Настройки» целевого сервера")
	}
	plan.Config = agentConfig{ServerURL: server, EnrollToken: tok}
	data, err := json.MarshalIndent(plan.Config, "", "  ")
	if err != nil {
		return plan, err
	}
	plan.Files = append(plan.Files,
		installtxn.File{Path: configPathIn(dir), Data: data, Mode: 0o600},
		installtxn.File{Path: filepath.Join(dir, "agent_state.json"), Snapshot: true},
		installtxn.File{Path: filepath.Join(dir, "agent_status.json"), Remove: true},
	)
	if source != "" {
		plan.Files = append(plan.Files, installtxn.File{Path: filepath.Join(dir, "agent.exe"), Source: source, Mode: 0o755})
	}
	if transfer {
		// Snapshot protects mutations made by the candidate service as well as
		// deletion of the previous registration before its first heartbeat.
		plan.Files[1] = installtxn.File{Path: filepath.Join(dir, "agent_state.json"), Remove: true}
		plan.Files = append(plan.Files, installtxn.File{Path: filepath.Join(dir, "agent_update_result.json"), Remove: true})
		if registered {
			archive := struct {
				ServerURL string     `json:"server_url"`
				State     agentState `json:"agent_state"`
			}{existing.ServerURL, state}
			data, err := json.MarshalIndent(archive, "", "  ")
			if err != nil {
				return plan, err
			}
			plan.ArchivePath = filepath.Join(dir, "agent_registration.before-transfer."+now.UTC().Format("20060102T150405.000000000Z")+".json")
			if _, err := os.Stat(plan.ArchivePath); !errors.Is(err, os.ErrNotExist) {
				return plan, fmt.Errorf("копия прежней регистрации уже существует или недоступна: %s", plan.ArchivePath)
			}
			plan.Files = append(plan.Files, installtxn.File{Path: plan.ArchivePath, Data: data, Mode: 0o600})
		}
	} else if keepRegistration && registered {
		// The administrator explicitly confirmed the same server. A delayed
		// update outcome still belongs to its original task and device, so
		// change only its destination address together with the configuration.
		previous, err := installServerURL(existing.ServerURL)
		if err == nil && previous != server {
			resultPath := filepath.Join(dir, "agent_update_result.json")
			data, err := retargetInstallUpdateResult(resultPath, previous, server, state.DeviceID)
			if err != nil {
				return plan, err
			}
			if data != nil {
				plan.Files = append(plan.Files, installtxn.File{Path: resultPath, Data: data, Mode: 0o600})
			}
		}
	}
	return plan, nil
}

func checkInstallUpdatePending(dir string) error {
	path := filepath.Join(dir, "agent_update.json")
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("обновление агента уже подготовлено или выполняется: дождитесь результата, затем повторите установку; журнал agent.log, состояние %s", path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("проверка выполняющегося обновления: %w", err)
	}
	return nil
}

func retargetInstallUpdateResult(path, oldURL, newURL string, deviceID int64) ([]byte, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var result map[string]json.RawMessage
	var sourceURL string
	var sourceDeviceID int64
	if json.Unmarshal(b, &result) != nil || json.Unmarshal(result["server_url"], &sourceURL) != nil || json.Unmarshal(result["device_id"], &sourceDeviceID) != nil {
		return nil, fmt.Errorf("не удалось прочитать отложенный результат обновления %s: сохраните его для диагностики перед изменением адреса", path)
	}
	canonical, err := installServerURL(sourceURL)
	if err != nil || canonical != oldURL || sourceDeviceID != deviceID || deviceID <= 0 {
		return nil, fmt.Errorf("отложенный результат обновления %s относится к другой регистрации: сохраните его для диагностики перед изменением адреса", path)
	}
	result["server_url"], err = json.Marshal(newURL)
	if err != nil {
		return nil, err
	}
	return json.Marshal(result)
}

// checkInstallServer only probes reachability. Personal credentials belong to
// SYSTEM, so authentication is confirmed by a fresh heartbeat of the service.
func checkInstallServer(server string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, server+"/healthz", nil)
	if err != nil {
		return fmt.Errorf("проверка адреса сервера: %w", err)
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil // office proxy variables must not redirect LAN setup
	client := &http.Client{Timeout: 8 * time.Second, Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("сервер %s недоступен: %w.\nПроверьте адрес, работу сервера и доступ к порту; действующий агент пока не остановлен", server, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusForbidden {
		return fmt.Errorf("сервер запретил доступ с этого ПК (HTTP 403): добавьте его подсеть в разрешённые сети сервера; действующий агент пока не остановлен")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024))
	if err != nil {
		return fmt.Errorf("чтение проверки сервера: %w", err)
	}
	if resp.StatusCode != http.StatusOK || strings.TrimSpace(string(body)) != "ok" {
		return fmt.Errorf("сервер %s не готов к установке (HTTP %d, ожидается ответ NetAdmin /healthz); действующий агент пока не остановлен", server, resp.StatusCode)
	}
	return nil
}
