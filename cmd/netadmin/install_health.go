package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"netadmin/internal/version"
	"netadmin/internal/winsvc"
)

type serverRuntime struct {
	ListenAddr string `json:"listen_addr"`
	ProcessID  int    `json:"process_id"`
	DataDir    string `json:"data_dir"`
}

const serverInstallGuardName = "server_install_guard.json"

func checkServerInstallDataDir(dir, actual string) error {
	b, err := os.ReadFile(filepath.Join(dir, serverInstallGuardName))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var expected struct {
		DataDir string `json:"data_dir"`
	}
	if json.Unmarshal(b, &expected) != nil || expected.DataDir == "" {
		return fmt.Errorf("повреждена отметка установки %s", serverInstallGuardName)
	}
	if !samePath(expected.DataDir, actual) {
		return fmt.Errorf("окружение службы указывает на %s, а установка защищает %s; запуск отменён до изменения базы. Примените машинные переменные окружения и повторите установку", actual, expected.DataDir)
	}
	return nil
}

func saveServerRuntime(dir, listenAddr string) error {
	b, err := json.Marshal(serverRuntime{ListenAddr: listenAddr, ProcessID: os.Getpid(), DataDir: serviceRuntimeDataDir()})
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".na-runtime-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), filepath.Join(dir, "server_runtime.json"))
}

func serviceRuntimeDataDir() string {
	// Called inside the SCM process, where the actual service environment is
	// authoritative. The installer uses the registry, never its shell override.
	if dir := os.Getenv("NETADMIN_DATA_DIR"); dir != "" {
		return dir
	}
	return installDir()
}

func serverDataDir(installDir, serviceSetting string) (string, error) {
	if serviceSetting == "" {
		return installDir, nil
	}
	if !filepath.IsAbs(serviceSetting) {
		return "", fmt.Errorf("NETADMIN_DATA_DIR службы должен содержать абсолютный путь; задайте его в машинных настройках перед обновлением")
	}
	return filepath.Clean(serviceSetting), nil
}

func serverHealthURL(listenAddr string) (string, error) {
	if listenAddr == "" {
		listenAddr = "0.0.0.0:8765"
	}
	host, port, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return "", fmt.Errorf("адрес службы %q: %w", listenAddr, err)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", fmt.Errorf("неверный порт службы: %q", port)
	}
	switch host {
	case "", "0.0.0.0":
		host = "127.0.0.1"
	case "::":
		host = "::1"
	}
	return "http://" + net.JoinHostPort(host, port) + "/healthz", nil
}

func installedServerHealthURL(dir string) (string, error) {
	var cfg struct {
		ListenAddr string `json:"listen_addr"`
	}
	b, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	if err == nil {
		if err := json.Unmarshal(b, &cfg); err != nil {
			return "", fmt.Errorf("настройки установленного сервера: %w", err)
		}
	}
	return serverHealthURL(cfg.ListenAddr)
}

func checkServerHealth(url, expectedVersion string, expectedPID int) error {
	client := &http.Client{
		Timeout:       2 * time.Second,
		Transport:     &http.Transport{Proxy: nil, DisableKeepAlives: true},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 65))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK || strings.TrimSpace(string(body)) != "ok" {
		return fmt.Errorf("интерфейс не готов (HTTP %d)", resp.StatusCode)
	}
	if resp.Header.Get("X-NetAdmin-Version") != expectedVersion || expectedPID <= 0 || resp.Header.Get("X-NetAdmin-PID") != strconv.Itoa(expectedPID) {
		return fmt.Errorf("на указанном адресе отвечает другая версия или другой процесс NetAdmin")
	}
	return nil
}

func waitInstalledServerHealth(dir, dataDir string) (string, error) {
	url, err := installedServerHealthURL(dataDir)
	if err != nil {
		return "", err
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		pid, pidErr := winsvc.ProcessID(serviceName)
		if pidErr == nil {
			// The service also inherits machine environment variables, while
			// the installer may have different shell overrides. Trust only the
			// address reported by this SCM process in the protected directory.
			var live serverRuntime
			if b, readErr := os.ReadFile(filepath.Join(dir, "server_runtime.json")); readErr == nil && json.Unmarshal(b, &live) == nil && live.ProcessID == pid {
				if actualURL, addrErr := serverHealthURL(live.ListenAddr); addrErr == nil {
					url = actualURL
				}
			}
			err = checkServerHealth(url, version.Value, pid)
		} else {
			err = pidErr
		}
		if err == nil {
			return url, nil
		}
		if !time.Now().Before(deadline) {
			return "", fmt.Errorf("служба не подтвердила готовность %s: %w", url, err)
		}
		time.Sleep(250 * time.Millisecond)
	}
}
