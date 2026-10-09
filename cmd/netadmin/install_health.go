package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
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

	"netadmin/internal/config"
	"netadmin/internal/version"
	"netadmin/internal/winsvc"
)

type serverRuntime struct {
	PublicURL   string `json:"public_url,omitempty"`
	TLSCertFile string `json:"tls_cert_file,omitempty"`
	ListenAddr  string `json:"listen_addr"`
	ProcessID   int    `json:"process_id"`
	DataDir     string `json:"data_dir"`
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

func saveServerRuntime(dir, listenAddr string, transport ...config.TLSSettings) error {
	live := serverRuntime{ListenAddr: listenAddr, ProcessID: os.Getpid(), DataDir: serviceRuntimeDataDir()}
	if len(transport) > 0 && transport[0].Enabled() {
		live.PublicURL, live.TLSCertFile = transport[0].PublicURL, transport[0].CertFile
	}
	b, err := json.Marshal(live)
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
	cfg, transport, err := installedServerTransport(dir)
	if err != nil {
		return "", err
	}
	if transport.Enabled() {
		return transport.PublicURL + "/healthz", nil
	}
	return serverHealthURL(cfg.ListenAddr)
}

func installedServerTransport(dir string) (config.Config, config.TLSSettings, error) {
	var cfg config.Config
	b, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return cfg, config.TLSSettings{}, err
	}
	if err == nil {
		if err := json.Unmarshal(b, &cfg); err != nil {
			return cfg, config.TLSSettings{}, fmt.Errorf("настройки установленного сервера: %w", err)
		}
	}
	transport, err := cfg.TLSSettingsAt(dir, false)
	return cfg, transport, err
}

func checkServerHealth(url, expectedVersion string, expectedPID int) error {
	return checkServerHealthTLS(url, expectedVersion, expectedPID, "", "")
}

func checkServerHealthTLS(probeURL, expectedVersion string, expectedPID int, certFile, listenAddr string) error {
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true}
	if strings.HasPrefix(probeURL, "https://") && certFile != "" {
		b, err := os.ReadFile(certFile)
		if err != nil {
			return err
		}
		block, _ := pem.Decode(b)
		if block == nil || block.Type != "CERTIFICATE" {
			return errors.New("неверный сертификат проверки службы")
		}
		leaf, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return err
		}
		roots := x509.NewCertPool()
		roots.AddCert(leaf)
		transport.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
		// Verify the public certificate name while dialing the actual local
		// listener. Installation must not depend on external DNS/NAT routing.
		if listenAddr != "" {
			local, err := serverHealthURL(listenAddr)
			if err != nil {
				return err
			}
			u, err := url.Parse(local)
			if err != nil {
				return err
			}
			dialer := &net.Dialer{Timeout: 2 * time.Second}
			transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
				return dialer.DialContext(ctx, network, u.Host)
			}
		}
	}
	client := &http.Client{
		Timeout:       2 * time.Second,
		Transport:     transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	defer transport.CloseIdleConnections()
	resp, err := client.Get(probeURL)
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
	cfg, transport, err := installedServerTransport(dataDir)
	if err != nil {
		return "", err
	}
	url, err := installedServerHealthURL(dataDir)
	if err != nil {
		return "", err
	}
	deadline := time.Now().Add(15 * time.Second)
	certFile, listenAddr := transport.CertFile, cfg.ListenAddr
	for {
		pid, pidErr := winsvc.ProcessID(serviceName)
		if pidErr == nil {
			// The service also inherits machine environment variables, while
			// the installer may have different shell overrides. Trust only the
			// address reported by this SCM process in the protected directory.
			var live serverRuntime
			if b, readErr := os.ReadFile(filepath.Join(dir, "server_runtime.json")); readErr == nil && json.Unmarshal(b, &live) == nil && live.ProcessID == pid {
				listenAddr, certFile = live.ListenAddr, live.TLSCertFile
				if actualURL, addrErr := serverHealthURL(live.ListenAddr); addrErr == nil {
					url = actualURL
					if live.PublicURL != "" && live.TLSCertFile != "" {
						url = live.PublicURL + "/healthz"
					}
				}
			}
			err = checkServerHealthTLS(url, version.Value, pid, certFile, listenAddr)
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
