//go:build windows

package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// downloadClient — отдельный клиент с большим таймаутом для скачивания дистрибутивов.
var downloadClient = &http.Client{
	Timeout:   30 * time.Minute,
	Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
}

// installPackage скачивает дистрибутив с сервера, проверяет SHA-256 и тихо ставит.
func installPackage(payload string) (status, output string, code int) {
	var p struct {
		ID       int64  `json:"id"`
		Name     string `json:"name"`
		Kind     string `json:"kind"`
		Filename string `json:"filename"`
		SHA256   string `json:"sha256"`
		Args     string `json:"args"`
	}
	if json.Unmarshal([]byte(payload), &p) != nil || p.ID == 0 {
		return "failed", "некорректные данные установки", 1
	}

	tmp := filepath.Join(os.TempDir(), "na_"+p.Filename)
	if err := downloadPackage(p.ID, tmp); err != nil {
		return "failed", "скачивание: " + err.Error(), 1
	}
	defer os.Remove(tmp)

	if p.SHA256 != "" {
		sum, err := fileSHA256(tmp)
		if err != nil {
			return "failed", "проверка контрольной суммы: " + err.Error(), 1
		}
		if !strings.EqualFold(sum, p.SHA256) {
			return "failed", "контрольная сумма не совпала (файл повреждён)", 1
		}
	}

	out, code := runInstaller(p.Kind, tmp, p.Args)
	status = "done"
	if code != 0 {
		status = "failed"
	}
	if out == "" {
		out = fmt.Sprintf("установка завершена (код %d)", code)
	}
	return status, out, code
}

func downloadPackage(id int64, dst string) error {
	req, err := http.NewRequest("GET", serverURL+"/api/agent-package?id="+strconv.FormatInt(id, 10), nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-Agent-Token", authToken())
	resp, err := downloadClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("сервер вернул %d", resp.StatusCode)
	}
	f, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(f, resp.Body)
	return err
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// runInstaller запускает дистрибутив в тихом режиме по типу.
func runInstaller(kind, path, args string) (string, int) {
	extra := strings.Fields(args)
	var cmd *exec.Cmd
	switch kind {
	case "msi":
		a := append([]string{"/i", path, "/quiet", "/norestart"}, extra...)
		cmd = exec.Command("msiexec", a...)
	case "script":
		if strings.EqualFold(filepath.Ext(path), ".ps1") {
			a := append([]string{"-ExecutionPolicy", "Bypass", "-NoProfile", "-File", path}, extra...)
			cmd = exec.Command("powershell", a...)
		} else { // .bat/.cmd
			a := append([]string{"/c", path}, extra...)
			cmd = exec.Command("cmd", a...)
		}
	default: // exe
		cmd = exec.Command(path, extra...)
	}
	hideWindow(cmd)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	code := 0
	if err != nil {
		code = 1
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		}
	}
	s := strings.TrimSpace(out.String())
	if len(s) > 6000 {
		s = s[:6000] + "…"
	}
	return s, code
}
